// Nym Web Proxy - (c) 2026 Ch1ffr3punk
//
// RFC- and W3C-compliant HTTP proxy for the Nym mixnet.
//
// Standards implemented:
//   - RFC 7230 (HTTP/1.1 Message Syntax and Routing):
//       Via header, hop-by-hop header removal, Transfer-Encoding decoding
//   - RFC 7231 (HTTP/1.1 Semantics and Content):
//       Warning header on content transformation
//   - RFC 7234 (HTTP/1.1 Caching):
//       Conditional request preservation, cache validators only stripped on modification
//   - RFC 7239 (Forwarded HTTP Extension):
//       Privacy-preserving client identification
//   - W3C HTML5:
//       Charset meta, viewport meta, alt attributes on images
//   - W3C CORS:
//       Cross-origin resource sharing headers
//   - Privacy & Security:
//       Referrer-Policy, Permissions-Policy, X-Content-Type-Options

use bytes::Bytes;
use clap::Parser;
use flate2::read::{DeflateDecoder, GzDecoder};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nym_network_defaults::setup_env;
use nym_sdk::client_pool::ClientPool;
use nym_sdk::mixnet::{
    IncludedSurbs, MixnetClientBuilder, MixnetMessageSender, NymNetworkDetails,
};
use nym_sdk::tcp_proxy::utils::{DecayWrapper, Payload, ProxiedMessage};
use nym_sphinx_addressing::Recipient;
use regex::Regex;
use std::collections::HashSet;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{debug, error, info};
use uuid::Uuid;

// CLI arguments

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Nym Web Proxy - (c) Ch1ffr3punk")]
struct Args {
    /// Port to listen on for incoming HTTP proxy requests
    #[arg(short, long, default_value_t = 8081)]
    listen_port: u16,

    /// Rewrite HTML content to fix relative URLs and improve accessibility
    #[arg(long, default_value_t = false)]
    rewrite_html: bool,

    /// Timeout in seconds for mixnet responses
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,

    /// Number of pre-warmed mixnet clients in the pool
    #[arg(long, default_value_t = 10)]
    pool_size: usize,
}

// In-memory message reordering buffer
// The mixnet delivers messages out of order. This buffer collects incoming
// messages and emits them in the correct sequence based on their message_id.

struct MemoryBuffer {
    buffer: Vec<DecayWrapper<ProxiedMessage>>,
    next_msg_id: u16,
}

impl MemoryBuffer {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            next_msg_id: 0,
        }
    }

    fn push(&mut self, msg: ProxiedMessage) {
        self.buffer.push(DecayWrapper::new(msg));
    }

    /// Drain all messages that are ready to be delivered (either their decay
    /// timer expired, or their message_id is <= the next expected id).
    /// Returns the concatenated payload bytes of all ready Data messages.
    fn drain_ordered(&mut self) -> Vec<u8> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut ready: Vec<&ProxiedMessage> = self
            .buffer
            .iter()
            .filter(|w| w.decayed() || w.message_id() <= self.next_msg_id)
            .map(|w| w.inner())
            .collect();

        ready.sort_by(|a, b| a.message_id().cmp(&b.message_id()));

        if ready.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut sent_ids = HashSet::new();

        for msg in ready {
            match msg.message() {
                Payload::Data(data) => {
                    result.extend_from_slice(data);
                    sent_ids.insert(msg.message_id());
                }
                Payload::Close => {
                    break;
                }
            }
        }

        if let Some(max_id) = sent_ids.iter().max() {
            self.next_msg_id = max_id.wrapping_add(1);
        }

        self.buffer
            .retain(|w| !sent_ids.contains(&w.inner().message_id()));
        result
    }
}

// Nym address helpers

/// Try to decode a 192-character lowercase hex string into a Nym address.
/// Returns a base58-formatted address string like "identity.encryption@gateway".
fn try_decode_nym_address(host: &str) -> Option<String> {
    if host.len() != 192 {
        info!("Host length {} != 192", host.len());
        return None;
    }

    let is_hex = host
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !is_hex {
        info!("Host contains non-hex or uppercase characters");
        return None;
    }

    let decoded_bytes = match hex::decode(host) {
        Ok(bytes) => bytes,
        Err(e) => {
            info!("Hex decode failed: {}", e);
            return None;
        }
    };

    if decoded_bytes.len() != 96 {
        info!("Decoded length {} != 96", decoded_bytes.len());
        return None;
    }

    let identity_key = bs58::encode(&decoded_bytes[0..32]).into_string();
    let encryption_key = bs58::encode(&decoded_bytes[32..64]).into_string();
    let gateway_key = bs58::encode(&decoded_bytes[64..96]).into_string();

    let nym_address = format!("{}.{}@{}", identity_key, encryption_key, gateway_key);
    info!("✓ Decoded Nym address: {}", nym_address);
    Some(nym_address)
}

fn parse_recipient(nym_address_str: &str) -> Option<Recipient> {
    Recipient::try_from_base58_string(nym_address_str).ok()
}

// W3C-compliant HTML rewriting

fn rewrite_html_content(html: &str, _original_host: &str, base_url: &str) -> String {
    let mut modified = html.to_string();

    // W3C: Inject <base> tag so relative URLs resolve against the Nym host.
    let base_tag = format!("<base href=\"{}\">", base_url);
    if let Some(head_pos) = modified.find("<head>") {
        if !modified.contains("<base") {
            modified.insert_str(head_pos + 6, &format!("\n{}\n", base_tag));
        } else {
            let re = Regex::new(r"<base[^>]*>").unwrap();
            modified = re.replace(&modified, base_tag.as_str()).to_string();
        }
    }

    // Convert legacy Base58 Nym addresses in href/src/action attributes to Hex.
    let legacy_pattern = Regex::new(
        r#"(href|src|action)=["'](https?://)([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})\.([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})@([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})([^"']*?)["']"#
    ).unwrap();

    modified = legacy_pattern
        .replace_all(&modified, |caps: &regex::Captures| {
            let attr = &caps[1];
            let scheme = &caps[2];
            let identity = &caps[3];
            let encryption = &caps[4];
            let gateway = &caps[5];
            let path = &caps[6];

            let id_bytes = bs58::decode(identity).into_vec().unwrap_or_default();
            let enc_bytes = bs58::decode(encryption).into_vec().unwrap_or_default();
            let gw_bytes = bs58::decode(gateway).into_vec().unwrap_or_default();

            if id_bytes.len() == 32 && enc_bytes.len() == 32 && gw_bytes.len() == 32 {
                let mut all_bytes = Vec::with_capacity(96);
                all_bytes.extend_from_slice(&id_bytes);
                all_bytes.extend_from_slice(&enc_bytes);
                all_bytes.extend_from_slice(&gw_bytes);
                format!("{}=\"{}{}{}\"", attr, scheme, hex::encode(&all_bytes), path)
            } else {
                caps[0].to_string()
            }
        })
        .to_string();

    // W3C Accessibility: Add loading="lazy" to images and ensure alt="" exists.
    let img_pattern = Regex::new(r"<img([^>]*)>").unwrap();
    modified = img_pattern
        .replace_all(&modified, |caps: &regex::Captures| {
            let attrs = &caps[1];
            let mut new_attrs = attrs.to_string();

            if !attrs.contains("loading=") {
                new_attrs.push_str(" loading=\"lazy\"");
            }
            if !attrs.contains("alt=") {
                new_attrs.push_str(" alt=\"\"");
            }

            format!("<img{}>", new_attrs)
        })
        .to_string();

    // W3C: Disable form autocomplete for privacy.
    let form_pattern = Regex::new(r"<form([^>]*)>").unwrap();
    modified = form_pattern
        .replace_all(&modified, |caps: &regex::Captures| {
            let attrs = &caps[1];
            if !attrs.contains("autocomplete=") {
                format!("<form{} autocomplete=\"off\">", attrs)
            } else {
                caps[0].to_string()
            }
        })
        .to_string();

    // W3C: Ensure charset meta tag exists.
    if !modified.contains("charset=") {
        if let Some(head_pos) = modified.find("<head>") {
            modified.insert_str(head_pos + 6, "\n<meta charset=\"utf-8\">\n");
        }
    }

    // W3C: Add viewport meta for mobile responsiveness.
    if !modified.contains("viewport") {
        if let Some(head_pos) = modified.find("<head>") {
            modified.insert_str(
                head_pos + 6,
                "\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
            );
        }
    }

    modified
}

// Decompression helpers

/// Decode a chunked transfer-encoded body back into the raw payload.
/// If the origin uses "Transfer-Encoding: chunked" and we strip that header
/// without decoding, the browser receives hex size prefixes as garbage.
fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < raw.len() {
        let line_end = match raw[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => i + p,
            None => break,
        };

        let size_field = String::from_utf8_lossy(&raw[i..line_end]);
        let size_hex = size_field.split(';').next().unwrap_or("0").trim();
        let size = usize::from_str_radix(size_hex, 16).unwrap_or(0);

        if size == 0 {
            break; // terminal chunk
        }

        let data_start = line_end + 2;
        let data_end = (data_start + size).min(raw.len());
        out.extend_from_slice(&raw[data_start..data_end]);

        i = data_end + 2; // skip the CRLF trailing the chunk data
    }

    out
}

/// Decompress a response body based on its Content-Encoding value.
/// This MUST run before we hand the body to the browser, because we always
/// strip the Content-Encoding header from the proxied response.
fn decompress_body(body: &[u8], encoding: &str) -> Result<Vec<u8>, std::io::Error> {
    match encoding.to_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(body);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        "deflate" => {
            let mut decoder = DeflateDecoder::new(body);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok(out)
        }
        _ => Ok(body.to_vec()),
    }
}

// Core mixnet forwarding logic

async fn forward_to_mixnet(
    req: Request<Incoming>,
    target: Recipient,
    nym_address_str: &str,
    original_host: &str,
    args: &Args,
    pool: ClientPool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    info!("  → Acquiring mixnet client for {}", nym_address_str);

    let mut client = match pool.get_mixnet_client().await {
        Some(c) => {
            info!("  → Got client {} from pool", c.nym_address());
            c
        }
        None => {
            info!("  → Pool empty, creating ephemeral client");
            let net = NymNetworkDetails::new_from_env();
            match MixnetClientBuilder::new_ephemeral()
                .network_details(net)
                .build()
            {
                Ok(b) => match b.connect_to_mixnet().await {
                    Ok(c) => {
                        info!("  → Ephemeral client: {}", c.nym_address());
                        c
                    }
                    Err(e) => {
                        error!("Mixnet connect error: {}", e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from(format!(
                                "Mixnet connect error: {}",
                                e
                            ))))
                            .unwrap());
                    }
                },
                Err(e) => {
                    error!("Mixnet build error: {}", e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!(
                            "Mixnet build error: {}",
                            e
                        ))))
                        .unwrap());
                }
            }
        }
    };

    let session_id = Uuid::new_v4();
    let sender = client.split_sender();
    let method = req.method().clone();
    let browser_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut actual_request = format!("{} {} HTTP/1.1\r\n", method, browser_path);
    actual_request.push_str(&format!("Host: {}\r\n", nym_address_str));

    // RFC 7230: Tell origin we only understand gzip/deflate (no brotli).
    actual_request.push_str("Accept-Encoding: gzip, deflate\r\n");

    // RFC 7239: Privacy-preserving client identification.
    actual_request.push_str("Forwarded: for=anonymous;by=nym-proxy\r\n");

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Body error: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!("Body error: {}", e))))
                .unwrap());
        }
    };

    // RFC 7230: Strip hop-by-hop headers. Preserve conditional headers
    // (If-None-Match, If-Modified-Since) so the origin can return 304 responses.
    let strip_req_headers = vec![
        "host",
        "content-length",
        "accept-encoding",
        "connection",
    ];

    for (name, value) in parts.headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if strip_req_headers.contains(&name_lower.as_str()) {
            continue;
        }
        if let Ok(value_str) = value.to_str() {
            actual_request.push_str(&format!("{}: {}\r\n", name, value_str));
        }
    }

    if !body_bytes.is_empty() {
        actual_request.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    actual_request.push_str("\r\n");

    let mut request_bytes = actual_request.into_bytes();
    request_bytes.extend_from_slice(&body_bytes);

    info!("  ✓ Reconstructed request ({} bytes)", request_bytes.len());

    // Split the request into 1024-byte chunks and send each as a ProxiedMessage.
    let mut message_id = 0u16;
    for chunk in request_bytes.chunks(1024) {
        message_id = message_id.wrapping_add(1);
        let msg = ProxiedMessage::new(Payload::Data(chunk.to_vec()), session_id, message_id);
        if let Ok(coded) = bincode::serialize(&msg) {
            let _ = sender
                .send_message(target, &coded, IncludedSurbs::Amount(100))
                .await;
            debug!("  → Sent msg {} ({} bytes)", message_id, chunk.len());
        }
    }

    // Send a Close message to signal the end of the request.
    message_id = message_id.wrapping_add(1);
    let close_msg = ProxiedMessage::new(Payload::Close, session_id, message_id);
    if let Ok(coded) = bincode::serialize(&close_msg) {
        let _ = sender
            .send_message(target, &coded, IncludedSurbs::Amount(100))
            .await;
    }

    info!("  ✓ Request sent, waiting for mixnet response...");

    // Spawn a task to receive and reorder messages from the mixnet.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    tokio::spawn(async move {
        let mut buffer = MemoryBuffer::new();
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                Some(message) = client.next() => {
                    if let Ok(msg) = bincode::deserialize::<ProxiedMessage>(&message.message) {
                        if matches!(msg.message(), Payload::Close) {
                            debug!("  ← Received close message");
                            let ordered = buffer.drain_ordered();
                            if !ordered.is_empty() {
                                let _ = tx.send(ordered).await;
                            }
                            break;
                        }
                        buffer.push(msg);
                        let ordered = buffer.drain_ordered();
                        if !ordered.is_empty() {
                            let _ = tx.send(ordered).await;
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    let ordered = buffer.drain_ordered();
                    if !ordered.is_empty() {
                        let _ = tx.send(ordered).await;
                    }
                }
            }
        }
    });

    // Collect the response until we have a complete HTTP response (headers + body).
    let mut response_buf = Vec::new();
    let timeout_duration = std::time::Duration::from_secs(args.timeout_secs);

    let _ = tokio::time::timeout(timeout_duration, async {
        let mut headers_complete = false;
        let mut expected_body_len = 0usize;
        let mut is_chunked = false;

        while let Some(chunk) = rx.recv().await {
            response_buf.extend_from_slice(&chunk);

            if !headers_complete {
                if let Some(header_end) = response_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    headers_complete = true;
                    let headers_part = String::from_utf8_lossy(&response_buf[..header_end]);
                    debug!("  ← Headers:\n{}", headers_part);

                    for line in headers_part.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("content-length:") {
                            if let Some(len_str) = line.split(':').nth(1) {
                                if let Ok(len) = len_str.trim().parse::<usize>() {
                                    expected_body_len = len;
                                    info!("  ← Parsed Content-Length: {}", expected_body_len);
                                }
                            }
                        }
                        if lower.contains("transfer-encoding: chunked") {
                            is_chunked = true;
                            info!("  ← Response is chunked");
                        }
                    }
                }
            }

            if headers_complete {
                let header_end = response_buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap();
                let body_start = header_end + 4;

                if is_chunked {
                    if response_buf.ends_with(b"0\r\n\r\n")
                        || response_buf.ends_with(b"0\r\n\r\n\r\n")
                    {
                        break;
                    }
                } else if expected_body_len > 0 {
                    if response_buf.len() >= body_start + expected_body_len {
                        info!(
                            "  ← Content-Length satisfied (have {}, expected {}). Total: {}",
                            response_buf.len() - body_start,
                            expected_body_len,
                            response_buf.len()
                        );
                        break;
                    }
                } else if expected_body_len == 0 && response_buf.len() == body_start {
                    // Handle responses like 304 Not Modified or 204 No Content.
                    break;
                }
            }
        }
    })
    .await;

    cancel_token.cancel();

    if response_buf.is_empty() {
        error!("Empty mixnet response");
        return Ok(Response::builder()
            .status(StatusCode::GATEWAY_TIMEOUT)
            .body(Full::new(Bytes::from("Empty mixnet response")))
            .unwrap());
    }

    let response_bytes = Bytes::from(response_buf);

    // Parse the raw HTTP response and build a clean hyper::Response.
    if let Some(header_end) = response_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        let header_bytes = &response_bytes[..header_end];
        let mut body_bytes = response_bytes[header_end + 4..].to_vec();

        if let Ok(header_str) = std::str::from_utf8(header_bytes) {
            let mut lines = header_str.lines();
            let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
            let status_code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(502);

            info!("  ← Response status: {}", status_code);

            // PASS 1: Collect headers. Capture the ones that describe the body
            // encoding so we can transform the body BEFORE dropping those headers.
            let mut content_type = String::new();
            let mut content_encoding = String::new();
            let mut is_chunked_response = false;
            let mut kept_headers: Vec<(String, String)> = Vec::new();

            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_string();
                    let value = value.trim().to_string();
                    let name_lower = name.to_lowercase();

                    if name_lower == "content-type" {
                        content_type = value.clone();
                        kept_headers.push((name, value));
                    } else if name_lower == "content-encoding" {
                        // Remember it, but never forward it: we will decode the body.
                        content_encoding = value.clone();
                    } else if name_lower == "transfer-encoding" {
                        if value.to_lowercase().contains("chunked") {
                            is_chunked_response = true;
                        }
                        // Never forward Transfer-Encoding; we decode it ourselves.
                    } else if name_lower == "connection" || name_lower == "content-length" {
                        // Hop-by-hop; we will recompute Content-Length.
                    } else {
                        kept_headers.push((name, value));
                    }
                }
            }

            // PASS 2: Remove chunked framing if present (must happen before decoding).
            if is_chunked_response {
                let decoded = decode_chunked_body(&body_bytes);
                info!(
                    "  ← De-chunked body ({} -> {} bytes)",
                    body_bytes.len(),
                    decoded.len()
                );
                body_bytes = decoded;
            }

            // PASS 3: Decompress. This is the fix for the binary-garbage /
            // "Content-Encoding" errors: the browser would otherwise receive raw
            // gzip bytes with no header telling it how to decode them.
            let mut was_decompressed = false;
            if !content_encoding.is_empty() {
                match decompress_body(&body_bytes, &content_encoding) {
                    Ok(decoded) => {
                        info!(
                            "  ← Decompressed {} ({} -> {} bytes)",
                            content_encoding,
                            body_bytes.len(),
                            decoded.len()
                        );
                        body_bytes = decoded;
                        was_decompressed = true;
                    }
                    Err(e) => {
                        error!(
                            "  ✗ Decompression of '{}' failed: {}",
                            content_encoding, e
                        );
                    }
                }
            }

            // PASS 4: Optional HTML rewriting (only when --rewrite-html is set).
            let mut html_was_modified = false;
            if args.rewrite_html && content_type.contains("text/html") {
                if let Ok(html_str) = std::str::from_utf8(&body_bytes) {
                    let rewritten = rewrite_html_content(
                        html_str,
                        original_host,
                        &format!("http://{}/", original_host),
                    );
                    body_bytes = rewritten.into_bytes();
                    html_was_modified = true;
                }
            }

            // PASS 5: RFC 7234 - If we modified the body (HTML rewrite or decompression),
            // the origin's ETag/Last-Modified no longer match. Strip them.
            // Otherwise, preserve them so the browser can use conditional requests.
            if html_was_modified || was_decompressed {
                let filtered: Vec<(String, String)> = kept_headers
                    .into_iter()
                    .filter(|(n, _)| {
                        let nl = n.to_lowercase();
                        nl != "etag" && nl != "last-modified"
                    })
                    .collect();
                kept_headers = filtered;
            }

            // PASS 6: Build the final response.
            let mut builder = Response::builder().status(status_code);

            for (name, value) in kept_headers {
                builder = builder.header(name, value);
            }

            // RFC 7230 Section 5.7.1: Via header identifies this proxy.
            builder = builder.header("Via", "1.1 nym-web-proxy");

            // RFC 7234 Section 5.5: Warning header when transformation was applied.
            if html_was_modified || was_decompressed {
                builder = builder.header("Warning", "299 - \"Transformation Applied\"");
            }

            // W3C CORS: Cross-origin resource sharing.
            builder = builder.header("Access-Control-Allow-Origin", "*");
            builder = builder.header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS, PATCH",
            );
            builder = builder.header("Access-Control-Allow-Headers", "*");

            // Privacy: Referrer-Policy (prevent referrer leaks).
            builder = builder.header("Referrer-Policy", "no-referrer");

            // Privacy: Permissions-Policy (restrict browser features).
            builder = builder.header(
                "Permissions-Policy",
                "geolocation=(), microphone=(), camera=()",
            );

            // Security: Prevent MIME type sniffing.
            builder = builder.header("X-Content-Type-Options", "nosniff");

            builder = builder.header("Content-Length", body_bytes.len().to_string());
            info!("  ← Sending {} bytes to browser", body_bytes.len());

            return Ok(builder.body(Full::new(Bytes::from(body_bytes))).unwrap());
        }
    }

    // Fallback: return the raw response bytes as application/octet-stream.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("Content-Length", response_bytes.len().to_string())
        .body(Full::new(response_bytes))
        .unwrap())
}

// HTTP request handlers

async fn handle_options_request() -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS, PATCH",
        )
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Max-Age", "86400")
        .header("Content-Length", "0")
        .body(Full::new(Bytes::new()))
        .unwrap())
}

async fn handle_request(
    req: Request<Incoming>,
    args: Arc<Args>,
    pool: ClientPool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::OPTIONS {
        return handle_options_request().await;
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let host_without_port = host.split(':').next().unwrap_or(&host).to_string();
    info!(
        "➜ {} {} (Host: {})",
        req.method(),
        req.uri().path(),
        host_without_port
    );

    if let Some(nym_address) = try_decode_nym_address(&host_without_port) {
        if let Some(target) = parse_recipient(&nym_address) {
            return forward_to_mixnet(
                req,
                target,
                &nym_address,
                &host_without_port,
                &args,
                pool,
            )
            .await;
        }
    }

    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NymFox Web Proxy</title>
</head>
<body style="font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
<h1>NymFox Web Proxy</h1>
<p style="color: #c00;">This proxy expects a <strong>hex-encoded Nym address</strong> (192 lowercase characters) as the hostname.</p>
<p>Got: <code>{}</code> (length: {})</p>
<p>Expected: 192 lowercase hex characters (0-9, a-f)</p>
</body>
</html>"#,
            host_without_port,
            host_without_port.len()
        ))))
        .unwrap())
}

// Main entry point

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load Nym network config FIRST (sets env vars internally).
    setup_env(None::<&str>);

    // Initialize tracing with a fixed filter that ignores RUST_LOG env var.
    // This ensures nym-web-proxy info logs always appear, and SDK internal logs
    // (client initialization, topology refresh, etc.) are suppressed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("nym-web-proxy=info"))
        .init();

    let args = Arc::new(Args::parse());

    info!(
        "Initializing Nym Client Pool (reserve size: {})...",
        args.pool_size
    );
    let pool = ClientPool::new(args.pool_size);
    let pool_clone = pool.clone();

    tokio::spawn(async move {
        if let Err(e) = pool_clone.start().await {
            error!("Client pool background task failed: {}", e);
        }
    });

    info!("Pre-warming client pool...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], args.listen_port))).await?;

    info!(
        "✓ RFC/W3C-compliant Nym Web Proxy ready on http://127.0.0.1:{}",
        args.listen_port
    );

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let args_clone = args.clone();
        let pool_clone = pool.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let a = args_clone.clone();
                let p = pool_clone.clone();
                async move { handle_request(req, a, p).await }
            });

            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, service)
                .await
            {
                debug!("Connection error: {}", e);
            }
        });
    }
}
