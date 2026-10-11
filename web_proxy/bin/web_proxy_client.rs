// Nym Web Proxy - (c) 2026 Ch1ffr3punk

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use nym_network_defaults::setup_env;
use nym_sdk::client_pool::ClientPool;
use nym_sdk::mixnet::{IncludedSurbs, MixnetClientBuilder, MixnetMessageSender, NymNetworkDetails};
use nym_sdk::tcp_proxy::utils::{DecayWrapper, Payload, ProxiedMessage};
use nym_sphinx_addressing::Recipient;
use regex::Regex;
use std::collections::HashSet;
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

    /// Rewrite HTML content to fix relative URLs
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

        self.buffer.retain(|w| !sent_ids.contains(&w.inner().message_id()));

        result
    }
}

// Nym address helpers

fn try_decode_nym_address(host: &str) -> Option<String> {
    if host.len() != 192 {
        info!("Host length {} != 192", host.len());
        return None;
    }
    let is_hex = host.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
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

// HTML rewriting

fn rewrite_html_content(html: &str, _original_host: &str, base_url: &str) -> String {
    let mut modified = html.to_string();
    let base_tag = format!("<base href=\"{}\">", base_url);

    if let Some(head_pos) = modified.find("<head>") {
        if !modified.contains("<base") {
            modified.insert_str(head_pos + 6, &format!("\n{}\n", base_tag));
        } else {
            let re = Regex::new(r"<base[^>]*>").unwrap();
            modified = re.replace(&modified, base_tag.as_str()).to_string();
        }
    }

    let legacy_pattern = Regex::new(
        r#"(href|src|action)=["'](https?://)([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})\.([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})@([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{43,44})([^"']*?)["']"#
    ).unwrap();

    modified = legacy_pattern.replace_all(&modified, |caps: &regex::Captures| {
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
    }).to_string();

    let form_pattern = Regex::new(r"<form([^>]*)>").unwrap();
    modified = form_pattern.replace_all(&modified, |caps: &regex::Captures| {
        let attrs = &caps[1];
        if !attrs.contains("autocomplete=") {
            format!("<form{} autocomplete=\"off\">", attrs)
        } else {
            caps[0].to_string()
        }
    }).to_string();

    modified
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
                            .body(Full::new(Bytes::from(format!("Mixnet connect error: {}", e))))
                            .unwrap());
                    }
                },
                Err(e) => {
                    error!("Mixnet build error: {}", e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!("Mixnet build error: {}", e))))
                        .unwrap());
                }
            }
        }
    };

    let session_id = Uuid::new_v4();
    let sender = client.split_sender();

    let method = req.method().clone();
    let browser_path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut actual_request = format!("{} {} HTTP/1.1\r\n", method, browser_path);
    actual_request.push_str(&format!("Host: {}\r\n", nym_address_str));

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

    for (name, value) in parts.headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if ["host", "content-length", "accept-encoding", "if-none-match", "if-modified-since"]
            .contains(&name_lower.as_str())
        {
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

    message_id = message_id.wrapping_add(1);
    let close_msg = ProxiedMessage::new(Payload::Close, session_id, message_id);
    if let Ok(coded) = bincode::serialize(&close_msg) {
        let _ = sender
            .send_message(target, &coded, IncludedSurbs::Amount(100))
            .await;
    }

    info!("  ✓ Request sent, waiting for mixnet response...");

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
                let header_end = response_buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                let body_start = header_end + 4;

                if is_chunked {
                    if response_buf.ends_with(b"0\r\n\r\n") || response_buf.ends_with(b"0\r\n\r\n\r\n") {
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
                }
            }
        }
    }).await;

    cancel_token.cancel();

    if response_buf.is_empty() {
        error!("Empty mixnet response");
        return Ok(Response::builder()
            .status(StatusCode::GATEWAY_TIMEOUT)
            .body(Full::new(Bytes::from("Empty mixnet response")))
            .unwrap());
    }

    let response_bytes = Bytes::from(response_buf);
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

            let mut builder = Response::builder().status(status_code);
            let mut content_type = String::new();

            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim();
                    let value = value.trim();
                    let name_lower = name.to_lowercase();

                    if ["content-encoding", "transfer-encoding", "connection", "etag", "last-modified", "cache-control"]
                        .contains(&name_lower.as_str())
                    {
                        continue;
                    }
                    if name_lower == "content-type" {
                        content_type = value.to_string();
                    }
                    builder = builder.header(name, value);
                }
            }

            builder = builder.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
            builder = builder.header("Pragma", "no-cache");
            builder = builder.header("Access-Control-Allow-Origin", "*");
            builder = builder.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
            builder = builder.header("Access-Control-Allow-Headers", "*");

            if args.rewrite_html && content_type.contains("text/html") {
                if let Ok(html_str) = std::str::from_utf8(&body_bytes) {
                    let rewritten = rewrite_html_content(
                        html_str,
                        original_host,
                        &format!("http://{}/", original_host),
                    );
                    body_bytes = rewritten.into_bytes();
                }
            }

            builder = builder.header("Content-Length", body_bytes.len().to_string());
            info!("  ← Sending {} bytes to browser", body_bytes.len());
            return Ok(builder.body(Full::new(Bytes::from(body_bytes))).unwrap());
        }
    }

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
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
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
    info!("➜ {} {} (Host: {})", req.method(), req.uri().path(), host_without_port);

    if let Some(nym_address) = try_decode_nym_address(&host_without_port) {
        if let Some(target) = parse_recipient(&nym_address) {
            return forward_to_mixnet(req, target, &nym_address, &host_without_port, &args, pool).await;
        }
    }

    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>NymFox Web Proxy</title></head>
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
    // Load Nym network config FIRST (sets env vars internally)
    setup_env(None::<&str>);

    // Initialize tracing with a FIXED filter that ignores RUST_LOG env var.
    // This ensures nym-web-proxy info logs always appear, and SDK internal logs
    // (client initialization, topology refresh, etc.) are suppressed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("nym-web-proxy=info"))
        .init();

    let args = Arc::new(Args::parse());

    info!("Initializing Nym Client Pool (reserve size: {})...", args.pool_size);
    let pool = ClientPool::new(args.pool_size);
    let pool_clone = pool.clone();

    tokio::spawn(async move {
        if let Err(e) = pool_clone.start().await {
            error!("Client pool background task failed: {}", e);
        }
    });

    info!("Pre-warming client pool...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], args.listen_port))).await?;

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
