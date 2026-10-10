use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Method};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, debug};
use regex::Regex;
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value_t = 8081)]
    listen_port: u16,

    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    nym_proxy_host: String,

    #[arg(short = 'P', long, default_value_t = 8080)]
    nym_proxy_port: u16,

    #[arg(long, default_value_t = false)]
    rewrite_html: bool,

    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,
}

fn try_decode_nym_address(host: &str) -> Option<String> {
    if host.len() != 192 {
        debug!("Host length {} != 192", host.len());
        return None;
    }

    let is_hex = host.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !is_hex {
        debug!("Host contains non-hex or uppercase characters");
        return None;
    }

    let decoded_bytes = match hex::decode(host) {
        Ok(bytes) => bytes,
        Err(e) => {
            debug!("Hex decode failed: {}", e);
            return None;
        }
    };

    if decoded_bytes.len() != 96 {
        debug!("Decoded length {} != 96", decoded_bytes.len());
        return None;
    }

    let identity_key = bs58::encode(&decoded_bytes[0..32]).into_string();
    let encryption_key = bs58::encode(&decoded_bytes[32..64]).into_string();
    let gateway_key = bs58::encode(&decoded_bytes[64..96]).into_string();

    let nym_address = format!("{}.{}@{}", identity_key, encryption_key, gateway_key);
    info!("✓ Decoded Nym address: {}", nym_address);
    Some(nym_address)
}

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

async fn forward_to_nym_proxy(
    req: Request<Incoming>,
    nym_address: &str,
    proxy_host: &str,
    proxy_port: u16,
    original_host: &str,
    args: &Args,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);
    info!("  → Connecting to nym-proxy-client at {}", proxy_addr);

    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(args.timeout_secs),
        TcpStream::connect(&proxy_addr)
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("Connection failed: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Connect error: {}", e))))
                .unwrap());
        }
        Err(_) => {
            error!("Connection timeout");
            return Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Full::new(Bytes::from("Connection timeout")))
                .unwrap());
        }
    };

    let connect_request = format!(
        "CONNECT {}:80 HTTP/1.1\r\nHost: {}\r\n\r\n",
        nym_address, nym_address
    );
    if let Err(_e) = stream.write_all(connect_request.as_bytes()).await {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("CONNECT send error")))
            .unwrap());
    }

    let mut connect_resp_buf = [0u8; 1024];
    let n = match stream.read(&mut connect_resp_buf).await {
        Ok(n) => n,
        Err(_e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("CONNECT read error")))
                .unwrap());
        }
    };
    
    let connect_resp = String::from_utf8_lossy(&connect_resp_buf[..n]);
    if !connect_resp.contains("200") && !connect_resp.contains("201") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from(format!("Proxy rejected: {}", connect_resp.trim()))))
            .unwrap());
    }
    info!("  ✓ CONNECT tunnel established");

    let method = req.method().clone();
    let browser_path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut actual_request = format!("{} {} HTTP/1.1\r\n", method, browser_path);
    actual_request.push_str(&format!("Host: {}\r\n", nym_address));
    
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!("Body error: {}", e))))
                .unwrap());
        }
    };

    for (name, value) in parts.headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower == "host" 
            || name_lower == "content-length" 
            || name_lower == "accept-encoding" 
            || name_lower == "if-none-match" 
            || name_lower == "if-modified-since" 
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

    if let Err(_e) = stream.write_all(actual_request.as_bytes()).await {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Request send error")))
            .unwrap());
    }
    if !body_bytes.is_empty() {
        let _ = stream.write_all(&body_bytes).await;
    }
    info!("  ✓ Actual request sent, waiting for response...");

    let mut response_buf = Vec::new();
    let mut temp_buf = [0u8; 8192];
    let timeout_duration = std::time::Duration::from_secs(args.timeout_secs);

    let _ = tokio::time::timeout(timeout_duration, async {
        let mut headers_complete = false;
        let mut expected_body_len = 0usize;
        let mut is_chunked = false;

        loop {
            match stream.read(&mut temp_buf).await {
                Ok(0) => {
                    info!("  ← Connection closed (EOF). Total: {} bytes", response_buf.len());
                    break;
                }
                Ok(n) => {
                    response_buf.extend_from_slice(&temp_buf[..n]);
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
                                    break;
                                }
                            }
                            if headers_part.to_lowercase().contains("transfer-encoding: chunked") {
                                is_chunked = true;
                                info!("  ← Response is chunked");
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
                                info!("  ← Content-Length satisfied (have {}, expected {}). Total: {}", 
                                    response_buf.len() - body_start, expected_body_len, response_buf.len());
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading: {}", e);
                    break;
                }
            }
        }
    }).await;

    if response_buf.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Empty response")))
            .unwrap());
    }

    let response_bytes = Bytes::from(response_buf);
    if let Some(header_end) = response_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        let header_bytes = &response_bytes[..header_end];
        let mut body_bytes = response_bytes[header_end + 4..].to_vec();

        if let Ok(header_str) = std::str::from_utf8(header_bytes) {
            let mut lines = header_str.lines();
            let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
            let status_code = status_line.split_whitespace()
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
                    
                    if name_lower == "content-encoding" 
                        || name_lower == "transfer-encoding" 
                        || name_lower == "connection" 
                        || name_lower == "etag" 
                        || name_lower == "last-modified" 
                        || name_lower == "cache-control" 
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
                    let rewritten = rewrite_html_content(html_str, original_host, &format!("http://{}/", original_host));
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::OPTIONS {
        return handle_options_request().await;
    }

    let host = req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let host_without_port = host.split(':').next().unwrap_or(&host).to_string();
    info!("➜ {} {} (Host: {})", req.method(), req.uri().path(), host_without_port);

    if let Some(nym_address) = try_decode_nym_address(&host_without_port) {
        forward_to_nym_proxy(
            req,
            &nym_address,
            &args.nym_proxy_host,
            args.nym_proxy_port,
            &host_without_port,
            &args,
        ).await
    } else {
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
                host_without_port, host_without_port.len()
            ))))
            .unwrap())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nymweb=info".parse().unwrap()),
        )
        .init();

    let args = Arc::new(Args::parse());
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], args.listen_port))).await?;

    info!("═══════════════════════════════════════════════════════");
    info!("  Nym Web Proxy v0.1.0 - (c) 2026 Ch1ffr3punk");
    info!("═══════════════════════════════════════════════════════");
    info!("  Listening on:      http://127.0.0.1:{}", args.listen_port);
    info!("  Nym-Proxy-Client:  {}:{}", args.nym_proxy_host, args.nym_proxy_port);
    info!("  HTML rewriting:    {}", if args.rewrite_html { "enabled" } else { "disabled" });
    info!("  Timeout:           {} seconds", args.timeout_secs);
    info!("═══════════════════════════════════════════════════════");

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let args_clone = args.clone();
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let a = args_clone.clone();
                async move { handle_request(req, a).await }
            });
            let _ = http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, service)
                .await;
        });
    }
}
