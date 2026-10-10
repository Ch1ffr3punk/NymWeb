// http_connect.rs
//
// HTTP proxy request parser. Supports:
// 1. CONNECT requests (used by browsers for HTTPS tunneling)
// 2. Absolute GET/POST requests (used by browsers for plain HTTP)
//
// The parser treats the host as a direct Nym recipient address.

use anyhow::{bail, Context, Result};
use nym_sphinx_addressing::Recipient;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const MAX_HEADER_BYTES: usize = 8 * 1024;

pub enum ConnectOutcome {
    Tunneled {
        target: Recipient,
        stream: PrefixedStream,
    },
}

pub struct PrefixedStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    pub fn into_split(self) -> (PrefixedReadHalf, tokio::net::tcp::OwnedWriteHalf) {
        let (read, write) = self.inner.into_split();
        (
            PrefixedReadHalf {
                prefix: self.prefix,
                prefix_pos: self.prefix_pos,
                inner: read,
            },
            write,
        )
    }
}

pub struct PrefixedReadHalf {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: tokio::net::tcp::OwnedReadHalf,
}

impl AsyncRead for PrefixedReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub async fn try_http_connect(mut stream: TcpStream) -> Result<ConnectOutcome> {
    let mut peek = [0u8; 8];
    let n = match stream.peek(&mut peek).await {
        Ok(n) if n >= 4 => n,
        Ok(n) if n > 0 => n,
        _ => bail!("Connection closed before HTTP request could be read"),
    };

    let starts_connect = n >= 8 && &peek[..8] == b"CONNECT ";
    let starts_get = n >= 4 && &peek[..4] == b"GET ";
    let starts_post = n >= 5 && &peek[..5] == b"POST ";
    let starts_head = n >= 5 && &peek[..5] == b"HEAD ";
    let starts_put = n >= 4 && &peek[..4] == b"PUT ";
    let starts_delete = n >= 7 && &peek[..7] == b"DELETE ";
    let starts_options = n >= 8 && &peek[..8] == b"OPTIONS ";

    let is_absolute_request = starts_get
        || starts_post
        || starts_head
        || starts_put
        || starts_delete
        || starts_options;

    if !starts_connect && !is_absolute_request {
        bail!(
            "Not a valid HTTP proxy request (starts with: {:?})",
            String::from_utf8_lossy(&peek[..n])
        );
    }

    let mut request_buf = Vec::with_capacity(1024);
    let mut temp_buf = [0u8; 512];
    loop {
        let n = stream.read(&mut temp_buf).await?;
        if n == 0 {
            bail!("Client closed the connection while reading headers");
        }
        request_buf.extend_from_slice(&temp_buf[..n]);
        if request_buf.len() >= MAX_HEADER_BYTES {
            bail!("Headers exceed maximum size of {} bytes", MAX_HEADER_BYTES);
        }
        if request_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request_str =
        String::from_utf8(request_buf.clone()).context("HTTP headers are not valid UTF-8")?;
    debug!("Received HTTP request headers:\n{}", request_str);

    if starts_connect {
        handle_connect_request(request_str, stream).await
    } else {
        handle_absolute_request(request_str, stream).await
    }
}

/// Resolves a hostname to a Nym recipient by parsing it as a direct Nym address.
fn resolve_target(hostname: &str) -> Result<Recipient> {
    // Strip any trailing .nym pseudo-TLD if present.
    let clean_host = hostname.strip_suffix(".nym").unwrap_or(hostname);

    // Parse as a direct Nym address.
    Recipient::try_from_base58_string(clean_host)
        .with_context(|| format!("'{}' is not a valid Nym address", clean_host))
}

async fn handle_connect_request(
    request_str: String,
    mut stream: TcpStream,
) -> Result<ConnectOutcome> {
    let host_value = extract_host_header(&request_str)?;
    let host_stripped = strip_port(&host_value);
    let target = resolve_target(host_stripped)?;

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("Failed to send 200 response")?;
    stream.flush().await?;

    Ok(ConnectOutcome::Tunneled {
        target,
        stream: PrefixedStream::new(Vec::new(), stream),
    })
}

async fn handle_absolute_request(
    request_str: String,
    stream: TcpStream,
) -> Result<ConnectOutcome> {
    let first_line = request_str.lines().next().context("Empty HTTP request")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().context("Missing HTTP method")?;
    let url = parts.next().context("Missing URL in request")?;
    let http_version = parts.next().unwrap_or("HTTP/1.1");

    let url_parsed = url::Url::parse(url).context("Invalid URL in request")?;
    let host_with_port = url_parsed.host_str().context("Missing host in URL")?;
    let host_decoded = percent_decode(host_with_port);
    let host_stripped = strip_port(&host_decoded);

    let target = resolve_target(host_stripped)?;

    let path = if url_parsed.path().is_empty() {
        "/"
    } else {
        url_parsed.path()
    };
    let query = url_parsed
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let mut rewritten = String::with_capacity(request_str.len());
    let mut first_line_done = false;
    for line in request_str.lines() {
        if !first_line_done {
            rewritten.push_str(&format!("{} {}{} {}\r\n", method, path, query, http_version));
            first_line_done = true;
        } else {
            rewritten.push_str(line);
            if !line.ends_with('\r') {
                rewritten.push('\r');
            }
            rewritten.push('\n');
        }
    }

    let rewritten_bytes = rewritten.into_bytes();
    debug!(
        "Rewritten HTTP request:\n{}",
        String::from_utf8_lossy(&rewritten_bytes)
    );

    Ok(ConnectOutcome::Tunneled {
        target,
        stream: PrefixedStream::new(rewritten_bytes, stream),
    })
}

fn extract_host_header(request_str: &str) -> Result<String> {
    for line in request_str.lines() {
        let line = line.trim();
        if line.is_empty() || line == "\r" {
            continue;
        }
        if line.to_lowercase().starts_with("host:") {
            return Ok(line[5..].trim().to_string());
        }
    }
    bail!("Missing Host header in HTTP request")
}

fn strip_port(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((a, port)) => {
            if port.parse::<u16>().is_ok() {
                a
            } else {
                addr
            }
        }
        None => addr,
    }
}

fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}
