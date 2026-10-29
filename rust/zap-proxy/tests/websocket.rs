// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Rust derivative of the ZAP core. It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build.

//! WebSocket opening handshake through the proxy, against an in-process echo server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zap_proxy::{install_crypto_provider, CertificateAuthority, Proxy, ProxyConfig};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const GREETING: &[u8] = b"hello-from-origin";
const CLIENT_PAYLOAD: &[u8] = &[0x00, 0xff, 0x0a, b'Z'];

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zapd-ws-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

async fn start_proxy(
    ca_dir: PathBuf,
    exclude: Vec<String>,
    extra_root_pems: Vec<String>,
) -> zap_proxy::RunningProxy {
    Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir,
        exclude,
        listeners: Vec::new(),
        extra_root_pems,
        history: None,
        early_override: None,
    })
    .await
    .expect("proxy start")
}

struct Frame {
    opcode: u8,
    payload: Vec<u8>,
}

fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [0x11, 0x22, 0x33, 0x44];
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x80 | opcode);
    frame.push(0x80 | payload.len() as u8);
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }
    frame
}

fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x80 | opcode);
    frame.push(payload.len() as u8);
    frame.extend_from_slice(payload);
    frame
}

async fn read_headers<R>(reader: &mut R) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65_536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
    String::from_utf8(buf).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

async fn read_frame<R>(reader: &mut R) -> std::io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await?;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7f) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    }
    let mask = if masked {
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask).await?;
        Some(mask)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Frame { opcode, payload })
}

fn request_path(header: &str) -> String {
    let target = header
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"));
    let path = if let Some(rest) = rest {
        match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        }
    } else {
        target
    };
    path.split('?').next().unwrap_or(path).to_string()
}

async fn speak<S>(mut socket: S, seen: Arc<Mutex<Vec<String>>>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header = read_headers(&mut socket).await?;
    seen.lock().expect("request log").push(header.clone());
    let path = request_path(&header);
    if path == "/reject" {
        let body = "nope";
        let response = format!(
            "HTTP/1.1 400 No\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    if path != "/socket" {
        let body = "plain";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
    );
    socket.write_all(response.as_bytes()).await?;
    socket.write_all(&server_frame(0x1, GREETING)).await?;
    let frame = read_frame(&mut socket).await?;
    socket
        .write_all(&server_frame(frame.opcode, &frame.payload))
        .await?;
    let mut buf = [0u8; 32];
    loop {
        match socket.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(())
}

async fn spawn_echo() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_task = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let seen_task = Arc::clone(&seen_task);
            tokio::spawn(async move {
                if let Err(err) = speak(socket, seen_task).await {
                    eprintln!("websocket echo: {err}");
                }
            });
        }
    });
    (addr, seen)
}

async fn spawn_tls_echo(ca_dir: &Path) -> (SocketAddr, String, Arc<Mutex<Vec<String>>>) {
    install_crypto_provider();
    let ca = CertificateAuthority::open(ca_dir).unwrap();
    let pem = ca.cert_pem().to_string();
    let acceptor = TlsAcceptor::from(ca.server_config("127.0.0.1").unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_task = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen_task = Arc::clone(&seen_task);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                if let Err(err) = speak(tls, seen_task).await {
                    eprintln!("websocket tls echo: {err}");
                }
            });
        }
    });
    (addr, pem, seen)
}

fn proxy_handshake(origin: SocketAddr, path: &str) -> String {
    format!(
        "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        port = origin.port(),
    )
}

fn header_has(header: &str, name: &str, value: &str) -> bool {
    header.lines().any(|line| {
        line.split_once(':').is_some_and(|(key, raw)| {
            key.trim().eq_ignore_ascii_case(name) && raw.trim().eq_ignore_ascii_case(value)
        })
    })
}

fn header_contains(header: &str, name: &str, needle: &str) -> bool {
    header.lines().any(|line| {
        line.split_once(':').is_some_and(|(key, raw)| {
            key.trim().eq_ignore_ascii_case(name)
                && raw
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
        })
    })
}

async fn expect_frames<S>(socket: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let greeting = tokio::time::timeout(Duration::from_secs(5), read_frame(socket))
        .await
        .expect("greeting timed out")
        .expect("greeting");
    assert_eq!(greeting.opcode, 0x1, "text greeting");
    assert_eq!(greeting.payload, GREETING);

    socket
        .write_all(&client_frame(0x2, CLIENT_PAYLOAD))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), read_frame(socket))
        .await
        .expect("echo timed out")
        .expect("echo");
    assert_eq!(echoed.opcode, 0x2, "binary opcode preserved");
    assert_eq!(echoed.payload, CLIENT_PAYLOAD);
}

fn assert_handshake_row(proxy: &zap_proxy::RunningProxy, scheme: &str) {
    let rows = proxy.history().rows();
    assert_eq!(rows.len(), 1, "history: {rows:?}");
    assert_eq!(rows[0].method, "GET");
    assert_eq!(rows[0].status, 101);
    assert!(rows[0].url.starts_with(scheme), "{}", rows[0].url);
    assert!(rows[0].url.ends_with("/socket"), "{}", rows[0].url);
    assert!(rows[0].request_body.is_empty());
    assert!(rows[0].response_body.is_empty(), "frames are not stored");
    assert!(rows[0]
        .request_headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("sec-websocket-key") && value == KEY));
    assert!(rows[0].request_headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
    }));
    assert!(rows[0].response_headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("sec-websocket-accept") && value == ACCEPT
    }));
}

#[tokio::test]
async fn websocket_frames_pass_both_ways_and_the_handshake_is_stored() {
    let (origin, seen) = spawn_echo().await;
    let dir = temp_dir("ws");
    let proxy = start_proxy(dir.clone(), Vec::new(), Vec::new()).await;

    let mut socket = TcpStream::connect(proxy.local_addr()).await.unwrap();
    socket
        .write_all(proxy_handshake(origin, "/socket").as_bytes())
        .await
        .unwrap();
    let header = tokio::time::timeout(Duration::from_secs(5), read_headers(&mut socket))
        .await
        .expect("101 timed out")
        .expect("101");
    assert!(
        header.starts_with("HTTP/1.1 101"),
        "response head: {header:?}"
    );
    assert!(header_has(&header, "upgrade", "websocket"), "{header:?}");
    assert!(
        header_contains(&header, "connection", "upgrade"),
        "{header:?}"
    );
    assert!(
        header_has(&header, "sec-websocket-accept", ACCEPT),
        "{header:?}"
    );
    expect_frames(&mut socket).await;
    drop(socket);

    assert_handshake_row(&proxy, "http://");
    let origin_request = seen.lock().expect("request log")[0].clone();
    assert!(
        header_has(&origin_request, "sec-websocket-key", KEY),
        "origin saw: {origin_request:?}"
    );
    assert!(
        header_contains(&origin_request, "via", "1.1 zapd"),
        "origin saw: {origin_request:?}"
    );
    assert!(
        request_path(&origin_request).ends_with("/socket"),
        "origin saw: {origin_request:?}"
    );

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn rejected_handshake_is_recorded_and_not_tunneled() {
    let (origin, _) = spawn_echo().await;
    let dir = temp_dir("reject");
    let proxy = start_proxy(dir.clone(), Vec::new(), Vec::new()).await;

    let mut socket = TcpStream::connect(proxy.local_addr()).await.unwrap();
    socket
        .write_all(proxy_handshake(origin, "/reject").as_bytes())
        .await
        .unwrap();
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), read_http(&mut socket))
        .await
        .expect("400 timed out")
        .expect("400");
    assert_eq!(status, 400);
    assert_eq!(body, b"nope");

    let rows = proxy.history().rows();
    assert_eq!(rows.len(), 1, "history: {rows:?}");
    assert_eq!(rows[0].status, 400);
    assert_eq!(rows[0].response_body.as_ref(), b"nope");
    assert!(rows[0].url.ends_with("/reject"), "{}", rows[0].url);

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn incomplete_upgrade_stays_on_the_http_path() {
    let (origin, seen) = spawn_echo().await;
    let dir = temp_dir("plain");
    let proxy = start_proxy(dir.clone(), Vec::new(), Vec::new()).await;
    let request = format!(
        "GET http://127.0.0.1:{port}/kept HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        port = origin.port(),
    );
    let mut socket = TcpStream::connect(proxy.local_addr()).await.unwrap();
    socket.write_all(request.as_bytes()).await.unwrap();
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), read_http(&mut socket))
        .await
        .expect("plain timed out")
        .expect("plain");
    assert_eq!(status, 200);
    assert_eq!(body, b"plain");

    let origin_request = seen.lock().expect("request log")[0].clone();
    assert!(
        !header_contains(&origin_request, "upgrade", "websocket"),
        "ordinary forward strips the upgrade: {origin_request:?}"
    );
    let rows = proxy.history().rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, 200);
    assert!(rows[0].url.ends_with("/kept"), "{}", rows[0].url);

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn excluded_websocket_is_tunneled_and_not_stored() {
    let (origin, _) = spawn_echo().await;
    let dir = temp_dir("exclude");
    let proxy = start_proxy(
        dir.clone(),
        vec![r"http://127\.0\.0\.1:\d+/socket".to_string()],
        Vec::new(),
    )
    .await;

    let mut socket = TcpStream::connect(proxy.local_addr()).await.unwrap();
    socket
        .write_all(proxy_handshake(origin, "/socket").as_bytes())
        .await
        .unwrap();
    let header = tokio::time::timeout(Duration::from_secs(5), read_headers(&mut socket))
        .await
        .expect("101 timed out")
        .expect("101");
    assert!(header.starts_with("HTTP/1.1 101"), "{header:?}");
    expect_frames(&mut socket).await;
    drop(socket);
    assert!(
        proxy.history().is_empty(),
        "excluded handshake is not stored"
    );

    let kept = format!(
        "GET http://127.0.0.1:{port}/kept HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        port = origin.port(),
    );
    let mut plain = TcpStream::connect(proxy.local_addr()).await.unwrap();
    plain.write_all(kept.as_bytes()).await.unwrap();
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), read_http(&mut plain))
        .await
        .expect("kept timed out")
        .expect("kept");
    assert_eq!(status, 200);
    assert_eq!(body, b"plain");
    let urls = proxy.history().urls();
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(urls[0].ends_with("/kept"), "{urls:?}");

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn websocket_over_connect_tunnels_frames() {
    let origin_dir = temp_dir("origin-ca");
    let (origin, origin_pem, _) = spawn_tls_echo(&origin_dir).await;
    let proxy_dir = temp_dir("proxy-ca");
    let proxy = start_proxy(proxy_dir.clone(), Vec::new(), vec![origin_pem]).await;

    let mut tcp = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = origin.port(),
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let connect_header = tokio::time::timeout(Duration::from_secs(5), read_headers(&mut tcp))
        .await
        .expect("connect timed out")
        .expect("connect");
    assert!(
        connect_header.starts_with("HTTP/1.1 200"),
        "{connect_header:?}"
    );

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(proxy.ca_cert_pem())));
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector.connect(name, tcp).await.expect("mitm tls");
    let request = format!(
        "GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        port = origin.port(),
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    let header = tokio::time::timeout(Duration::from_secs(5), read_headers(&mut tls))
        .await
        .expect("101 timed out")
        .expect("101");
    assert!(header.starts_with("HTTP/1.1 101"), "{header:?}");
    assert!(
        header_has(&header, "sec-websocket-accept", ACCEPT),
        "{header:?}"
    );
    expect_frames(&mut tls).await;

    assert_handshake_row(&proxy, "https://");

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(origin_dir);
    let _ = std::fs::remove_dir_all(proxy_dir);
}

fn tls_config(ca_pem: &str) -> ClientConfig {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.expect("pem")).expect("trust anchor");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn read_http<R>(reader: &mut R) -> std::io::Result<(u16, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let header = read_headers(reader).await?;
    let status = header
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let mut length = None;
    for line in header.split("\r\n") {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap_or(0));
        }
    }
    let length = length.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("no content-length in {header:?}"),
        )
    })?;
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok((status, body))
}
