// Copyright 2010-2024 The ZAP Development Team
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

//! The passive-scan queue runs on the proxy response path.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zap_proxy::{Proxy, ProxyConfig, RunningProxy};
use zap_pscan::{AlertThreshold, PassiveScanListener, PLUGIN_ID};
use zap_store::{Session, SessionHistoryListener};

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-pscan-proxy-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

async fn spawn_origin(status: &str, extra_headers: &str, body: &[u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    let extra_headers = extra_headers.to_string();
    let body = body.to_vec();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0_u8; 2048];
        let _ = socket.read(&mut buf).await;
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(header.as_bytes()).await;
        let _ = socket.write_all(&body).await;
    });
    addr
}

async fn http_exchange(addr: SocketAddr, request: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("response header");
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8(header).unwrap();
    let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut length = 0_usize;
    for line in header.split("\r\n") {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0_u8; length];
    if length > 0 {
        stream.read_exact(&mut body).await.expect("response body");
    }
    (status, body)
}

async fn start_proxy(
    dir: &std::path::Path,
    session: Arc<Session>,
    listener: Arc<PassiveScanListener>,
) -> RunningProxy {
    Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir: dir.join("ca"),
        exclude: Vec::new(),
        listeners: vec![
            Arc::new(SessionHistoryListener::new(Arc::clone(&session))),
            listener,
        ],
        extra_root_pems: Vec::new(),
        history: None,
        early_override: None,
    })
    .await
    .expect("proxy")
}

#[tokio::test]
async fn proxy_fixture_response_raises_one_alert_with_plugin_risk_and_url() {
    let origin = spawn_origin("200 OK", "", b"<html>fixture</html>").await;
    let dir = temp_dir("alert");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let listener = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
    let proxy = start_proxy(&dir, Arc::clone(&session), Arc::clone(&listener)).await;

    let url = format!("http://127.0.0.1:{}/fixture", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let (status, body) = http_exchange(proxy.local_addr(), &request).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"<html>fixture</html>");

    let alerts = session.alerts().unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].plugin_id, 10021);
    assert_eq!(alerts[0].plugin_id, PLUGIN_ID);
    assert_eq!(alerts[0].risk, 1);
    assert_eq!(alerts[0].url, url);
    assert_eq!(session.history_rows().unwrap()[0].url, url);

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn proxy_threshold_off_raises_nothing() {
    let origin = spawn_origin("200 OK", "", b"<html>fixture</html>").await;
    let dir = temp_dir("off");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let listener = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
    listener.set_threshold(PLUGIN_ID, AlertThreshold::Off);
    let proxy = start_proxy(&dir, Arc::clone(&session), listener).await;

    let url = format!("http://127.0.0.1:{}/fixture", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let (status, _) = http_exchange(proxy.local_addr(), &request).await;
    assert_eq!(status, 200);
    assert!(session.alerts().unwrap().is_empty());
    assert_eq!(session.history_rows().unwrap().len(), 1);

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn proxy_nosniff_response_raises_nothing() {
    let origin = spawn_origin(
        "200 OK",
        "X-Content-Type-Options: nosniff\r\n",
        b"<html>safe</html>",
    )
    .await;
    let dir = temp_dir("nosniff");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let listener = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
    let proxy = start_proxy(&dir, Arc::clone(&session), listener).await;

    let url = format!("http://127.0.0.1:{}/ok", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let (status, _) = http_exchange(proxy.local_addr(), &request).await;
    assert_eq!(status, 200);
    assert!(session.alerts().unwrap().is_empty());

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
