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

//! `http://zap/JSON/...` is answered by the proxy and is not stored.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zap_api::ApiService;
use zap_proxy::{Proxy, ProxyConfig};
use zap_store::{Session, SessionHistoryListener};

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-api-proxy-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0_u8; 2048];
        let _ = socket.read(&mut buf).await;
        let body = b"origin-body";
        let header = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(header.as_bytes()).await;
        let _ = socket.write_all(body).await;
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

#[tokio::test]
async fn proxy_serves_zap_json_and_shutdown_without_storing_the_call() {
    let origin = spawn_origin().await;
    let dir = temp_dir("api");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let api = Arc::new(ApiService::new(
        Arc::clone(&session),
        "0.1.0",
        Arc::new(move || {
            flag.store(true, Ordering::SeqCst);
        }),
    ));
    let proxy = Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir: dir.join("ca"),
        exclude: Vec::new(),
        listeners: vec![Arc::new(SessionHistoryListener::new(Arc::clone(&session)))],
        extra_root_pems: Vec::new(),
        history: None,
        early_override: Some(Arc::new(move |message| api.handle(message))),
    })
    .await
    .expect("proxy");

    let proxied = format!(
        "GET http://127.0.0.1:{port}/hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        port = origin.port()
    );
    let (status, body) = http_exchange(proxy.local_addr(), &proxied).await;
    assert_eq!(status, 201);
    assert_eq!(body, b"origin-body");

    let (status, body) = http_exchange(
        proxy.local_addr(),
        "GET http://zap/JSON/core/view/version/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    let version: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(version["version"], "0.1.0");

    let (status, body) = http_exchange(
        proxy.local_addr(),
        "GET http://zap/JSON/core/view/messages/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    let messages: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let list = messages["messages"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    let message: serde_json::Value = serde_json::from_str(list[0].as_str().unwrap()).unwrap();
    assert_eq!(message["responseBody"], "origin-body");
    assert_eq!(message["type"], "1");

    let (status, body) = http_exchange(
        proxy.local_addr(),
        "GET http://zap/JSON/core/view/hosts/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    let hosts: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(hosts["hosts"][0], "127.0.0.1");

    assert_eq!(
        session.history_rows().unwrap().len(),
        1,
        "api calls are not history rows"
    );

    let (status, body) = http_exchange(
        proxy.local_addr(),
        "GET http://zap/JSON/core/action/shutdown/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["Result"], "OK");
    assert!(shutdown.load(Ordering::SeqCst));
    assert_eq!(session.history_rows().unwrap().len(), 1);

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
