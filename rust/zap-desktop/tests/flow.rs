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

//! A person can proxy a site, inspect the message, and forward or drop a breakpoint.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zap_desktop::{launch, DesktopConfig};

fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-desktop-flow-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

async fn spawn_origin(
    body: &'static [u8],
) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits_task = std::sync::Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let hits_task = std::sync::Arc::clone(&hits_task);
            tokio::spawn(async move {
                let mut header = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n\r\n") || header.len() > 8192 {
                        break;
                    }
                }
                hits_task.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });
    (addr, hits)
}

async fn read_http(stream: &mut TcpStream) -> (u16, Vec<u8>) {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.unwrap();
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8(header).unwrap();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut length = 0usize;
    for line in text.split("\r\n") {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body).await.unwrap();
    }
    (status, body)
}

async fn ui_exchange(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = None;
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    let mut stream = stream.expect("ui listen");
    stream.write_all(request.as_bytes()).await.unwrap();
    let (status, body) = read_http(&mut stream).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn wait_json(ui: SocketAddr, needle: &str) -> String {
    let start = Instant::now();
    loop {
        let (status, body) = ui_exchange(
            ui,
            "GET /state.json HTTP/1.1\r\nHost: ui\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        if body.contains(needle) {
            return body;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "state stayed {body}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_inspect_and_forward_without_the_json_api() {
    let dir = temp_dir("forward");
    let (origin, hits) = spawn_origin(b"origin-body").await;
    let desktop = launch(DesktopConfig {
        ui: SocketAddr::from(([127, 0, 0, 1], 0)),
        proxy: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_path: dir.join("session.sqlite"),
        ca_dir: dir.join("ca"),
    })
    .await
    .unwrap();
    let ui = desktop.ui_addr();
    let proxy = desktop.proxy_addr();
    let (status, page) = ui_exchange(
        ui,
        "GET / HTTP/1.1\r\nHost: ui\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(page.contains("<h2>Sites</h2>"));
    assert!(page.contains("<h2>History</h2>"));
    assert!(page.contains("<h2>Request</h2>"));
    assert!(page.contains("<h2>Response</h2>"));
    assert!(page.contains("<h2>Alerts</h2>"));
    assert!(page.contains("Break on requests"));
    assert!(page.contains("Break on responses"));
    assert!(page.contains("/state.json"));
    assert!(page.contains("setInterval"));

    let (status, _) = ui_exchange(
        ui,
        "POST /break/request HTTP/1.1\r\nHost: ui\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\nConnection: close\r\n\r\nenabled=true",
    )
    .await;
    assert_eq!(status, 303);

    let url = format!("http://127.0.0.1:{}/item", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let proxy_task = tokio::spawn(async move {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        read_http(&mut stream).await
    });
    let state = wait_json(ui, "\"side\":\"request\"").await;
    assert!(state.contains(&url));
    let (status, held_page) = ui_exchange(
        ui,
        "GET / HTTP/1.1\r\nHost: ui\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(held_page.contains("Forward"));
    assert!(held_page.contains("Drop"));
    assert!(held_page.contains(&url));
    assert!(held_page.contains("data-id=\"1\""));

    let (status, _) = ui_exchange(
        ui,
        "POST /break/forward HTTP/1.1\r\nHost: ui\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nConnection: close\r\n\r\nid=1",
    )
    .await;
    assert_eq!(status, 303, "forward should accept the waiting id");
    let (status, body) = proxy_task.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, b"origin-body");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let state = wait_json(ui, "origin-body").await;
    assert!(state.contains("\"method\":\"GET\""));
    assert!(state.contains(&url));
    assert!(state.contains("\"pluginId\":10021"));
    assert!(state.contains("fixture") || state.contains("127.0.0.1"));
    let (status, page) = ui_exchange(
        ui,
        "GET /?history=1 HTTP/1.1\r\nHost: ui\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(page.contains("origin-body"));
    assert!(page.contains(&url));
    assert!(page.contains("plugin 10021"));
    desktop.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_stops_the_request_before_the_origin() {
    let dir = temp_dir("drop");
    let (origin, hits) = spawn_origin(b"should-not-arrive").await;
    let desktop = launch(DesktopConfig {
        ui: SocketAddr::from(([127, 0, 0, 1], 0)),
        proxy: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_path: dir.join("session.sqlite"),
        ca_dir: dir.join("ca"),
    })
    .await
    .unwrap();
    let ui = desktop.ui_addr();
    let proxy = desktop.proxy_addr();
    let (status, _) = ui_exchange(
        ui,
        "POST /break/request HTTP/1.1\r\nHost: ui\r\nContent-Length: 12\r\nConnection: close\r\n\r\nenabled=true",
    )
    .await;
    assert_eq!(status, 303);
    let url = format!("http://127.0.0.1:{}/gone", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let proxy_task = tokio::spawn(async move {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        read_http(&mut stream).await
    });
    let state = wait_json(ui, "\"side\":\"request\"").await;
    let id = state
        .split("\"id\":")
        .nth(1)
        .unwrap()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .unwrap();
    let drop_body = format!("id={id}");
    let drop_request = format!(
        "POST /break/drop HTTP/1.1\r\nHost: ui\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{drop_body}",
        drop_body.len()
    );
    let (status, _) = ui_exchange(ui, &drop_request).await;
    assert_eq!(status, 303);
    let (status, body) = proxy_task.await.unwrap();
    assert_eq!(status, 502);
    assert!(String::from_utf8_lossy(&body).contains("listener stopped"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let (status, state) = ui_exchange(
        ui,
        "GET /state.json HTTP/1.1\r\nHost: ui\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert!(state.contains("\"history\":[]"));
    desktop.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_forward_keeps_an_edited_body() {
    let dir = temp_dir("edit");
    let (origin, _) = spawn_origin(b"origin-body").await;
    let desktop = launch(DesktopConfig {
        ui: SocketAddr::from(([127, 0, 0, 1], 0)),
        proxy: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_path: dir.join("session.sqlite"),
        ca_dir: dir.join("ca"),
    })
    .await
    .unwrap();
    let ui = desktop.ui_addr();
    let proxy = desktop.proxy_addr();
    let (status, _) = ui_exchange(
        ui,
        "POST /break/response HTTP/1.1\r\nHost: ui\r\nContent-Length: 12\r\nConnection: close\r\n\r\nenabled=true",
    )
    .await;
    assert_eq!(status, 303);
    let url = format!("http://127.0.0.1:{}/edit", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let proxy_task = tokio::spawn(async move {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        read_http(&mut stream).await
    });
    let _ = wait_json(ui, "\"side\":\"response\"").await;
    let form = "id=1&body=changed-body";
    let forward = format!(
        "POST /break/forward HTTP/1.1\r\nHost: ui\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
        form.len()
    );
    let (status, _) = ui_exchange(ui, &forward).await;
    assert_eq!(status, 303);
    let (status, body) = proxy_task.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body, b"changed-body");
    let state = wait_json(ui, "changed-body").await;
    assert!(state.contains("\"pluginId\":10021"));
    desktop.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
