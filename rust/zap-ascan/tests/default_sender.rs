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

//! Both rules against a local origin, sent by the default HTTP client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zap_ascan::{ActiveScanService, DefaultSender, ScanOptions, CRLF_PLUGIN_ID, XPATH_PLUGIN_ID};
use zap_core::{HttpMessage, HttpResponse};
use zap_store::Session;

fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-ascan-sender-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn form_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    out.push((high << 4) | low);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_value(target: &str, name: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if form_decode(key) == name {
            Some(form_decode(value))
        } else {
            None
        }
    })
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        socket.read_exact(&mut byte).await.expect("request");
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(header).unwrap()
}

async fn spawn_crlf() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let header = read_request(&mut socket).await;
                let target = header.split_whitespace().nth(1).unwrap_or("/");
                let mut extra = String::new();
                if let Some(years) = query_value(target, "years") {
                    if let Some((name, value)) = years.split_once("\r\n").and_then(|(_, rest)| {
                        let (name, value) = rest.split_once(':')?;
                        Some((name.trim().to_string(), value.trim().to_string()))
                    }) {
                        extra = format!("{name}: {value}\r\n");
                    }
                }
                let body = b"<html><body></body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });
    addr
}

async fn spawn_xpath() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let header = read_request(&mut socket).await;
                let target = header.split_whitespace().nth(1).unwrap_or("/");
                let query = query_value(target, "query").unwrap_or_default();
                let body: &[u8] = if query == "\"'" {
                    b"<html><body>XPathException</body></html>"
                } else {
                    b"<html><body></body></html>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });
    addr
}

fn seed(url: &str) -> HttpMessage {
    HttpMessage {
        method: Method::GET,
        uri: url.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"<html><body></body></html>"),
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_sender_crlf_fixture_raises_plugin_40003() {
    let addr = spawn_crlf().await;
    let dir = temp_dir("crlf");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let sender = Arc::new(DefaultSender::from_current().unwrap());
    let service = ActiveScanService::new(session, sender);
    let url = format!("http://{addr}/shouldFindCrLfInjection.php?years=1");
    let id = service.engine().start(seed(&url), ScanOptions::default());
    assert!(
        service.wait(id, Duration::from_secs(10)),
        "crlf scan did not finish; requests={:?}",
        service.engine().request_count(id)
    );
    let alerts = service.engine().alerts(id).unwrap();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].plugin_id, CRLF_PLUGIN_ID);
    assert_eq!(alerts[0].risk, 2);
    assert_eq!(alerts[0].confidence, 2);
    assert_eq!(alerts[0].cwe_id, 113);
    assert_eq!(alerts[0].wasc_id, 25);
    assert_eq!(alerts[0].param, "years");
    assert!(alerts[0]
        .url
        .contains("years=any%0D%0ASet-cookie%3A+Tamper%3D"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_sender_xpath_fixture_raises_plugin_90021() {
    let addr = spawn_xpath().await;
    let dir = temp_dir("xpath");
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let sender = Arc::new(DefaultSender::from_current().unwrap());
    let service = ActiveScanService::new(session, sender);
    let url = format!(
        "http://{addr}/shouldRaiseAlertIfResponseContainsExpectedErrorForInjectedInput/?query=xxx"
    );
    let id = service.engine().start(seed(&url), ScanOptions::default());
    assert!(
        service.wait(id, Duration::from_secs(10)),
        "xpath scan did not finish; requests={:?}",
        service.engine().request_count(id)
    );
    let alerts = service.engine().alerts(id).unwrap();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0].plugin_id, XPATH_PLUGIN_ID);
    assert_eq!(alerts[0].name, "XPath Injection");
    assert_eq!(alerts[0].risk, 3);
    assert_eq!(alerts[0].confidence, 3);
    assert_eq!(alerts[0].cwe_id, 643);
    assert_eq!(alerts[0].wasc_id, 39);
    assert_eq!(alerts[0].param, "query");
    assert_eq!(alerts[0].evidence, "XPathException");
    assert!(alerts[0].url.contains("query=%22%27"));
    let _ = std::fs::remove_dir_all(dir);
}
