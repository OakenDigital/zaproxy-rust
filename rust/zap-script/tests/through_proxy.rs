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

//! The sample script rewrites headers on a real proxied exchange.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zap_proxy::{Proxy, ProxyConfig, RunningProxy};
use zap_script::{ScriptHost, ScriptProxyListener, ScriptType, SAMPLE_REWRITE_SCRIPT};

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0_u8; 4096];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let script = header_value(&request, "x-script-request");
        let sender = header_value(&request, "x-sender-request");
        let body = format!("script={script}\nsender={sender}");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(header.as_bytes()).await;
        let _ = socket.write_all(body.as_bytes()).await;
    });
    addr
}

fn header_value(request: &str, name: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case(name) {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "missing".to_string())
}

async fn http_exchange(addr: SocketAddr, request: &str) -> (u16, String, Vec<u8>) {
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
    (status, header, body)
}

async fn start_proxy(host: Arc<ScriptHost>) -> RunningProxy {
    Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir: std::env::temp_dir().join(format!("zap-script-ca-{}", std::process::id())),
        exclude: Vec::new(),
        listeners: vec![Arc::new(ScriptProxyListener::new(host))],
        extra_root_pems: Vec::new(),
        history: None,
        early_override: None,
    })
    .await
    .expect("proxy")
}

#[tokio::test]
async fn sample_script_rewrites_headers_on_the_way_out_and_back() {
    let host = Arc::new(ScriptHost::new());
    host.add_script("rewrite-proxy", ScriptType::Proxy, SAMPLE_REWRITE_SCRIPT)
        .unwrap();
    host.add_script(
        "rewrite-sender",
        ScriptType::HttpSender,
        SAMPLE_REWRITE_SCRIPT,
    )
    .unwrap();
    let origin = spawn_origin().await;
    let proxy = start_proxy(host).await;
    let url = format!("http://127.0.0.1:{}/fixture", origin.port());
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    let (status, header, body) = http_exchange(proxy.local_addr(), &request).await;
    assert_eq!(status, 200);
    let body = String::from_utf8(body).unwrap();
    assert_eq!(body, "script=rewritten\nsender=rewritten");
    assert_eq!(header_value(&header, "x-script-response"), "rewritten");
    assert_eq!(header_value(&header, "x-sender-response"), "rewritten");
    proxy.shutdown().await;
}
