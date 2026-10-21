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

//! Form login and JSON login each produce an authenticated follow-up request.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zap_auth::User;
use zap_core::HttpMessage;
use zap_http::UpstreamClient;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    content_type: String,
    cookie: String,
    body: String,
}

fn request_path(target: &str) -> String {
    let path = if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        }
    } else {
        target
    };
    path.split('?').next().unwrap_or("/").to_string()
}

async fn read_request(socket: &mut TcpStream) -> Seen {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        socket.read_exact(&mut byte).await.expect("request header");
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8(header).unwrap();
    let line = header.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/");
    let path = request_path(target);
    let mut content_type = String::new();
    let mut cookie = String::new();
    let mut length = 0_usize;
    for line in header.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-type:") {
            content_type = value.trim().to_string();
        } else if let Some(value) = lower.strip_prefix("cookie:") {
            cookie = value.trim().to_string();
        } else if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0_u8; length];
    if length > 0 {
        socket.read_exact(&mut body).await.expect("request body");
    }
    Seen {
        method,
        path,
        content_type,
        cookie,
        body: String::from_utf8(body).unwrap_or_default(),
    }
}

fn response(status: u16, body: &str, set_cookie: &str) -> Vec<u8> {
    let cookie = if set_cookie.is_empty() {
        String::new()
    } else {
        format!("Set-Cookie: {set_cookie}\r\n")
    };
    format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{cookie}Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn spawn_app(
    session_cookie: &'static str,
    expected_body: &'static str,
) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let request = read_request(&mut socket).await;
            let bytes = if request.method == "GET" && request.path == "/login" {
                response(200, "login-page", "")
            } else if request.method == "POST"
                && request.path == "/login"
                && request.body == expected_body
            {
                response(200, "logged-in", session_cookie)
            } else if request.method == "GET"
                && request.path == "/private"
                && request.cookie.contains(session_cookie)
            {
                response(200, "secret", "")
            } else {
                response(401, "anonymous", "")
            };
            log.lock().unwrap().push(request);
            let _ = socket.write_all(&bytes).await;
        }
    });
    (addr, seen)
}

fn follow_up(url: &str) -> HttpMessage {
    HttpMessage {
        method: Method::GET,
        uri: url.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    }
}

#[tokio::test]
async fn form_login_yields_an_authenticated_follow_up() {
    let expected = "username=alice&password=s3cret-form";
    let (addr, seen) = spawn_app("session=form-ok", expected).await;
    let login_url = format!("http://{addr}/login");
    let user = User::form(
        "Ada",
        "alice",
        "s3cret-form",
        &login_url,
        "username={%username%}&password={%password%}",
        None,
    )
    .unwrap();
    let client = UpstreamClient::new(&[]).unwrap();
    let mut session = user;
    let private_url = format!("http://{addr}/private");
    let mut message = follow_up(&private_url);
    let response = client
        .send_as_user(&mut message, &mut session)
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"secret");

    let mut again = follow_up(&private_url);
    let second = client.send_as_user(&mut again, &mut session).await.unwrap();
    assert_eq!(second.body.as_ref(), b"secret");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|item| item.method == "POST").count(), 1);
    assert_eq!(
        seen.iter()
            .filter(|item| item.method == "GET" && item.path == "/login")
            .count(),
        1
    );
    let post = seen.iter().find(|item| item.method == "POST").unwrap();
    assert_eq!(post.body, expected);
    assert!(post
        .content_type
        .starts_with("application/x-www-form-urlencoded"));
    let private_hits: Vec<_> = seen.iter().filter(|item| item.path == "/private").collect();
    assert_eq!(private_hits.len(), 2);
    assert!(private_hits
        .iter()
        .all(|item| item.cookie.contains("session=form-ok")));
}

#[tokio::test]
async fn json_login_yields_an_authenticated_follow_up() {
    let expected = r#"{"username":"bob","password":"s3cret-json"}"#;
    let (addr, seen) = spawn_app("session=json-ok", expected).await;
    let login_url = format!("http://{addr}/login");
    let user = User::json(
        "Bob",
        "bob",
        "s3cret-json",
        &login_url,
        r#"{"username":"{%username%}","password":"{%password%}"}"#,
        Some(&login_url),
    )
    .unwrap();
    let client = UpstreamClient::new(&[]).unwrap();
    let mut session = user;
    let mut message = follow_up(&format!("http://{addr}/private"));
    let response = client
        .send_as_user(&mut message, &mut session)
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"secret");

    let seen = seen.lock().unwrap();
    let post = seen.iter().find(|item| item.method == "POST").unwrap();
    assert_eq!(post.body, expected);
    assert!(post.content_type.starts_with("application/json"));
    assert!(seen
        .iter()
        .any(|item| item.path == "/private" && item.cookie.contains("session=json-ok")));
}
