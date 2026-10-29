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
// official OWASP ZAP build. The header check follows `HttpMessage.isWebSocketUpgrade`.

//! HTTP/1.1 WebSocket opening handshake (RFC 6455).
//!
//! The framed connection is not parsed here. [`UpstreamClient::open_websocket`]
//! returns the origin socket when the origin answers `101`, and the proxy
//! copies those bytes both ways.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, Method, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::upgrade::Upgraded;

use super::{append_via, UpstreamClient, UpstreamError};
use zap_core::{headers_for_forwarding, HttpMessage, HttpResponse};

/// Origin response plus the switched socket when the status is 101.
#[derive(Debug)]
pub struct WebSocketHandshake {
    pub response: HttpResponse,
    /// Set when the origin switched protocols. The caller copies this
    /// socket and the client upgrade in both directions.
    pub origin: Option<Upgraded>,
}

/// Client opening handshake: HTTP/1.1 `GET` with `Upgrade: websocket`,
/// a `Connection` token of `upgrade`, `Sec-WebSocket-Version: 13`, and a
/// 16-byte `Sec-WebSocket-Key`.
pub fn is_websocket_handshake(method: &Method, version: Version, headers: &HeaderMap) -> bool {
    version == Version::HTTP_11
        && method == Method::GET
        && upgrade_is_websocket(headers)
        && connection_has_token(headers, "upgrade")
        && websocket_version_is_13(headers)
        && websocket_key_is_nonce(headers)
}

/// `101` whose `Upgrade` is `websocket` and whose `Connection` lists `upgrade`.
pub fn is_websocket_accept(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::SWITCHING_PROTOCOLS
        && upgrade_is_websocket(headers)
        && connection_has_token(headers, "upgrade")
}

impl UpstreamClient {
    /// Forward `msg` as a WebSocket opening handshake.
    ///
    /// `Upgrade` and `Connection` are kept. Other hop-by-hop headers are
    /// removed, and the `Via` header is still appended. When the origin
    /// returns 101, [`WebSocketHandshake::origin`] is the raw connection;
    /// the response body is empty because any further bytes are frames on
    /// that socket.
    pub async fn open_websocket(
        &self,
        msg: &mut HttpMessage,
    ) -> Result<WebSocketHandshake, UpstreamError> {
        append_via(&mut msg.headers);
        let headers = headers_for_websocket_request(&msg.headers);
        let mut builder = Request::builder()
            .method(msg.method.clone())
            .uri(msg.uri.clone());
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(msg.body.clone()))
            .map_err(|err| UpstreamError::new(format!("request build: {err}")))?;

        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| UpstreamError::new("upstream timed out"))?
            .map_err(|err| UpstreamError::new(format!("upstream: {err}")))?;

        let status = response.status();
        let response_headers = response.headers().clone();
        if status == StatusCode::SWITCHING_PROTOCOLS {
            let origin = hyper::upgrade::on(response)
                .await
                .map_err(|err| UpstreamError::new(format!("websocket upgrade: {err}")))?;
            return Ok(WebSocketHandshake {
                response: HttpResponse {
                    status,
                    headers: response_headers,
                    body: Bytes::new(),
                },
                origin: Some(origin),
            });
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|err| UpstreamError::new(format!("upstream body: {err}")))?
            .to_bytes();
        Ok(WebSocketHandshake {
            response: HttpResponse {
                status,
                headers: response_headers,
                body,
            },
            origin: None,
        })
    }
}

/// Headers forwarded on the opening handshake.
///
/// [`headers_for_forwarding`] drops `Upgrade` and `Connection`. Those two
/// are copied back from `src` so the origin still sees the handshake.
fn headers_for_websocket_request(src: &HeaderMap) -> HeaderMap {
    let mut headers = headers_for_forwarding(src);
    headers.remove(http::header::HOST);
    copy_header(&mut headers, src, http::header::CONNECTION);
    copy_header(&mut headers, src, http::header::UPGRADE);
    headers
}

fn copy_header(dst: &mut HeaderMap, src: &HeaderMap, name: HeaderName) {
    dst.remove(&name);
    for value in src.get_all(&name) {
        dst.append(name.clone(), value.clone());
    }
}

fn upgrade_is_websocket(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
}

fn connection_has_token(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|text| {
                text.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
        })
}

fn websocket_version_is_13(headers: &HeaderMap) -> bool {
    headers
        .get("sec-websocket-version")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "13")
}

fn websocket_key_is_nonce(headers: &HeaderMap) -> bool {
    headers
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| decode_base64(value.trim()))
        .is_some_and(|bytes| bytes.len() == 16)
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn val(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let (a, b, c, d) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        if a == b'=' || b == b'=' || (c == b'=' && d != b'=') {
            return None;
        }
        let pad = usize::from(c == b'=') + usize::from(d == b'=');
        let av = val(a)?;
        let bv = val(b)?;
        let cv = if c == b'=' { 0 } else { val(c)? };
        let dv = if d == b'=' { 0 } else { val(d)? };
        out.push((av << 2) | (bv >> 4));
        if pad < 2 {
            out.push((bv << 4) | (cv >> 2));
        }
        if pad < 1 {
            out.push((cv << 6) | dv);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};

    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn handshake_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.insert(
            HeaderName::from_static("sec-websocket-key"),
            HeaderValue::from_static(RFC_KEY),
        );
        headers.insert(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        headers.insert(http::header::HOST, HeaderValue::from_static("example.test"));
        headers
    }

    #[test]
    fn rfc_get_with_upgrade_token_is_a_handshake() {
        let headers = handshake_headers();
        assert!(is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &headers
        ));
        assert!(is_websocket_accept(
            StatusCode::SWITCHING_PROTOCOLS,
            &headers
        ));
    }

    #[test]
    fn upgrade_check_is_case_insensitive_and_rejects_incomplete_handshakes() {
        let mut headers = handshake_headers();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("WebSocket"));
        assert!(is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &headers
        ));

        assert!(!is_websocket_handshake(
            &Method::POST,
            Version::HTTP_11,
            &headers
        ));
        assert!(!is_websocket_handshake(
            &Method::GET,
            Version::HTTP_10,
            &headers
        ));

        headers.insert(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("8"),
        );
        assert!(!is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &headers
        ));

        let mut missing_key = handshake_headers();
        missing_key.remove("sec-websocket-key");
        assert!(!is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &missing_key
        ));

        let mut short_key = handshake_headers();
        short_key.insert(
            HeaderName::from_static("sec-websocket-key"),
            HeaderValue::from_static("YQ=="),
        );
        assert!(!is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &short_key
        ));

        let mut no_upgrade_token = handshake_headers();
        no_upgrade_token.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        assert!(!is_websocket_handshake(
            &Method::GET,
            Version::HTTP_11,
            &no_upgrade_token
        ));
    }

    #[test]
    fn accept_requires_101_upgrade_and_connection() {
        let headers = handshake_headers();
        assert!(!is_websocket_accept(StatusCode::OK, &headers));
        let mut kept = headers.clone();
        kept.remove(http::header::UPGRADE);
        assert!(!is_websocket_accept(StatusCode::SWITCHING_PROTOCOLS, &kept));
    }

    #[test]
    fn request_headers_keep_upgrade_and_drop_host() {
        let src = handshake_headers();
        let forwarded = headers_for_websocket_request(&src);
        assert_eq!(
            forwarded.get(http::header::UPGRADE).unwrap(),
            HeaderValue::from_static("websocket")
        );
        assert_eq!(
            forwarded
                .get(http::header::CONNECTION)
                .unwrap()
                .to_str()
                .unwrap(),
            "keep-alive, Upgrade"
        );
        assert_eq!(
            forwarded
                .get("sec-websocket-key")
                .unwrap()
                .to_str()
                .unwrap(),
            RFC_KEY
        );
        assert!(forwarded.get(http::header::HOST).is_none());
    }

    #[test]
    fn rfc_sample_key_decodes_to_sixteen_bytes() {
        let bytes = decode_base64(RFC_KEY).unwrap();
        assert_eq!(bytes, b"the sample nonce");
    }
}
