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

//! Hop-by-hop headers stripped when a buffered message is forwarded.

use http::HeaderMap;

/// Header names removed on forward, plus any name listed in `Connection`.
///
/// `content-length` is also dropped by [`headers_for_forwarding`] because the
/// body is buffered and the length is written from the buffer. It is not
/// hop-by-hop; it is rebuilt framing.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Whether `name` is hop-by-hop. Comparison is ASCII case-insensitive.
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|hop| hop.eq_ignore_ascii_case(name))
}

/// Copy headers that should be forwarded with a buffered body.
///
/// Drops hop-by-hop headers, names listed in `Connection`, and `content-length`.
pub fn headers_for_forwarding(src: &HeaderMap) -> HeaderMap {
    let mut listed = Vec::new();
    if let Some(connection) = src.get(http::header::CONNECTION) {
        if let Ok(value) = connection.to_str() {
            for token in value.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    listed.push(token.to_ascii_lowercase());
                }
            }
        }
    }

    let mut out = HeaderMap::new();
    for (name, value) in src.iter() {
        if is_hop_by_hop(name.as_str()) || listed.iter().any(|extra| extra == name.as_str()) {
            continue;
        }
        if name == http::header::CONTENT_LENGTH {
            continue;
        }
        out.append(name, value.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};

    #[test]
    fn forwarding_strips_hop_by_hop_connection_tokens_and_length() {
        let mut src = HeaderMap::new();
        src.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("close, x-drop-me"),
        );
        src.insert(
            HeaderName::from_static("x-drop-me"),
            HeaderValue::from_static("1"),
        );
        src.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        src.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        src.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        src.insert(
            HeaderName::from_static("x-keep"),
            HeaderValue::from_static("yes"),
        );

        let forwarded = headers_for_forwarding(&src);
        assert!(forwarded.get("connection").is_none());
        assert!(forwarded.get("x-drop-me").is_none());
        assert!(forwarded.get("transfer-encoding").is_none());
        assert!(forwarded.get("content-length").is_none());
        assert_eq!(
            forwarded.get("content-type").unwrap(),
            HeaderValue::from_static("text/plain")
        );
        assert_eq!(
            forwarded.get("x-keep").unwrap(),
            HeaderValue::from_static("yes")
        );
    }
}
