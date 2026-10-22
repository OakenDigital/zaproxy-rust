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
// This file is not an official OWASP ZAP build.

//! Response helpers shared by the passive rules.

use http::HeaderMap;
use zap_core::HttpMessage;
use zap_store::NewAlert;

pub fn response_headers(msg: &HttpMessage) -> Option<&HeaderMap> {
    msg.response.as_ref().map(|response| &response.headers)
}

pub fn body(msg: &HttpMessage) -> &[u8] {
    msg.response
        .as_ref()
        .map(|response| response.body.as_ref())
        .unwrap_or(b"")
}

pub fn status(msg: &HttpMessage) -> Option<u16> {
    msg.response
        .as_ref()
        .map(|response| response.status.as_u16())
}

pub fn header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect()
}

pub fn first_content_type(headers: &HeaderMap) -> Option<String> {
    header_values(headers, "content-type")
        .into_iter()
        .next()
        .map(|value| value.to_ascii_lowercase())
}

/// `HttpResponseHeader.isHtml`: the first content type contains `html`.
pub fn is_html(headers: &HeaderMap) -> bool {
    first_content_type(headers).is_some_and(|value| value.contains("html"))
}

/// `HttpResponseHeader.isText`. A missing content type is not text.
pub fn is_text(headers: &HeaderMap) -> bool {
    let Some(value) = first_content_type(headers) else {
        return false;
    };
    ["text", "html", "javascript", "json", "xml"]
        .iter()
        .any(|token| value.contains(token))
}

pub fn is_error_or_redirect(status: u16) -> bool {
    (300..400).contains(&status) || (400..500).contains(&status) || status >= 500
}

pub fn is_https(msg: &HttpMessage) -> bool {
    msg.uri.scheme_str() == Some("https")
}

#[allow(clippy::too_many_arguments)]
pub fn alert(
    plugin_id: i32,
    name: &str,
    risk: i32,
    confidence: i32,
    cwe: i32,
    wasc: i32,
    param: &str,
    url: &str,
) -> NewAlert {
    NewAlert {
        plugin_id,
        name: name.to_string(),
        risk,
        confidence,
        cwe_id: cwe,
        wasc_id: wasc,
        param: param.to_string(),
        url: url.to_string(),
    }
}
