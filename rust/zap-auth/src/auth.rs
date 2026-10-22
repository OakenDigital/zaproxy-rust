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
// official OWASP ZAP build. Token replacement follows
// `PostBasedAuthenticationMethodType` (pscan is unrelated; this is form and
// JSON authentication).

//! Form and JSON login messages.
//!
//! `{%username%}` and `{%password%}` are replaced in the URL with Java
//! `URLEncoder` rules, and in the body with the method encoder: form
//! URL-encoding, or JSON string escaping.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use zap_core::HttpMessage;

use crate::Error;

/// `{%username%}` in a login URL or body.
pub const USERNAME_TOKEN: &str = "{%username%}";

/// `{%password%}` in a login URL or body.
pub const PASSWORD_TOKEN: &str = "{%password%}";

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// Which post-based authentication method builds the login body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginKind {
    /// Type 2. Body encoder is `application/x-www-form-urlencoded`.
    Form,
    /// Type 5. Body encoder is JSON string escaping.
    Json,
}

/// Login URL, login page URL, and body template for one user.
#[derive(Clone, Debug)]
pub(crate) struct LoginSpec {
    pub kind: LoginKind,
    pub login_url: String,
    pub login_page_url: String,
    pub body_template: String,
}

impl LoginSpec {
    pub fn parse(
        kind: LoginKind,
        login_url: &str,
        login_body: &str,
        login_page_url: Option<&str>,
    ) -> Result<Self, Error> {
        validate_login_template(login_url)?;
        let page = login_page_url.unwrap_or(login_url);
        parse_absolute(page)?;
        Ok(Self {
            kind,
            login_url: login_url.to_string(),
            login_page_url: page.to_string(),
            body_template: login_body.to_string(),
        })
    }

    pub fn page_request(&self) -> HttpMessage {
        get_message(&self.login_page_url)
    }

    pub fn login_request(&self, username: &str, password: &str) -> HttpMessage {
        let url = replace_tokens(&self.login_url, username, password, form_encode);
        let body = if self.body_template.is_empty() {
            String::new()
        } else {
            let encode = match self.kind {
                LoginKind::Form => form_encode,
                LoginKind::Json => json_escape,
            };
            replace_tokens(&self.body_template, username, password, encode)
        };
        if body.is_empty() {
            return get_message(&url);
        }
        let mut headers = HeaderMap::new();
        let content_type = match self.kind {
            LoginKind::Form => FORM_CONTENT_TYPE,
            LoginKind::Json => JSON_CONTENT_TYPE,
        };
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        );
        HttpMessage {
            method: Method::POST,
            uri: url.parse().expect("login url was validated"),
            headers,
            body: Bytes::from(body),
            response: None,
        }
    }
}

fn get_message(url: &str) -> HttpMessage {
    HttpMessage {
        method: Method::GET,
        uri: url.parse().expect("login url was validated"),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    }
}

fn validate_login_template(url: &str) -> Result<(), Error> {
    let probe = url
        .replace(USERNAME_TOKEN, "user")
        .replace(PASSWORD_TOKEN, "pass");
    parse_absolute(&probe)
}

fn parse_absolute(url: &str) -> Result<(), Error> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| Error::Config(format!("login url is not an absolute URI: {url}")))?;
    if uri.scheme().is_none() || uri.host().is_none() {
        return Err(Error::Config(format!(
            "login url is not an absolute URI: {url}"
        )));
    }
    Ok(())
}

fn replace_tokens(
    data: &str,
    username: &str,
    password: &str,
    encode: fn(&str) -> String,
) -> String {
    data.replace(USERNAME_TOKEN, &encode(username))
        .replace(PASSWORD_TOKEN, &encode(password))
}

/// Java `URLEncoder.encode` with UTF-8: space is `+`, unreserved includes `*`.
pub(crate) fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Apache Commons Text `StringEscapeUtils.escapeJson` for the characters a
/// credential can introduce into a JSON string.
pub(crate) fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
