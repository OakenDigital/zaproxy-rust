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
// official OWASP ZAP build. Cookie session management follows
// `CookieBasedSessionManagementMethod`.

//! Cookie jar for one user's authenticated session.
//!
//! `Set-Cookie` from a response is stored. A later request drops any cookie
//! of the same name and then sends the stored cookies that match the host,
//! path, and scheme. That is the message rewrite plus the `HttpState` cookies
//! ZAP attaches when it sends as the user.

use http::{HeaderMap, HeaderValue, Uri};
use zap_core::HttpResponse;

#[derive(Clone, Debug)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
}

/// Cookies belonging to one authenticated user.
#[derive(Clone, Debug, Default)]
pub(crate) struct CookieJar {
    cookies: Vec<StoredCookie>,
}

impl CookieJar {
    pub fn store_response(&mut self, request_url: &str, response: &HttpResponse) {
        let Some((_, host, _)) = request_target(request_url) else {
            return;
        };
        for value in response.headers.get_all(http::header::SET_COOKIE) {
            let Ok(text) = value.to_str() else {
                continue;
            };
            if let Some(cookie) = parse_set_cookie(text, &host) {
                self.upsert(cookie);
            }
        }
    }

    pub fn apply(&self, url: &str, headers: &mut HeaderMap) {
        let Some((secure, host, path)) = request_target(url) else {
            return;
        };
        let matched: Vec<&StoredCookie> = self
            .cookies
            .iter()
            .filter(|cookie| {
                (!cookie.secure || secure)
                    && domain_matches(&cookie.domain, &host)
                    && path_matches(&cookie.path, &path)
            })
            .collect();
        if matched.is_empty() {
            return;
        }
        let mut pairs = parse_cookie_header(headers);
        pairs.retain(|(name, _)| !matched.iter().any(|cookie| cookie.name == *name));
        for cookie in matched {
            pairs.push((cookie.name.clone(), cookie.value.clone()));
        }
        let text = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(value) = HeaderValue::from_str(&text) {
            headers.insert(http::header::COOKIE, value);
        }
    }

    fn upsert(&mut self, cookie: StoredCookie) {
        if let Some(existing) = self.cookies.iter_mut().find(|stored| {
            stored.name == cookie.name
                && stored.domain.eq_ignore_ascii_case(&cookie.domain)
                && stored.path == cookie.path
        }) {
            *existing = cookie;
        } else {
            self.cookies.push(cookie);
        }
    }
}

fn request_target(url: &str) -> Option<(bool, String, String)> {
    let uri: Uri = url.parse().ok()?;
    let secure = uri.scheme_str() == Some("https");
    let host = uri.host()?.to_ascii_lowercase();
    let path = uri.path();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Some((secure, host, path))
}

fn parse_set_cookie(raw: &str, host: &str) -> Option<StoredCookie> {
    let mut parts = raw.split(';');
    let pair = parts.next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut domain = host.to_string();
    let mut path = "/".to_string();
    let mut secure = false;
    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (key, val) = attr
            .split_once('=')
            .map(|(key, value)| (key.trim(), value.trim()))
            .unwrap_or((attr, ""));
        if key.eq_ignore_ascii_case("domain") && !val.is_empty() {
            domain = val.trim_start_matches('.').to_ascii_lowercase();
        } else if key.eq_ignore_ascii_case("path") && !val.is_empty() {
            path = val.to_string();
        } else if key.eq_ignore_ascii_case("secure") {
            secure = true;
        }
    }
    Some(StoredCookie {
        name: name.to_string(),
        value: value.trim().to_string(),
        domain,
        path,
        secure,
    })
}

fn parse_cookie_header(headers: &HeaderMap) -> Vec<(String, String)> {
    let Some(value) = headers.get(http::header::COOKIE) else {
        return Vec::new();
    };
    let Ok(text) = value.to_str() else {
        return Vec::new();
    };
    text.split(';')
        .filter_map(|part| {
            let part = part.trim();
            let (name, value) = part.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                None
            } else {
                Some((name.to_string(), value.trim().to_string()))
            }
        })
        .collect()
}

fn domain_matches(cookie_domain: &str, host: &str) -> bool {
    if cookie_domain.eq_ignore_ascii_case(host) {
        return true;
    }
    host.len() > cookie_domain.len()
        && host.as_bytes().get(host.len() - cookie_domain.len() - 1) == Some(&b'.')
        && host[host.len() - cookie_domain.len()..].eq_ignore_ascii_case(cookie_domain)
}

fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path == "/" {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/')
        || request_path.len() == cookie_path.len()
        || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}
