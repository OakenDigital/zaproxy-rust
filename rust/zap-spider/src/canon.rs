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
// This file is a Rust derivative of UrlCanonicalizer and UrlResolver in
// spider 0.18.0. It is not an official OWASP ZAP build.

//! Absolute HTTP(S) URLs with the fragment removed and the query sorted.

use std::collections::BTreeSet;

use url::Url;

/// Resolve `raw` against `base` the way the spider records a URL.
pub fn canonicalize(base: &str, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "//" {
        return None;
    }
    let scheme_check = raw.to_ascii_lowercase();
    if scheme_check.starts_with("javascript:")
        || scheme_check.starts_with("mailto:")
        || scheme_check.starts_with("tel:")
    {
        return None;
    }
    let base = Url::parse(base).ok()?;
    let joined = base.join(raw).ok()?;
    if joined.scheme() != "http" && joined.scheme() != "https" {
        return None;
    }
    let host = joined.host_str()?.to_ascii_lowercase();
    let mut path = raw_path(&joined);
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    while path.starts_with("/../") {
        path = path[3..].to_string();
    }
    if path.is_empty() {
        path = "/".to_string();
    }
    path = path.replace("%7E", "~").replace(' ', "%20");
    let query = sorted_query(raw_query(&joined));
    let mut url = format!("{}://{host}", joined.scheme());
    if let Some(port) = joined.port() {
        url.push(':');
        url.push_str(&port.to_string());
    }
    url.push_str(&path);
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query);
    }
    Some(url)
}

pub fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

pub fn path_of(url: &str) -> String {
    Url::parse(url)
        .ok()
        .map(|url| raw_path(&url))
        .unwrap_or_else(|| "/".to_string())
}

pub fn root_file(seed: &str, file_name: &str) -> Option<String> {
    let url = Url::parse(seed).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    let mut root = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        root.push(':');
        root.push_str(&port.to_string());
    }
    root.push('/');
    root.push_str(file_name);
    Some(root)
}

/// Java `URLEncoder.encode` for form bodies and GET form queries.
pub fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn raw_path(url: &Url) -> String {
    let text = url.as_str();
    let rest = text.split_once("://").map(|(_, rest)| rest).unwrap_or(text);
    let path = rest.find('/').map(|index| &rest[index..]).unwrap_or("/");
    let path = path.split(['?', '#']).next().unwrap_or("/");
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn raw_query(url: &Url) -> Option<String> {
    let text = url.as_str();
    let after = text.split_once('?')?.1;
    let query = after.split('#').next().unwrap_or(after);
    if query.is_empty() {
        None
    } else {
        Some(query.to_string())
    }
}

fn sorted_query(query: Option<String>) -> String {
    let Some(query) = query else {
        return String::new();
    };
    let mut params = BTreeSet::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut tokens = pair.splitn(2, '=');
        let first = tokens.next().unwrap_or("");
        match tokens.next() {
            None if pair.starts_with('=') => {
                params.insert(("".to_string(), first.to_string()));
            }
            None => {
                params.insert((first.to_string(), String::new()));
            }
            Some(value) => {
                params.insert((first.to_string(), value.to_string()));
            }
        }
    }
    let mut out = String::new();
    for (name, value) in params {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&name);
        if !value.is_empty() {
            out.push('=');
            out.push_str(&value);
        }
    }
    out
}
