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
// This file is a Rust derivative of URL resolution used by the ZAP spiders.
// It is not an official OWASP ZAP build. Fragments are removed because a
// browser runtime is not included and hash routes are not clicked.

//! Absolute HTTP(S) URLs with the fragment removed.

use url::Url;

/// Resolve `raw` against `base`. Non-HTTP schemes are dropped.
pub fn resolve(base: &str, raw: &str) -> Option<String> {
    let decoded = decode_entities(raw);
    let raw = decoded.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    let scheme = raw.to_ascii_lowercase();
    if scheme.starts_with("javascript:")
        || scheme.starts_with("mailto:")
        || scheme.starts_with("tel:")
        || scheme.starts_with("data:")
    {
        return None;
    }
    let base = Url::parse(base).ok()?;
    let mut joined = base.join(raw).ok()?;
    if joined.scheme() != "http" && joined.scheme() != "https" {
        return None;
    }
    joined.set_fragment(None);
    Some(joined.to_string())
}

pub fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

pub fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}
