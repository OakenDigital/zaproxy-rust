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
// This file is a Rust derivative of the link discovery the AJAX spider
// performs inside a browser. It is not an official OWASP ZAP build. Links
// come from HTML attributes and from inline script string literals. The
// script is not executed.

//! HTML links and inline script string literals.

use crate::canon::{self, decode_entities};
use crate::sender::FetchResponse;

/// Bytes above this are not parsed.
const MAX_PARSE_BYTES: usize = 2_621_440;

struct Tag {
    name: String,
    attrs: String,
    /// Inline contents of `<script>` and `<style>`. Empty for other tags.
    body: String,
}

/// Absolute URLs referenced by one response.
pub fn links(page_url: &str, response: &FetchResponse) -> Vec<String> {
    let mut found = Vec::new();
    if is_redirect(response.status) {
        if let Some(location) = header(response, "location") {
            push(&mut found, page_url, location);
        }
    }
    if response.body.len() > MAX_PARSE_BYTES || !is_html(response) {
        return found;
    }
    let text = String::from_utf8_lossy(&response.body);
    let tags = scan_tags(&text);
    let base = document_base(page_url, &tags);
    for tag in &tags {
        collect_attributes(&base, tag, &mut found);
        if tag.name == "script" {
            collect_script(&base, tag, &mut found);
        }
    }
    found
}

fn collect_attributes(base: &str, tag: &Tag, found: &mut Vec<String>) {
    if tag.name == "meta" {
        let equiv = attr(&tag.attrs, "http-equiv").unwrap_or_default();
        if equiv.eq_ignore_ascii_case("refresh") {
            if let Some(content) = attr(&tag.attrs, "content") {
                if let Some(target) = refresh_target(&content) {
                    push(found, base, &target);
                }
            }
        }
        return;
    }
    for name in link_attributes(&tag.name) {
        let Some(value) = attr(&tag.attrs, name) else {
            continue;
        };
        if *name == "srcset" {
            for piece in srcset_urls(&value) {
                push(found, base, &piece);
            }
        } else if !value.is_empty() {
            push(found, base, &value);
        }
    }
}

fn collect_script(base: &str, tag: &Tag, found: &mut Vec<String>) {
    if attr(&tag.attrs, "src").is_some_and(|src| !src.is_empty()) {
        return;
    }
    if !is_javascript(&tag.attrs) {
        return;
    }
    for literal in string_literals(&tag.body) {
        push(found, base, &literal);
    }
}

fn push(found: &mut Vec<String>, base: &str, raw: &str) {
    if let Some(url) = canon::resolve(base, raw) {
        found.push(url);
    }
}

fn document_base(page_url: &str, tags: &[Tag]) -> String {
    for tag in tags {
        if tag.name != "base" {
            continue;
        }
        if let Some(href) = attr(&tag.attrs, "href") {
            if let Some(resolved) = canon::resolve(page_url, &href) {
                return resolved;
            }
        }
    }
    page_url.to_string()
}

fn link_attributes(name: &str) -> &'static [&'static str] {
    match name {
        "a" | "area" | "link" | "base" => &["href"],
        "img" | "source" => &["src", "srcset"],
        "script" | "iframe" | "frame" | "embed" | "audio" | "track" | "input" => &["src"],
        "video" => &["src", "poster", "srcset"],
        "form" => &["action"],
        "button" => &["formaction"],
        "object" => &["data"],
        _ => &[],
    }
}

fn is_javascript(attrs: &str) -> bool {
    match attr(attrs, "type") {
        None => true,
        Some(kind) => {
            let kind = kind.trim().to_ascii_lowercase();
            kind.is_empty()
                || kind == "module"
                || kind == "text/javascript"
                || kind == "application/javascript"
                || kind == "application/ecmascript"
                || kind == "text/ecmascript"
                || kind == "text/jscript"
        }
    }
}

fn refresh_target(content: &str) -> Option<String> {
    let lower = content.to_ascii_lowercase();
    let index = lower.find("url=")?;
    let value = content[index + 4..]
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn srcset_urls(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|part| {
            let url = part.split_whitespace().next().unwrap_or("");
            if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            }
        })
        .collect()
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn is_html(response: &FetchResponse) -> bool {
    match header(response, "content-type") {
        Some(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("html") || value.contains("xhtml")
        }
        None => {
            let text = String::from_utf8_lossy(&response.body);
            text.trim_start().starts_with('<')
        }
    }
}

fn header<'a>(response: &'a FetchResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn scan_tags(html: &str) -> Vec<Tag> {
    let mut tags = Vec::new();
    let mut index = 0;
    while index < html.len() {
        let Some(start) = html[index..].find('<') else {
            break;
        };
        let at = index + start;
        if html[at..].starts_with("<!--") {
            index = match html[at + 4..].find("-->") {
                Some(end) => at + 4 + end + 3,
                None => html.len(),
            };
            continue;
        }
        if html[at..].starts_with("</") || html[at..].starts_with("<!") {
            index = end_of_tag(html, at);
            continue;
        }
        let Some((name, attrs, after)) = open_tag(html, at) else {
            index = at + 1;
            continue;
        };
        let (body, next) = element_body(html, &name, &attrs, after);
        tags.push(Tag { name, attrs, body });
        index = next;
    }
    tags
}

fn open_tag(html: &str, at: usize) -> Option<(String, String, usize)> {
    let bytes = html.as_bytes();
    let mut name_end = at + 1;
    if name_end >= bytes.len() || !bytes[name_end].is_ascii_alphabetic() {
        return None;
    }
    while name_end < bytes.len()
        && (bytes[name_end].is_ascii_alphanumeric()
            || bytes[name_end] == b'-'
            || bytes[name_end] == b':')
    {
        name_end += 1;
    }
    let name = html[at + 1..name_end].to_ascii_lowercase();
    let close = quoted_gt(html, name_end)?;
    let attrs = html[name_end..close].to_string();
    Some((name, attrs, close + 1))
}

fn quoted_gt(html: &str, from: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut quote = None;
    let mut index = from;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if let Some(expected) = quote {
            if ch == expected {
                quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '>' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn element_body(html: &str, name: &str, attrs: &str, after: usize) -> (String, usize) {
    if name != "script" && name != "style" {
        return (String::new(), after);
    }
    if attrs.trim_end().ends_with('/') {
        return (String::new(), after);
    }
    let rest = &html[after..];
    let lower = rest.to_ascii_lowercase();
    let needle = format!("</{name}");
    let Some(found) = lower.find(&needle) else {
        return (rest.to_string(), html.len());
    };
    let close_at = after + found;
    let next = end_of_tag(html, close_at);
    (html[after..close_at].to_string(), next)
}

fn end_of_tag(html: &str, at: usize) -> usize {
    match html[at..].find('>') {
        Some(end) => at + end + 1,
        None => html.len(),
    }
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let lower_attrs = attrs.to_ascii_lowercase();
    let needle = name.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(index) = lower_attrs[offset..].find(&needle) {
        let at = offset + index;
        let before_ok = at == 0 || lower_attrs.as_bytes()[at - 1].is_ascii_whitespace();
        let after = at + needle.len();
        let after_ok =
            after >= lower_attrs.len() || !lower_attrs.as_bytes()[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            let tail = attrs[after..].trim_start();
            if let Some(value) = tail.strip_prefix('=') {
                return Some(decode_entities(&read_value(value.trim_start())));
            }
        }
        offset = at + needle.len();
    }
    None
}

fn read_value(input: &str) -> String {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    if first == '"' || first == '\'' {
        let mut out = String::new();
        for ch in chars {
            if ch == first {
                break;
            }
            out.push(ch);
        }
        out
    } else {
        let mut out = String::from(first);
        for ch in chars {
            if ch.is_whitespace() || ch == '>' {
                break;
            }
            out.push(ch);
        }
        out
    }
}

/// A quoted JS value is a link when it is absolute, root-relative, or dot-relative.
fn is_script_link(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("javascript:")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
    {
        return false;
    }
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

fn string_literals(source: &str) -> Vec<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if is_line_comment(&chars, index) {
            index = skip_line(&chars, index + 2);
            continue;
        }
        if is_block_comment(&chars, index) {
            index = skip_block(&chars, index + 2);
            continue;
        }
        let quote = chars[index];
        if quote == '"' || quote == '\'' || quote == '`' {
            index += 1;
            let (literal, next, keep) = read_literal(&chars, index, quote);
            if keep && is_script_link(&literal) {
                out.push(literal);
            }
            index = next;
            continue;
        }
        index += 1;
    }
    out
}

fn is_line_comment(chars: &[char], index: usize) -> bool {
    chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'/')
}

fn is_block_comment(chars: &[char], index: usize) -> bool {
    chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'*')
}

fn skip_line(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && chars[index] != '\n' {
        index += 1;
    }
    index
}

fn skip_block(chars: &[char], mut index: usize) -> usize {
    while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
        index += 1;
    }
    (index + 2).min(chars.len())
}

fn read_literal(chars: &[char], mut index: usize, quote: char) -> (String, usize, bool) {
    let mut literal = String::new();
    let mut interpolated = false;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' && index + 1 < chars.len() {
            index += 1;
            push_escape(chars, &mut index, &mut literal);
            continue;
        }
        if quote == '`' && ch == '$' && chars.get(index + 1) == Some(&'{') {
            interpolated = true;
        }
        if ch == quote {
            return (literal, index + 1, !interpolated);
        }
        if ch == '\n' && quote != '`' {
            return (String::new(), index, false);
        }
        literal.push(ch);
        index += 1;
    }
    (String::new(), chars.len(), false)
}

fn push_escape(chars: &[char], index: &mut usize, literal: &mut String) {
    if *index >= chars.len() {
        return;
    }
    match chars[*index] {
        'n' => literal.push('\n'),
        'r' => literal.push('\r'),
        't' => literal.push('\t'),
        'u' => match hex_char(chars, *index + 1, 4) {
            Some(code) => {
                literal.push(code);
                *index += 4;
            }
            None => literal.push('u'),
        },
        'x' => match hex_char(chars, *index + 1, 2) {
            Some(code) => {
                literal.push(code);
                *index += 2;
            }
            None => literal.push('x'),
        },
        other => literal.push(other),
    }
    *index += 1;
}

fn hex_char(chars: &[char], start: usize, len: usize) -> Option<char> {
    if start + len > chars.len() {
        return None;
    }
    let hex: String = chars[start..start + len].iter().collect();
    let code = u32::from_str_radix(&hex, 16).ok()?;
    char::from_u32(code)
}
