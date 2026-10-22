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
// This file is a Rust derivative of the spider 0.18.0 parsers (HTML, HTML
// forms, robots.txt, sitemap.xml, redirect, and response headers). It is
// not an official OWASP ZAP build. The Java add-on is not included.

//! Parsers that turn one response into the next request URLs.

use regex::Regex;

use crate::canon::{canonicalize, form_encode, path_of};
use crate::options::SpiderOptions;
use crate::sender::FetchResponse;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub url: String,
    pub method: String,
    pub body: String,
}

/// Bytes above this are not parsed, except `/robots.txt` and `/sitemap.xml`.
const MAX_PARSE_SIZE: usize = 2_621_440;

pub fn parse(url: &str, response: &FetchResponse, options: &SpiderOptions) -> Vec<Found> {
    let mut found = Vec::new();
    let path = path_of(url);
    if !parse_allowed(&path, response) {
        return found;
    }
    let mut consumed = false;
    if options.parse_robots_txt && is_robots(&path) {
        found.extend(robots(url, response));
        consumed = true;
    }
    if options.parse_sitemap_xml
        && is_sitemap(&path)
        && is_xml(response)
        && !is_error(response.status)
    {
        let urls = sitemap(url, response);
        if !urls.is_empty() {
            found.extend(urls);
            consumed = true;
        }
    }
    if is_redirect(response.status) {
        if let Some(location) = header(response, "location") {
            if !location.is_empty() {
                push_get(&mut found, url, &location);
            }
        }
        consumed = true;
    }
    headers(url, response, &mut found);
    if !consumed && is_html(response) {
        html(url, response, options, &mut found);
        if options.process_form {
            forms(url, response, options, &mut found);
        }
    }
    if !consumed && is_text(response) && !is_html(response) {
        plain_http_urls(url, response, &mut found);
    }
    found
}

fn parse_allowed(path: &str, response: &FetchResponse) -> bool {
    if is_robots(path) || is_sitemap(path) {
        return true;
    }
    if response.body.len() > MAX_PARSE_SIZE {
        return false;
    }
    if is_redirect(response.status) {
        return true;
    }
    is_text(response)
}

fn is_robots(path: &str) -> bool {
    path.eq_ignore_ascii_case("/robots.txt")
}

fn is_sitemap(path: &str) -> bool {
    path.ends_with("/sitemap.xml")
}

fn robots(url: &str, response: &FetchResponse) -> Vec<Found> {
    let mut found = Vec::new();
    let text = String::from_utf8_lossy(&response.body);
    for line in text.lines() {
        let mut line = line.split('#').next().unwrap_or("").to_string();
        line = strip_tags(&line).trim().to_string();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let path = if lower.starts_with("disallow:") {
            line[9..].trim()
        } else if lower.starts_with("allow:") {
            line[6..].trim()
        } else {
            continue;
        };
        let path = path.strip_suffix('*').unwrap_or(path).trim();
        if !path.is_empty() {
            push_get(&mut found, url, path);
        }
    }
    found
}

fn sitemap(url: &str, response: &FetchResponse) -> Vec<Found> {
    let mut found = Vec::new();
    let text = String::from_utf8_lossy(&response.body);
    let loc = Regex::new(r"(?is)<loc>\s*([^<]+?)\s*</loc>").expect("loc");
    for capture in loc.captures_iter(&text) {
        push_get(&mut found, url, capture[1].trim());
    }
    let href = Regex::new(r#"(?i)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("href");
    for capture in href.captures_iter(&text) {
        let value = capture.get(1).or_else(|| capture.get(2));
        if let Some(value) = value {
            push_get(&mut found, url, value.as_str().trim());
        }
    }
    found
}

fn plain_http_urls(url: &str, response: &FetchResponse, found: &mut Vec<Found>) {
    let text = String::from_utf8_lossy(&response.body);
    let pattern = Regex::new(r#"(?i)\W(https?://[^\x00-\x1f"'\s<>#()\[\]{}]+)"#).expect("text url");
    for capture in pattern.captures_iter(&text) {
        push_get(found, url, &capture[1]);
    }
}

fn headers(url: &str, response: &FetchResponse, found: &mut Vec<Found>) {
    if let Some(location) = header(response, "content-location") {
        if !location.is_empty() {
            push_get(found, url, &location);
        }
    }
    if let Some(refresh) = header(response, "refresh") {
        if let Some(target) = url_equals(&refresh) {
            push_get(found, url, &target);
        }
    }
    for value in header_values(response, "link") {
        let mut rest = value.as_str();
        while let Some(start) = rest.find('<') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('>') else {
                break;
            };
            push_get(found, url, &after[..end]);
            rest = &after[end + 1..];
        }
    }
}

fn html(page: &str, response: &FetchResponse, options: &SpiderOptions, found: &mut Vec<Found>) {
    let text = String::from_utf8_lossy(&response.body);
    let mut base = page.to_string();
    let mut base_tag_set = false;
    if let Some(href) = first_attr(&text, "base", "href") {
        if !href.is_empty() {
            if let Some(canonical) = canonicalize(page, &href) {
                base = canonical;
                base_tag_set = true;
            }
            push_get(found, page, &href);
        }
    }
    for (name, attrs) in tags(&text) {
        for attribute in attributes_for(&name) {
            if let Some(value) = attr(&attrs, attribute) {
                if *attribute == "ping" {
                    for piece in value.split_whitespace() {
                        push_get(found, &base, piece);
                    }
                } else if *attribute == "srcset" {
                    for piece in srcset(&value) {
                        push_get(found, &base, &piece);
                    }
                } else {
                    push_get(found, &base, &value);
                }
            }
        }
    }
    meta(&text, &base, found);
    text_urls(&text, &base, base_tag_set, found);
    if options.parse_comments {
        comments(&text, &base, found);
    }
}

fn forms(page: &str, response: &FetchResponse, options: &SpiderOptions, found: &mut Vec<Found>) {
    let text = String::from_utf8_lossy(&response.body);
    let mut base = page.to_string();
    if let Some(href) = first_attr(&text, "base", "href") {
        if let Some(canonical) = canonicalize(page, &href) {
            base = canonical;
        }
    }
    for (attrs, inner) in form_blocks(&text) {
        let method = attr(&attrs, "method").unwrap_or_default();
        let action = attr(&attrs, "action").unwrap_or_else(|| base.clone());
        if !options.post_form && method.trim().eq_ignore_ascii_case("post") {
            continue;
        }
        let action = action.split('#').next().unwrap_or(&action).to_string();
        let fields = form_fields(&inner);
        let bodies = form_bodies(&fields);
        if method.trim().eq_ignore_ascii_case("post") {
            if let Some(full) = canonicalize(&base, &action) {
                for body in bodies {
                    found.push(Found {
                        url: full.clone(),
                        method: "POST".to_string(),
                        body,
                    });
                }
            }
        } else {
            for body in bodies {
                let with_query = if action.contains('?') {
                    if action.ends_with('?') {
                        format!("{action}{body}")
                    } else {
                        format!("{action}&{body}")
                    }
                } else {
                    format!("{action}?{body}")
                };
                push_get(found, &base, &with_query);
            }
        }
    }
}

struct Field {
    name: String,
    value: String,
    submit: bool,
}

fn form_fields(inner: &str) -> Vec<Field> {
    let mut fields = Vec::new();
    for (name, attrs) in tags(inner) {
        if !matches!(name.as_str(), "input" | "textarea" | "select" | "button") {
            continue;
        }
        if attr(&attrs, "disabled").is_some() {
            continue;
        }
        let Some(field_name) = attr(&attrs, "name") else {
            continue;
        };
        if field_name.is_empty() {
            continue;
        }
        let kind = attr(&attrs, "type").unwrap_or_else(|| {
            if name == "button" {
                "submit".to_string()
            } else {
                "text".to_string()
            }
        });
        if kind.eq_ignore_ascii_case("button") || kind.eq_ignore_ascii_case("reset") {
            continue;
        }
        if matches!(kind.to_ascii_lowercase().as_str(), "checkbox" | "radio")
            && attr(&attrs, "checked").is_none()
        {
            continue;
        }
        let submit = kind.eq_ignore_ascii_case("submit") || kind.eq_ignore_ascii_case("image");
        let value = attr(&attrs, "value").unwrap_or_default();
        fields.push(Field {
            name: form_encode(&field_name),
            value: form_encode(&value),
            submit,
        });
    }
    fields
}

fn form_bodies(fields: &[Field]) -> Vec<String> {
    let submit_indexes: Vec<usize> = fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.submit)
        .map(|(index, _)| index)
        .collect();
    if submit_indexes.is_empty() {
        return vec![encode_fields(fields.iter())];
    }
    submit_indexes
        .into_iter()
        .map(|submit_index| {
            encode_fields(fields.iter().enumerate().filter_map(|(index, field)| {
                if field.submit && index != submit_index {
                    None
                } else {
                    Some(field)
                }
            }))
        })
        .collect()
}

fn encode_fields<'a>(fields: impl Iterator<Item = &'a Field>) -> String {
    let mut body = String::new();
    for field in fields {
        if !body.is_empty() {
            body.push('&');
        }
        body.push_str(&field.name);
        body.push('=');
        body.push_str(&field.value);
    }
    body
}

fn meta(html: &str, base: &str, found: &mut Vec<Found>) {
    for (name, attrs) in tags(html) {
        if name != "meta" {
            continue;
        }
        let content = attr(&attrs, "content").unwrap_or_default();
        if let Some(equiv) = attr(&attrs, "http-equiv") {
            if matches!(
                equiv.to_ascii_lowercase().as_str(),
                "refresh" | "location" | "content-security-policy"
            ) {
                if let Some(target) = url_equals(&content) {
                    push_get(found, base, &target);
                }
            }
        } else if attr(&attrs, "name")
            .is_some_and(|name| name.eq_ignore_ascii_case("msapplication-config"))
            && !content.is_empty()
            && !content.eq_ignore_ascii_case("none")
        {
            push_get(found, base, &content);
        }
    }
}

fn text_urls(html: &str, base: &str, base_tag_set: bool, found: &mut Vec<Found>) {
    let pattern =
        Regex::new(r#"(?i)(?:https?://|(?:\s|\B)(?:\.{0,2})//?)[^\x00-\x1f"'\s<>#()\[\]{}]+"#)
            .expect("inline url");
    let base_path = base_path_of(base);
    for tag in [
        "p",
        "title",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "blockquote",
    ] {
        for inner in element_inners(html, tag) {
            let text = strip_tags(&inner);
            for matched in pattern.find_iter(&text) {
                let mut token = matched.as_str().trim().to_string();
                if token.is_empty() {
                    continue;
                }
                if base_tag_set
                    && token.starts_with('/')
                    && !token.starts_with("//")
                    && (base_path.is_empty() || !token.starts_with(&base_path))
                {
                    token = token[1..].to_string();
                }
                if token.starts_with('.') {
                    if let Some(index) = token.find('/') {
                        token = token[index..].to_string();
                    }
                }
                push_get(found, base, &token);
            }
        }
    }
}

fn comments(html: &str, base: &str, found: &mut Vec<Found>) {
    let pattern = Regex::new(r"(?is)<!--(.*?)-->").expect("comment");
    let plain =
        Regex::new(r#"(?i)(?:https?:)?//[^\x00-\x1f"'\s<>#()\[\]{}]+"#).expect("comment url");
    for capture in pattern.captures_iter(html) {
        let inner = &capture[1];
        let before = found.len();
        for (name, attrs) in tags(inner) {
            for attribute in attributes_for(&name) {
                if let Some(value) = attr(&attrs, attribute) {
                    push_get(found, base, &value);
                }
            }
        }
        if found.len() == before {
            for matched in plain.find_iter(inner) {
                push_get(found, base, matched.as_str());
            }
        }
    }
}

fn push_get(found: &mut Vec<Found>, base: &str, raw: &str) {
    let Some(url) = canonicalize(base, raw) else {
        return;
    };
    found.push(Found {
        url,
        method: "GET".to_string(),
        body: String::new(),
    });
}

fn attributes_for(name: &str) -> &'static [&'static str] {
    match name {
        "a" | "area" => &["href", "ping"],
        "applet" => &["archive", "codebase", "src"],
        "audio" | "embed" | "frame" | "iframe" | "input" | "script" | "source" => &["src"],
        "blockquote" => &["cite"],
        "isindex" => &["action"],
        "link" => &["href"],
        "object" => &["data", "codebase"],
        "param" => &["value"],
        "table" | "td" | "body" => &["background"],
        "video" => &["src", "poster"],
        "img" => &["src", "longdesc", "lowsrc", "dynsrc", "srcset"],
        "html" => &["manifest"],
        "import" => &["implementation"],
        _ => &[],
    }
}

fn srcset(value: &str) -> Vec<String> {
    let pattern = Regex::new(r#"(?i)[^"'=\s,]+\.[^\s,]+"#).expect("srcset");
    pattern
        .find_iter(value)
        .map(|matched| matched.as_str().to_string())
        .collect()
}

fn url_equals(value: &str) -> Option<String> {
    let pattern = Regex::new(r#"(?i)(?:url\s*=|report-uri)\s*["']?([^;'"]+)"#).expect("url=");
    pattern
        .captures(value)
        .map(|capture| capture[1].trim().to_string())
}

fn first_attr(html: &str, tag: &str, attribute: &str) -> Option<String> {
    tags(html).into_iter().find_map(|(name, attrs)| {
        if name == tag {
            attr(&attrs, attribute)
        } else {
            None
        }
    })
}

fn tags(html: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let bytes = html.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        if html[index..].starts_with("<!--") {
            if let Some(end) = html[index + 4..].find("-->") {
                index += 4 + end + 3;
                continue;
            }
        }
        if html[index..].starts_with("<!") || html[index..].starts_with("</") {
            if let Some(end) = html[index..].find('>') {
                index += end + 1;
                continue;
            }
            break;
        }
        let Some(end) = html[index..].find('>') else {
            break;
        };
        let raw = &html[index + 1..index + end];
        index += end + 1;
        let raw = raw.trim().trim_end_matches('/');
        let mut parts = raw.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let attr_text = raw[name.len()..].trim();
        out.push((name.to_ascii_lowercase(), attributes(attr_text)));
    }
    out
}

fn attributes(text: &str) -> Vec<(String, String)> {
    let pattern =
        Regex::new(r#"(?i)([A-Za-z_:][\w:.-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?"#)
            .expect("attr");
    pattern
        .captures_iter(text)
        .map(|capture| {
            let name = capture[1].to_ascii_lowercase();
            let value = capture
                .get(2)
                .or_else(|| capture.get(3))
                .or_else(|| capture.get(4))
                .map(|value| value.as_str().to_string())
                .unwrap_or_default();
            (name, value)
        })
        .collect()
}

fn attr(attrs: &[(String, String)], name: &str) -> Option<String> {
    attrs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

fn form_blocks(html: &str) -> Vec<(Vec<(String, String)>, String)> {
    let pattern = Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>").expect("form");
    pattern
        .captures_iter(html)
        .map(|capture| (attributes(capture[1].trim()), capture[2].to_string()))
        .collect()
}

fn element_inners(html: &str, tag: &str) -> Vec<String> {
    let pattern = Regex::new(&format!(r"(?is)<{tag}\b[^>]*>(.*?)</{tag}>")).expect("inner");
    pattern
        .captures_iter(html)
        .map(|capture| capture[1].to_string())
        .collect()
}

fn strip_tags(value: &str) -> String {
    Regex::new(r"<[^>]+>")
        .expect("tag")
        .replace_all(value, "")
        .into_owned()
}

fn base_path_of(base: &str) -> String {
    let with_slash = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    let parts: Vec<_> = with_slash.split('/').collect();
    if parts.len() > 3 && !parts[3].is_empty() {
        format!("/{}/", parts[3])
    } else {
        String::new()
    }
}

fn header(response: &FetchResponse, name: &str) -> Option<String> {
    header_values(response, name).into_iter().next()
}

fn header_values(response: &FetchResponse, name: &str) -> Vec<String> {
    response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .collect()
}

fn content_type(response: &FetchResponse) -> String {
    header(response, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_html(response: &FetchResponse) -> bool {
    content_type(response).contains("html")
}

fn is_xml(response: &FetchResponse) -> bool {
    content_type(response).contains("xml")
}

fn is_text(response: &FetchResponse) -> bool {
    let value = content_type(response);
    ["text", "html", "javascript", "json", "xml"]
        .iter()
        .any(|needle| value.contains(needle))
}

fn is_redirect(status: u16) -> bool {
    (300..400).contains(&status)
}

fn is_error(status: u16) -> bool {
    status >= 400
}
