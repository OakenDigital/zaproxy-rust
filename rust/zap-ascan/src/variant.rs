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
// official OWASP ZAP build. Query and form injection follow the Paros
// parameter variants carried in the ZAP core. JSON injection follows
// `VariantJSONQuery`.

//! URL query, form body, and JSON variants.
//!
//! Other variants (XML, multipart, OData, GWT, script) are not implemented.

use bytes::Bytes;
use http::{HeaderValue, Uri};
use zap_core::HttpMessage;

use crate::coding::{escape_java, form_encode, form_pairs, unescape_java};

/// One injectable parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// Name reported on the alert. Array query names use `name[0]`.
    pub name: String,
    /// Name written back into the query or form body.
    pub wire_name: String,
    pub value: String,
}

/// Where a parameter was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariantKind {
    Query,
    Form,
    Json,
}

#[derive(Clone, Debug)]
struct JsonSpan {
    begin: usize,
    end: usize,
    quote: bool,
}

/// Parameters from one variant of a message.
#[derive(Clone, Debug)]
pub struct Variant {
    kind: VariantKind,
    params: Vec<Param>,
    raw: String,
    spans: Vec<JsonSpan>,
}

impl Variant {
    pub fn kind(&self) -> VariantKind {
        self.kind
    }

    pub fn params(&self) -> &[Param] {
        &self.params
    }

    /// Copy `base` with parameter `index` set to `value`.
    pub fn apply(&self, base: &HttpMessage, index: usize, value: &str) -> HttpMessage {
        let mut msg = base.clone();
        match self.kind {
            VariantKind::Query => {
                let query = rebuild_pairs(&self.params, index, value);
                msg.uri = set_query(&msg.uri, &query);
            }
            VariantKind::Form => {
                let body = rebuild_pairs(&self.params, index, value);
                set_body(&mut msg, body.into_bytes());
            }
            VariantKind::Json => {
                let span = &self.spans[index];
                let replacement = if span.quote {
                    format!("\"{}\"", escape_java(value))
                } else {
                    escape_java(value)
                };
                let mut body = self.raw.clone();
                body.replace_range(span.begin..span.end, &replacement);
                set_body(&mut msg, body.into_bytes());
            }
        }
        msg
    }
}

/// Variants that apply to `msg`, in ZAP's default order: query, form, JSON.
pub fn variants_for(msg: &HttpMessage) -> Vec<Variant> {
    let mut found = Vec::new();
    if let Some(variant) = query_variant(msg) {
        found.push(variant);
    }
    if let Some(variant) = form_variant(msg) {
        found.push(variant);
    }
    if let Some(variant) = json_variant(msg) {
        found.push(variant);
    }
    found
}

fn query_variant(msg: &HttpMessage) -> Option<Variant> {
    let query = msg.uri.query().unwrap_or("");
    if query.is_empty() {
        return None;
    }
    let params = named_params(&form_pairs(query));
    if params.is_empty() {
        return None;
    }
    Some(Variant {
        kind: VariantKind::Query,
        params,
        raw: String::new(),
        spans: Vec::new(),
    })
}

fn form_variant(msg: &HttpMessage) -> Option<Variant> {
    if !content_type_starts(msg, "application/x-www-form-urlencoded") {
        return None;
    }
    let body = String::from_utf8_lossy(&msg.body);
    let params = named_params(&form_pairs(&body));
    if params.is_empty() {
        return None;
    }
    Some(Variant {
        kind: VariantKind::Form,
        params,
        raw: String::new(),
        spans: Vec::new(),
    })
}

fn json_variant(msg: &HttpMessage) -> Option<Variant> {
    if !content_type_starts(msg, "application/json") {
        return None;
    }
    let raw = String::from_utf8_lossy(&msg.body).into_owned();
    if raw.trim().is_empty() {
        return None;
    }
    let parsed = parse_json(&raw)?;
    if parsed.is_empty() {
        return None;
    }
    let params = parsed
        .iter()
        .map(|item| Param {
            name: item.name.clone(),
            wire_name: item.name.clone(),
            value: item.value.clone(),
        })
        .collect();
    let spans = parsed
        .into_iter()
        .map(|item| JsonSpan {
            begin: item.begin,
            end: item.end,
            quote: item.quote,
        })
        .collect();
    Some(Variant {
        kind: VariantKind::Json,
        params,
        raw,
        spans,
    })
}

fn named_params(pairs: &[(String, String)]) -> Vec<Param> {
    let mut arrays = std::collections::HashMap::<String, usize>::new();
    pairs
        .iter()
        .map(|(wire_name, value)| {
            let name = if let Some(base) = wire_name.strip_suffix("[]") {
                let count = arrays.entry(wire_name.clone()).or_insert(0);
                let name = format!("{base}[{count}]");
                *count += 1;
                name
            } else {
                wire_name.clone()
            };
            Param {
                name,
                wire_name: wire_name.clone(),
                value: value.clone(),
            }
        })
        .collect()
}

fn rebuild_pairs(params: &[Param], index: usize, new_value: &str) -> String {
    params
        .iter()
        .enumerate()
        .map(|(i, param)| {
            let value = if i == index {
                new_value
            } else {
                param.value.as_str()
            };
            format!("{}={}", form_encode(&param.wire_name), form_encode(value))
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn set_query(uri: &Uri, query: &str) -> Uri {
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority().map(|value| value.as_str()).unwrap_or("");
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let built = if query.is_empty() {
        format!("{scheme}://{authority}{path}")
    } else {
        format!("{scheme}://{authority}{path}?{query}")
    };
    built.parse().unwrap_or_else(|_| uri.clone())
}

fn set_body(msg: &mut HttpMessage, body: Vec<u8>) {
    if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
        msg.headers.insert(http::header::CONTENT_LENGTH, length);
    }
    msg.body = Bytes::from(body);
}

fn content_type_starts(msg: &HttpMessage, prefix: &str) -> bool {
    msg.headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().to_ascii_lowercase().starts_with(prefix))
}

struct JsonParam {
    name: String,
    value: String,
    begin: usize,
    end: usize,
    quote: bool,
}

fn parse_json(input: &str) -> Option<Vec<JsonParam>> {
    let mut parser = JsonParser {
        s: input,
        i: 0,
        out: Vec::new(),
    };
    parser.skip_ws();
    if parser.eof() {
        return Some(Vec::new());
    }
    parser.parse_value(None).ok()?;
    Some(parser.out)
}

struct JsonParser<'a> {
    s: &'a str,
    i: usize,
    out: Vec<JsonParam>,
}

impl<'a> JsonParser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.as_bytes().get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    fn parse_value(&mut self, name: Option<String>) -> Result<(), ()> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string_value(name.unwrap_or_default()),
            Some(b'{') => self.parse_object(),
            Some(b'[') => {
                let name = name.unwrap_or_else(|| "@items".to_string());
                self.parse_array(&name)
            }
            Some(b't') | Some(b'f') | Some(b'n') => self.skip_literal(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(name.unwrap_or_default()),
            _ => Err(()),
        }
    }

    fn parse_object(&mut self) -> Result<(), ()> {
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            let key = self.parse_string_raw()?;
            self.skip_ws();
            self.expect(b':')?;
            self.parse_value(Some(key))?;
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.i += 1;
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn parse_array(&mut self, name: &str) -> Result<(), ()> {
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        let mut index = 0;
        loop {
            let item = format!("{name}[{index}]");
            self.parse_value(Some(item))?;
            index += 1;
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.i += 1;
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_ws();
        }
    }

    fn parse_string_value(&mut self, name: String) -> Result<(), ()> {
        let (begin, end, value) = self.read_string()?;
        self.out.push(JsonParam {
            name,
            value,
            begin,
            end,
            quote: false,
        });
        Ok(())
    }

    fn parse_string_raw(&mut self) -> Result<String, ()> {
        let (_, _, value) = self.read_string()?;
        Ok(value)
    }

    fn read_string(&mut self) -> Result<(usize, usize, String), ()> {
        self.expect(b'"')?;
        let begin = self.i;
        let bytes = self.s.as_bytes();
        while self.i < bytes.len() {
            match bytes[self.i] {
                b'\\' => {
                    self.i += 1;
                    if self.i >= bytes.len() {
                        return Err(());
                    }
                    if bytes[self.i] == b'u' {
                        self.i += 1;
                        if self.i + 4 > bytes.len() {
                            return Err(());
                        }
                        self.i += 4;
                    } else {
                        self.i += 1;
                    }
                }
                b'"' => {
                    let end = self.i;
                    let value = unescape_java(&self.s[begin..end]);
                    self.i += 1;
                    return Ok((begin, end, value));
                }
                _ => self.i += 1,
            }
        }
        Err(())
    }

    fn parse_number(&mut self, name: String) -> Result<(), ()> {
        let begin = self.i;
        while let Some(byte) = self.peek() {
            if matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.i == begin {
            return Err(());
        }
        let raw = self.s[begin..self.i].to_string();
        self.out.push(JsonParam {
            name,
            value: raw,
            begin,
            end: self.i,
            quote: true,
        });
        Ok(())
    }

    fn skip_literal(&mut self) -> Result<(), ()> {
        if self.peek().is_none_or(|byte| !byte.is_ascii_alphabetic()) {
            return Err(());
        }
        while self.peek().is_some_and(|byte| byte.is_ascii_alphabetic()) {
            self.i += 1;
        }
        Ok(())
    }

    fn expect(&mut self, byte: u8) -> Result<(), ()> {
        if self.peek() == Some(byte) {
            self.i += 1;
            Ok(())
        } else {
            Err(())
        }
    }
}
