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
// This file is a Rust derivative of the ZAP OpenAPI add-on. It changes the
// language and the architecture (Apache License 2.0, section 4). It is not
// an official OWASP ZAP build.

//! Example, default, and type values for parameters and request bodies.
//!
//! Remote `$ref` values are left unresolved. Nothing is downloaded.

use serde_json::{Map, Value};

const MAX_DEPTH: u32 = 8;

pub(crate) fn resolve<'a>(root: &'a Value, value: &'a Value, seen: &mut Vec<String>) -> &'a Value {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return value;
    };
    if seen.iter().any(|item| item == reference) {
        return value;
    }
    if reference == "#" {
        return root;
    }
    if !reference.starts_with("#/") {
        return value;
    }
    let Some(target) = json_pointer(root, reference) else {
        return value;
    };
    seen.push(reference.to_string());
    let resolved = resolve(root, target, seen);
    seen.pop();
    resolved
}

pub(crate) fn generated_param(root: &Value, param: &Value) -> Value {
    let param = resolve(root, param, &mut Vec::new());
    if let Some(example) = param.get("example").filter(|value| !value.is_null()) {
        return example.clone();
    }
    let schema = param.get("schema").unwrap_or(param);
    generate(root, schema, 0)
}

pub(crate) fn media_example(root: &Value, media: &Value) -> Value {
    let media = resolve(root, media, &mut Vec::new());
    if let Some(example) = media.get("example").filter(|value| !value.is_null()) {
        return example.clone();
    }
    if let Some(value) = first_examples_value(media) {
        return value;
    }
    match media.get("schema") {
        Some(schema) => generate(root, schema, 0),
        None => Value::Null,
    }
}

pub(crate) fn render_body(content_type: &str, value: &Value) -> (String, Option<String>) {
    if value.is_null() {
        return (String::new(), None);
    }
    let bare = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    if bare == "application/x-www-form-urlencoded" || bare == "multipart/form-data" {
        return (
            form_encode(value),
            Some("application/x-www-form-urlencoded".to_string()),
        );
    }
    if bare == "text/plain" {
        return (scalar(value), Some("text/plain".to_string()));
    }
    let json = serde_json::to_string(value).unwrap_or_default();
    if json.is_empty() {
        return (String::new(), None);
    }
    let stored = if bare == "application/json" || bare.ends_with("+json") || bare.is_empty() {
        "application/json".to_string()
    } else {
        bare.to_string()
    };
    (json, Some(stored))
}

pub(crate) fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub(crate) fn encode_component(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub(crate) fn form_encode(value: &Value) -> String {
    let Some(map) = value.as_object() else {
        return encode_component(&scalar(value));
    };
    let mut out = String::new();
    for (index, (key, child)) in map.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&encode_component(key));
        out.push('=');
        out.push_str(&encode_component(&scalar(child)));
    }
    out
}

fn generate(root: &Value, schema: &Value, depth: u32) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    let schema = resolve(root, schema, &mut Vec::new()).clone();
    if schema.get("$ref").is_some() {
        return Value::String("string".to_string());
    }
    if let Some(example) = schema.get("example").filter(|value| !value.is_null()) {
        return example.clone();
    }
    if let Some(default) = schema.get("default").filter(|value| !value.is_null()) {
        return default.clone();
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
    {
        return first.clone();
    }
    if let Some(merged) = generate_all_of(root, &schema, depth) {
        return merged;
    }
    if let Some(first) = schema
        .get("oneOf")
        .or_else(|| schema.get("anyOf"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
    {
        return generate(root, first, depth + 1);
    }
    match type_name(&schema) {
        Some("object") => generate_object(root, &schema, depth),
        Some("array") => {
            let item = match schema.get("items") {
                Some(items) => generate(root, items, depth + 1),
                None => Value::String("string".to_string()),
            };
            Value::Array(vec![item])
        }
        Some("integer") => serde_json::json!(1),
        Some("number") => serde_json::json!(1.1),
        Some("boolean") => Value::Bool(true),
        Some("string") => Value::String(string_value(&schema)),
        None if schema.get("properties").is_some() => generate_object(root, &schema, depth),
        _ => Value::String("string".to_string()),
    }
}

fn generate_all_of(root: &Value, schema: &Value, depth: u32) -> Option<Value> {
    let parts = schema.get("allOf")?.as_array()?;
    let mut merged = Map::new();
    let mut fallback = None;
    for part in parts {
        match generate(root, part, depth + 1) {
            Value::Object(map) => {
                for (key, value) in map {
                    merged.insert(key, value);
                }
            }
            other if fallback.is_none() && !other.is_null() => fallback = Some(other),
            _ => {}
        }
    }
    if merged.is_empty() {
        fallback
    } else {
        Some(Value::Object(merged))
    }
}

fn generate_object(root: &Value, schema: &Value, depth: u32) -> Value {
    let mut map = Map::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            map.insert(name.clone(), generate(root, property, depth + 1));
        }
    }
    Value::Object(map)
}

fn string_value(schema: &Value) -> String {
    match schema.get("format").and_then(Value::as_str).unwrap_or("") {
        "date" => "2020-01-01".to_string(),
        "date-time" => "2020-01-01T00:00:00Z".to_string(),
        "email" => "user@example.com".to_string(),
        "uuid" => "00000000-0000-0000-0000-000000000000".to_string(),
        "byte" => "YQ==".to_string(),
        _ => "string".to_string(),
    }
}

fn type_name(schema: &Value) -> Option<&str> {
    match schema.get("type") {
        Some(Value::String(name)) => Some(name.as_str()),
        Some(Value::Array(items)) => items
            .iter()
            .find_map(Value::as_str)
            .filter(|name| *name != "null"),
        _ => None,
    }
}

fn first_examples_value(media: &Value) -> Option<Value> {
    let examples = media.get("examples")?.as_object()?;
    for example in examples.values() {
        if let Some(value) = example.get("value").filter(|value| !value.is_null()) {
            return Some(value.clone());
        }
    }
    None
}

fn json_pointer<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let mut current = root;
    for raw in reference.trim_start_matches("#/").split('/') {
        if raw.is_empty() {
            continue;
        }
        current = current.get(decode_pointer(raw))?;
    }
    Some(current)
}

fn decode_pointer(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                Some(other) => {
                    out.push('~');
                    out.push(other);
                }
                None => out.push('~'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}
