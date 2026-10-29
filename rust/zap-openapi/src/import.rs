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

//! Walk `paths` and build one request per operation.

use std::path::Path;

use http::{HeaderName, HeaderValue, Method, Uri};
use serde_json::Value;

use crate::error::ImportError;
use crate::generate::{
    encode_component, form_encode, generated_param, media_example, render_body, resolve, scalar,
};
use crate::ApiRequest;

const METHODS: &[&str] = &[
    "get", "post", "put", "head", "options", "delete", "patch", "trace",
];

const MEDIA_PREFERENCE: &[&str] = &[
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
];

enum SpecKind {
    OpenApi3,
    Swagger2,
}

pub(crate) fn import_str(
    document: &str,
    target: Option<&str>,
) -> Result<Vec<ApiRequest>, ImportError> {
    let root = parse_document(document)?;
    let kind = detect(&root)?;
    let bases = root_bases(&root, kind, target)?;
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut requests = Vec::new();
    let mut saw_operation = false;
    for (path, item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        let item = resolve(&root, item, &mut Vec::new()).clone();
        if !item.is_object() {
            continue;
        }
        let path_bases = scoped_bases(&item, &bases, target);
        let path_params = parameter_list(&root, item.get("parameters"));
        for method in METHODS {
            let Some(operation) = item.get(*method) else {
                continue;
            };
            let operation = resolve(&root, operation, &mut Vec::new()).clone();
            if !operation.is_object() {
                continue;
            }
            saw_operation = true;
            let op_bases = scoped_bases(&operation, &path_bases, target);
            if op_bases.is_empty() {
                continue;
            }
            let params = merge_params(
                &path_params,
                &parameter_list(&root, operation.get("parameters")),
            );
            for base in &op_bases {
                requests.push(build_request(
                    &root, method, base, path, &operation, &params,
                )?);
            }
        }
    }
    if saw_operation && requests.is_empty() {
        return Err(ImportError::NoServer);
    }
    Ok(requests)
}

pub(crate) fn import_path(
    path: &Path,
    target: Option<&str>,
) -> Result<Vec<ApiRequest>, ImportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| ImportError::Read(format!("{path:?}: {err}")))?;
    import_str(&text, target)
}

fn parse_document(text: &str) -> Result<Value, ImportError> {
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(ImportError::Empty);
    }
    if text.starts_with('{') || text.starts_with('[') {
        return serde_json::from_str(text).map_err(|err| ImportError::Syntax(err.to_string()));
    }
    serde_yaml::from_str(text).map_err(|err| ImportError::Syntax(err.to_string()))
}

fn detect(root: &Value) -> Result<SpecKind, ImportError> {
    if let Some(version) = root.get("openapi").and_then(Value::as_str) {
        if version.starts_with("3.") {
            return Ok(SpecKind::OpenApi3);
        }
        return Err(ImportError::Unsupported);
    }
    if is_swagger_2(root.get("swagger")) {
        return Ok(SpecKind::Swagger2);
    }
    Err(ImportError::Unsupported)
}

fn is_swagger_2(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => text == "2.0",
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|value| (value - 2.0).abs() < f64::EPSILON),
        _ => false,
    }
}

fn root_bases(
    root: &Value,
    kind: SpecKind,
    target: Option<&str>,
) -> Result<Vec<String>, ImportError> {
    if let Some(base) = target_base(target)? {
        return Ok(vec![base]);
    }
    Ok(match kind {
        SpecKind::OpenApi3 => server_list(root.get("servers")),
        SpecKind::Swagger2 => swagger_base(root).into_iter().collect(),
    })
}

fn target_base(target: Option<&str>) -> Result<Option<String>, ImportError> {
    let Some(target) = target.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if !is_http(target) {
        return Err(ImportError::BadTarget(target.to_string()));
    }
    Ok(Some(trim_slash(target)))
}

fn scoped_bases(spec: &Value, fallback: &[String], target: Option<&str>) -> Vec<String> {
    if target.map(str::trim).is_some_and(|value| !value.is_empty()) {
        return fallback.to_vec();
    }
    let local = server_list(spec.get("servers"));
    if local.is_empty() {
        fallback.to_vec()
    } else {
        local
    }
}

fn server_list(servers: Option<&Value>) -> Vec<String> {
    let Some(items) = servers.and_then(Value::as_array) else {
        return Vec::new();
    };
    items.iter().filter_map(server_url).collect()
}

fn server_url(server: &Value) -> Option<String> {
    let url = server.get("url")?.as_str()?.trim();
    if url.is_empty() {
        return None;
    }
    let mut url = url.to_string();
    if let Some(variables) = server.get("variables").and_then(Value::as_object) {
        for (name, spec) in variables {
            url = url.replace(&format!("{{{name}}}"), &server_variable(spec));
        }
    }
    if !is_http(&url) {
        return None;
    }
    Some(trim_slash(&url))
}

fn server_variable(spec: &Value) -> String {
    if let Some(default) = spec.get("default").filter(|value| !value.is_null()) {
        let text = scalar(default);
        if !text.is_empty() {
            return text;
        }
    }
    if let Some(first) = spec
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
    {
        let text = scalar(first);
        if !text.is_empty() {
            return text;
        }
    }
    "string".to_string()
}

fn swagger_base(root: &Value) -> Option<String> {
    let host = root.get("host").and_then(Value::as_str)?.trim();
    if host.is_empty() {
        return None;
    }
    let scheme = root
        .get("schemes")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|value| {
                value
                    .as_str()
                    .filter(|scheme| *scheme == "http" || *scheme == "https")
            })
        })
        .unwrap_or("http");
    let base_path = root
        .get("basePath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_end_matches('/');
    if base_path.is_empty() {
        Some(format!("{scheme}://{host}"))
    } else if let Some(stripped) = base_path.strip_prefix('/') {
        Some(format!("{scheme}://{host}/{stripped}"))
    } else {
        Some(format!("{scheme}://{host}/{base_path}"))
    }
}

fn parameter_list(root: &Value, spec: Option<&Value>) -> Vec<Value> {
    let Some(items) = spec.and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| resolve(root, item, &mut Vec::new()).clone())
        .filter(|item| item.get("name").and_then(Value::as_str).is_some())
        .collect()
}

fn merge_params(path_params: &[Value], operation_params: &[Value]) -> Vec<Value> {
    let mut merged = path_params.to_vec();
    for param in operation_params {
        let key = param_key(param);
        if let Some(existing) = merged.iter_mut().find(|item| param_key(item) == key) {
            *existing = param.clone();
        } else {
            merged.push(param.clone());
        }
    }
    merged
}

fn param_key(param: &Value) -> (String, String) {
    (
        param
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        param
            .get("in")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

fn build_request(
    root: &Value,
    method: &str,
    base: &str,
    path: &str,
    operation: &Value,
    params: &[Value],
) -> Result<ApiRequest, ImportError> {
    let filled = fill_path(root, path, params);
    let query = query_string(root, params);
    let url = format!("{}{query}", join_url(base, &filled));
    ensure_http_url(&url)?;
    let (body, content_type) = request_body(root, operation, params);
    let headers = header_params(root, params);
    Ok(ApiRequest {
        method: method.to_ascii_uppercase(),
        url,
        body,
        content_type,
        headers,
    })
}

fn fill_path(root: &Value, path: &str, params: &[Value]) -> String {
    let mut filled = path.to_string();
    for param in params.iter().filter(|param| location(param) == "path") {
        let Some(name) = param.get("name").and_then(Value::as_str) else {
            continue;
        };
        let value = encode_component(&scalar(&generated_param(root, param)));
        filled = filled.replace(&format!("{{{name}}}"), &value);
    }
    replace_undeclared(&filled)
}

fn replace_undeclared(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('}') {
            out.push_str("string");
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn query_string(root: &Value, params: &[Value]) -> String {
    let mut out = String::new();
    for param in params.iter().filter(|param| location(param) == "query") {
        let Some(name) = param.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !out.is_empty() {
            out.push('&');
        } else {
            out.push('?');
        }
        out.push_str(&encode_component(name));
        out.push('=');
        out.push_str(&encode_component(&scalar(&generated_param(root, param))));
    }
    out
}

fn header_params(root: &Value, params: &[Value]) -> Vec<(String, String)> {
    params
        .iter()
        .filter(|param| location(param) == "header")
        .filter_map(|param| {
            let name = param.get("name").and_then(Value::as_str)?;
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), scalar(&generated_param(root, param))))
        })
        .collect()
}

fn request_body(root: &Value, operation: &Value, params: &[Value]) -> (String, Option<String>) {
    if let Some(body) = operation.get("requestBody") {
        let body = resolve(root, body, &mut Vec::new());
        if let Some((body, content_type)) = openapi3_body(root, body) {
            return (body, content_type);
        }
    }
    swagger_body(root, params)
}

fn openapi3_body(root: &Value, body: &Value) -> Option<(String, Option<String>)> {
    let content = body.get("content")?.as_object()?;
    let (content_type, media) = pick_media(content)?;
    let value = media_example(root, media);
    let (text, stored) = render_body(content_type, &value);
    if text.is_empty() {
        None
    } else {
        Some((text, stored))
    }
}

fn pick_media(content: &serde_json::Map<String, Value>) -> Option<(&str, &Value)> {
    for name in MEDIA_PREFERENCE {
        if let Some(media) = content.get(*name) {
            return Some((*name, media));
        }
    }
    content
        .iter()
        .next()
        .map(|(name, media)| (name.as_str(), media))
}

fn swagger_body(root: &Value, params: &[Value]) -> (String, Option<String>) {
    if let Some(body) = params.iter().find(|param| location(param) == "body") {
        let value = if body.get("example").is_some() {
            generated_param(root, body)
        } else if let Some(schema) = body.get("schema") {
            media_example(root, &serde_json::json!({ "schema": schema }))
        } else {
            Value::Null
        };
        return render_body("application/json", &value);
    }
    let forms: Vec<&Value> = params
        .iter()
        .filter(|param| location(param) == "formData")
        .collect();
    if forms.is_empty() {
        return (String::new(), None);
    }
    let mut map = serde_json::Map::new();
    for param in forms {
        let Some(name) = param.get("name").and_then(Value::as_str) else {
            continue;
        };
        map.insert(name.to_string(), generated_param(root, param));
    }
    (
        form_encode(&Value::Object(map)),
        Some("application/x-www-form-urlencoded".to_string()),
    )
}

fn location(param: &Value) -> &str {
    param.get("in").and_then(Value::as_str).unwrap_or("")
}

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.is_empty() || path == "/" {
        return format!("{base}/");
    }
    if let Some(stripped) = path.strip_prefix('/') {
        format!("{base}/{stripped}")
    } else {
        format!("{base}/{path}")
    }
}

fn trim_slash(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

fn is_http(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn ensure_http_url(url: &str) -> Result<(), ImportError> {
    let uri = url
        .parse::<Uri>()
        .map_err(|_| ImportError::BadUrl(url.to_string()))?;
    if matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some() {
        Ok(())
    } else {
        Err(ImportError::BadUrl(url.to_string()))
    }
}

impl ApiRequest {
    pub(crate) fn http_message(&self) -> zap_core::HttpMessage {
        let mut headers = http::HeaderMap::new();
        for (name, value) in &self.headers {
            let (Ok(name), Ok(value)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::from_str(value),
            ) else {
                continue;
            };
            headers.insert(name, value);
        }
        if let Some(content_type) = &self.content_type {
            if !headers.contains_key(http::header::CONTENT_TYPE) {
                if let Ok(value) = HeaderValue::from_str(content_type) {
                    headers.insert(http::header::CONTENT_TYPE, value);
                }
            }
        }
        if !self.body.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&self.body.len().to_string()) {
                headers.insert(http::header::CONTENT_LENGTH, value);
            }
        }
        zap_core::HttpMessage {
            method: http_method(&self.method),
            uri: self
                .url
                .parse()
                .unwrap_or_else(|_| Uri::from_static("http://invalid.invalid/")),
            headers,
            body: bytes::Bytes::from(self.body.clone()),
            response: None,
        }
    }
}

fn http_method(name: &str) -> Method {
    match name {
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "HEAD" => Method::HEAD,
        "OPTIONS" => Method::OPTIONS,
        "PATCH" => Method::PATCH,
        "TRACE" => Method::TRACE,
        _ => Method::GET,
    }
}
