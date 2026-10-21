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
// official OWASP ZAP build.

//! Boa evaluation of one script hook against one message.

use boa_engine::{Context, JsString, JsValue, Source};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::{Map, Value};
use zap_core::{HttpMessage, HttpResponse};

use crate::host::ScriptError;

const PRELUDE: &str = r#"
function __zap_bind(msg) {
    msg.setRequestHeader = function (name, value) {
        msg.__requestHeaders[String(name).toLowerCase()] = String(value);
    };
    msg.requestHeader = function (name) {
        var key = String(name).toLowerCase();
        return Object.prototype.hasOwnProperty.call(msg.__requestHeaders, key)
            ? msg.__requestHeaders[key]
            : null;
    };
    msg.setResponseHeader = function (name, value) {
        if (msg.__responseHeaders === null || msg.__responseHeaders === undefined) {
            msg.__responseHeaders = {};
        }
        msg.__responseHeaders[String(name).toLowerCase()] = String(value);
    };
    msg.responseHeader = function (name) {
        if (msg.__responseHeaders === null || msg.__responseHeaders === undefined) {
            return null;
        }
        var key = String(name).toLowerCase();
        return Object.prototype.hasOwnProperty.call(msg.__responseHeaders, key)
            ? msg.__responseHeaders[key]
            : null;
    };
    msg.setResponse = function (status, body) {
        msg.__overrideStatus = Number(status);
        msg.__overrideBody = body === undefined || body === null ? "" : String(body);
        if (msg.__responseHeaders === null || msg.__responseHeaders === undefined) {
            msg.__responseHeaders = {};
        }
    };
    return msg;
}

function __zap_import(raw) {
    return __zap_bind(JSON.parse(raw));
}

function __zap_export(msg) {
    return JSON.stringify({
        __requestHeaders: msg.__requestHeaders,
        __responseHeaders: msg.__responseHeaders,
        __overrideStatus: msg.__overrideStatus,
        __overrideBody: msg.__overrideBody
    });
}

function __zap_helper() {
    return {};
}
"#;

pub fn compile_check(source: &str) -> Result<(), ScriptError> {
    let mut context = Context::default();
    eval(&mut context, source)
}

/// Run `hook` if the script defines it. `initiator` is passed only for httpsender hooks.
///
/// Returns whether a proxy hook allows the chain to continue. Missing hooks
/// and httpsender hooks report continue.
pub fn invoke(
    source: &str,
    hook: &str,
    msg: &mut HttpMessage,
    initiator: Option<i32>,
) -> Result<bool, ScriptError> {
    let mut context = Context::default();
    eval(&mut context, PRELUDE)?;
    eval(&mut context, source)?;
    if !function_defined(&mut context, hook)? {
        return Ok(true);
    }
    let raw = serde_json::to_string(&payload(msg))
        .map_err(|err| ScriptError::new(format!("script message: {err}")))?;
    let imported = call(
        &mut context,
        "__zap_import",
        &[JsValue::from(JsString::from(raw))],
    )?;
    let result = if let Some(initiator) = initiator {
        let helper = call(&mut context, "__zap_helper", &[])?;
        call(
            &mut context,
            hook,
            &[imported.clone(), JsValue::from(initiator), helper],
        )?
    } else {
        call(&mut context, hook, &[imported.clone()])?
    };
    let exported = call(&mut context, "__zap_export", &[imported])?;
    let text = js_to_string(&exported, &mut context)?;
    apply_export(msg, &text)?;
    Ok(result.as_boolean() != Some(false))
}

fn eval(context: &mut Context, source: &str) -> Result<(), ScriptError> {
    context
        .eval(Source::from_bytes(source))
        .map(|_| ())
        .map_err(|err| ScriptError::new(err.to_string()))
}

fn function_defined(context: &mut Context, name: &str) -> Result<bool, ScriptError> {
    let global = context.global_object();
    let value = global
        .get(JsString::from(name), context)
        .map_err(|err| ScriptError::new(err.to_string()))?;
    Ok(value.as_object().is_some())
}

fn call(context: &mut Context, name: &str, args: &[JsValue]) -> Result<JsValue, ScriptError> {
    let func = {
        let global = context.global_object();
        let value = global
            .get(JsString::from(name), context)
            .map_err(|err| ScriptError::new(err.to_string()))?;
        value
            .as_object()
            .ok_or_else(|| ScriptError::new(format!("missing function {name}")))?
    };
    func.call(&JsValue::undefined(), args, context)
        .map_err(|err| ScriptError::new(err.to_string()))
}

fn js_to_string(value: &JsValue, context: &mut Context) -> Result<String, ScriptError> {
    let text = value
        .to_string(context)
        .map_err(|err| ScriptError::new(err.to_string()))?;
    Ok(text.to_std_string_escaped())
}

fn payload(msg: &HttpMessage) -> Value {
    serde_json::json!({
        "url": msg.url(),
        "method": msg.method.as_str(),
        "requestBody": String::from_utf8_lossy(&msg.body),
        "responseBody": msg.response.as_ref().map(|response| {
            String::from_utf8_lossy(&response.body).into_owned()
        }),
        "responseStatus": msg.response.as_ref().map(|response| response.status.as_u16()),
        "__requestHeaders": header_object(&msg.headers),
        "__responseHeaders": msg.response.as_ref().map(|response| header_object(&response.headers)),
        "__overrideStatus": Value::Null,
        "__overrideBody": Value::Null,
    })
}

fn header_object(headers: &HeaderMap) -> Value {
    let mut map = Map::new();
    for (name, value) in headers.iter() {
        map.insert(
            name.as_str().to_string(),
            Value::String(String::from_utf8_lossy(value.as_bytes()).into_owned()),
        );
    }
    Value::Object(map)
}

fn apply_export(msg: &mut HttpMessage, json: &str) -> Result<(), ScriptError> {
    let exported: Value = serde_json::from_str(json)
        .map_err(|err| ScriptError::new(format!("script export: {err}")))?;
    let request_headers = exported
        .get("__requestHeaders")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    msg.headers = headers_from_map(&request_headers);
    let response_headers = exported.get("__responseHeaders").and_then(Value::as_object);
    let override_status = exported.get("__overrideStatus").and_then(Value::as_f64);
    if let Some(status) = override_status.filter(|status| status.is_finite()) {
        if let Ok(status) = StatusCode::from_u16(status as u16) {
            let headers = response_headers.map(headers_from_map).unwrap_or_default();
            let body = exported
                .get("__overrideBody")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            msg.response = Some(HttpResponse {
                status,
                headers,
                body: Bytes::from(body),
            });
            return Ok(());
        }
    }
    if let (Some(response), Some(headers)) = (msg.response.as_mut(), response_headers) {
        response.headers = headers_from_map(headers);
    }
    Ok(())
}

fn headers_from_map(map: &Map<String, Value>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in map {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Some(text) = value.as_str() else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(text) else {
            continue;
        };
        headers.insert(name, value);
    }
    headers
}
