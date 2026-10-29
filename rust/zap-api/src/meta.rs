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

//! Packaged-scan JSON that `docker/zap_common.py`, `zap-baseline.py`,
//! `zap-full-scan.py`, and `zap-api-scan.py` call.
//!
//! Keys and value types follow the Java API classes in this repo:
//! `PassiveScanAPI`, `ActiveScanAPI.ScannerApiResponse`, `ContextAPI`,
//! `UsersAPI`, `ScriptAPI`, and `ExtensionScript`. This module does not
//! start a scan and does not add scan rules.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Value};

/// API failures for the packaged-scan routes. Messages match `Messages.properties`.
#[derive(Debug)]
pub(crate) enum MetaError {
    MissingParameter,
    IllegalParameter,
    DoesNotExist,
    AlreadyExists,
    BadExternalData,
    BadState,
    UserNotFound,
    UrlNotFound,
    UrlNotInContext,
    Internal,
}

/// `Plugin.AlertThreshold` names. `INSANE` is an attack strength, not a threshold.
const ALERT_THRESHOLDS: &[&str] = &["OFF", "DEFAULT", "LOW", "MEDIUM", "HIGH"];

/// `AddOn.Status.release` (`Status` enum name). The ported rules are release rules.
const RULE_STATUS: &str = "release";

/// `Category.INJECTION`. ascanrules v78 `CrlfInjectionScanRule` and
/// `XpathInjectionScanRule` both return this category.
const INJECTION: i32 = 4;

/// `Category.getAllNames()` length. Ids `0..=4` exist. Anything past that does not.
const CATEGORY_COUNT: i32 = 5;

/// Default scan policy name accepted by `getScanPolicyFromParams`.
const DEFAULT_POLICY: &str = "Default Policy";

/// `ExtensionScript` engine list entry: `languageName + " : " + engineName`.
/// The language name is the ECMAScript name ZAP looks up. The engine is Boa.
const ENGINE_LIST_ENTRY: &str = "ECMAScript : Boa";
const ENGINE_NAME: &str = "Boa";

/// `ExtensionScript.TYPE_HTTP_SENDER` and `TYPE_PROXY` are enableable.
/// `TYPE_STANDALONE` is registered with `isEnableable` false.
const ENABLEABLE_TYPES: &[&str] = &["httpsender", "proxy"];
const STANDALONE_TYPE: &str = "standalone";

/// Passive rule 10021. Name matches the pscanrules rule the baseline script prints.
const PSCAN_ID: i32 = 10021;
const PSCAN_NAME: &str = "X-Content-Type-Options Header Missing";

/// `UsernamePasswordAuthenticationCredentials` API name. Used for form (type 2)
/// and JSON (type 5) authentication.
const USERNAME_PASSWORD_TYPE: &str = "UsernamePasswordAuthenticationCredentials";

struct ActiveScanner {
    id: i32,
    name: &'static str,
    cwe_id: i32,
    wasc_id: i32,
    policy_id: i32,
    enabled: bool,
    alert_threshold: String,
    attack_strength: String,
}

struct ImportedUser {
    id: i32,
    name: String,
    enabled: bool,
    credentials: String,
}

struct ImportedContext {
    id: i32,
    name: String,
    include: Vec<Regex>,
    users: Vec<ImportedUser>,
}

struct LoadedScript {
    name: String,
    engine: String,
    enableable: bool,
    enabled: bool,
}

/// In-memory policy, contexts, and scripts for one API service.
pub(crate) struct MetaState {
    /// `PassiveScanAPI` stores this. The packaged scripts set it and do not read it back.
    #[allow(dead_code)]
    max_alerts_per_rule: i32,
    scanners: Vec<ActiveScanner>,
    contexts: Vec<ImportedContext>,
    next_context_id: i32,
    scripts: Vec<LoadedScript>,
}

impl MetaState {
    pub(crate) fn new() -> Self {
        Self {
            max_alerts_per_rule: 0,
            scanners: vec![
                // Ids, names, CWE, and WASC match the ported ascanrules.
                active(40003, "CRLF Injection", 113, 25),
                active(90021, "XPath Injection", 643, 39),
                active(40012, "Cross Site Scripting (Reflected)", 79, 8),
                active(40018, "SQL Injection", 89, 19),
                listed(0, "Directory Browsing", 548, 48, 0),
            ],
            contexts: Vec::new(),
            next_context_id: 1,
            scripts: Vec::new(),
        }
    }

    /// `PassiveScanAPI` scanner map: id, name, enabled, alertThreshold, quality, status.
    ///
    /// `getAlertThreshold(true)` returns `DEFAULT` until a threshold is stored.
    pub(crate) fn pscan_scanners(&self) -> Value {
        let scanners = [
            (PSCAN_ID, PSCAN_NAME),
            (10033, "Directory Browsing"),
            (10023, "Information Disclosure - Debug Error Messages"),
            (10027, "Information Disclosure - Suspicious Comments"),
            (10009, "In Page Banner Information Leak"),
            (10039, "X-Backend-Server Header Information Leak"),
            (10052, "X-ChromeLogger-Data (XCOLD) Header Information Leak"),
            (10056, "X-Debug-Token Information Leak"),
        ]
        .into_iter()
        .map(|(id, name)| {
            json!({
                "id": id.to_string(),
                "name": name,
                "enabled": "true",
                "alertThreshold": "DEFAULT",
                "quality": RULE_STATUS,
                "status": RULE_STATUS,
            })
        })
        .collect::<Vec<_>>();
        json!({ "scanners": scanners })
    }

    pub(crate) fn records_to_scan(&self) -> Value {
        // Passive scanning in this build runs on the proxy listener, so the
        // queue `PassiveScanAPI` reports is empty.
        json!({ "recordsToScan": "0" })
    }

    pub(crate) fn disable_all_tags(&self) -> Value {
        ok()
    }

    pub(crate) fn set_max_alerts_per_rule(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        let raw = required(params, "maxAlerts")?;
        self.max_alerts_per_rule = raw.parse().map_err(|_| MetaError::IllegalParameter)?;
        Ok(ok())
    }

    /// `ScannerApiResponse` fields. `dependencies` is a JSON array of id strings.
    pub(crate) fn ascan_scanners(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        self.policy(params)?;
        let category = category_filter(params)?;
        let scanners: Vec<Value> = self
            .scanners
            .iter()
            .filter(|scanner| category.is_none_or(|id| scanner.policy_id == id))
            .map(scanner_value)
            .collect();
        Ok(json!({ "scanners": scanners }))
    }

    pub(crate) fn enable_all_scanners(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        self.policy(params)?;
        for scanner in &mut self.scanners {
            scanner.enabled = true;
        }
        Ok(ok())
    }

    pub(crate) fn set_scanner_alert_threshold(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        self.policy(params)?;
        let id = required_i32(params, "id")?;
        if id < 0 {
            return Err(MetaError::IllegalParameter);
        }
        let threshold = required(params, "alertThreshold")?
            .trim()
            .to_ascii_uppercase();
        if !ALERT_THRESHOLDS.contains(&threshold.as_str()) {
            return Err(MetaError::DoesNotExist);
        }
        let scanner = self
            .scanners
            .iter_mut()
            .find(|scanner| scanner.id == id)
            .ok_or(MetaError::DoesNotExist)?;
        scanner.alert_threshold = threshold;
        // `AbstractPlugin.setEnabledFromLevel`: OFF disables the scanner.
        scanner.enabled = scanner.alert_threshold != "OFF";
        Ok(ok())
    }

    /// No active scan is running in this crate. `getActiveScan` throws
    /// `DOES_NOT_EXIST` when the id is missing and when it is unknown.
    pub(crate) fn scan_progress(
        &self,
        _params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        Err(MetaError::DoesNotExist)
    }

    /// Validate `scanAsUser` the way `ActiveScanAPI` does, then stop.
    ///
    /// A digit scan id is not returned. Phase 6 owns `ascan` `scan`, `status`,
    /// and `stop`. A made-up id would never reach 100.
    pub(crate) fn scan_as_user(
        &self,
        params: &HashMap<String, String>,
        recorded_urls: &[String],
    ) -> Result<Value, MetaError> {
        let context_id = required_i32(params, "contextId")?;
        let user_id = required_i32(params, "userId")?;
        let context = self
            .contexts
            .iter()
            .find(|context| context.id == context_id)
            .ok_or(MetaError::DoesNotExist)?;
        if !context.users.iter().any(|user| user.id == user_id) {
            return Err(MetaError::UserNotFound);
        }
        self.policy(params)?;
        if let Some(method) = params.get("method").map(|value| value.trim()) {
            if !method.is_empty() && http::Method::from_bytes(method.as_bytes()).is_err() {
                return Err(MetaError::IllegalParameter);
            }
        }
        let url = params.get("url").map(|value| value.trim()).unwrap_or("");
        if url.is_empty() {
            let in_tree = recorded_urls
                .iter()
                .any(|recorded| context.in_context(recorded));
            if !in_tree {
                return Err(MetaError::MissingParameter);
            }
            return Err(MetaError::Internal);
        }
        if !context.in_context(url) {
            return Err(MetaError::UrlNotInContext);
        }
        if !recorded_urls.iter().any(|recorded| recorded == url) {
            return Err(MetaError::UrlNotFound);
        }
        Err(MetaError::Internal)
    }

    /// `ContextAPI` `importContext`. Returns `{"contextId":"<id>"}`.
    pub(crate) fn import_context(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        let filename = required(params, "contextFile")?;
        let path = Path::new(filename);
        if !path.is_file() {
            return Err(MetaError::DoesNotExist);
        }
        let xml = fs::read_to_string(path).map_err(|_| MetaError::Internal)?;
        let context_xml = element_body(&xml, "context").ok_or(MetaError::Internal)?;
        let name = element_body(context_xml, "name")
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or(MetaError::BadExternalData)?
            .to_string();
        if self.contexts.iter().any(|context| context.name == name) {
            return Err(MetaError::BadExternalData);
        }
        let mut include = Vec::new();
        for pattern in element_bodies(context_xml, "incregexes") {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }
            include.push(Regex::new(pattern).map_err(|_| MetaError::BadExternalData)?);
        }
        let id = self.next_context_id;
        self.next_context_id += 1;
        let mut users = Vec::new();
        for encoded in element_bodies(context_xml, "user") {
            if let Some(user) = decode_user(encoded.trim()) {
                users.push(user);
            }
        }
        self.contexts.push(ImportedContext {
            id,
            name,
            include,
            users,
        });
        Ok(json!({ "contextId": id.to_string() }))
    }

    /// `contextList` items are plain name strings (`ApiResponseElement` values).
    pub(crate) fn context_list(&self) -> Value {
        let names: Vec<&str> = self
            .contexts
            .iter()
            .map(|context| context.name.as_str())
            .collect();
        json!({ "contextList": names })
    }

    /// `UsersAPI.buildResponseFromUser` keys. `credentials` is a JSON string.
    pub(crate) fn users_list(&self, params: &HashMap<String, String>) -> Result<Value, MetaError> {
        let contexts: Vec<&ImportedContext> = if let Some(raw) = params
            .get("contextId")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
        {
            let id: i32 = raw.parse().map_err(|_| MetaError::IllegalParameter)?;
            let context = self
                .contexts
                .iter()
                .find(|context| context.id == id)
                .ok_or(MetaError::DoesNotExist)?;
            vec![context]
        } else {
            self.contexts.iter().collect()
        };
        let mut users = Vec::new();
        for context in contexts {
            for user in &context.users {
                users.push(json!({
                    "name": user.name,
                    "id": user.id.to_string(),
                    "contextId": context.id.to_string(),
                    "enabled": user.enabled.to_string(),
                    "credentials": user.credentials,
                }));
            }
        }
        Ok(json!({ "usersList": users }))
    }

    /// One string per engine: `language : engine`.
    pub(crate) fn list_engines(&self) -> Value {
        json!({ "listEngines": [ENGINE_LIST_ENTRY] })
    }

    pub(crate) fn load_script(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        let script_name = required(params, "scriptName")?;
        let script_type = required(params, "scriptType")?;
        let script_engine = required(params, "scriptEngine")?;
        let file_name = required(params, "fileName")?;
        let enableable = if ENABLEABLE_TYPES.contains(&script_type) {
            true
        } else if script_type == STANDALONE_TYPE {
            false
        } else {
            return Err(MetaError::DoesNotExist);
        };
        if !is_boa_engine(script_engine) {
            return Err(MetaError::DoesNotExist);
        }
        let path = Path::new(file_name);
        if !path.is_file() {
            return Err(MetaError::DoesNotExist);
        }
        if let Some(charset) = params
            .get("charset")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
        {
            if !charset_known(charset) {
                return Err(MetaError::IllegalParameter);
            }
        }
        // Existence is the Java check. The file is not evaluated.
        fs::read(path).map_err(|_| MetaError::Internal)?;
        if self.scripts.iter().any(|script| script.name == script_name) {
            return Err(MetaError::AlreadyExists);
        }
        self.scripts.push(LoadedScript {
            name: script_name.to_string(),
            engine: script_engine.to_string(),
            enableable,
            enabled: true,
        });
        Ok(ok())
    }

    pub(crate) fn enable_script(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Value, MetaError> {
        let script_name = required(params, "scriptName")?;
        let script = self
            .scripts
            .iter_mut()
            .find(|script| script.name == script_name)
            .ok_or(MetaError::DoesNotExist)?;
        if !script.enableable {
            return Err(MetaError::IllegalParameter);
        }
        if script.engine.is_empty() {
            return Err(MetaError::BadState);
        }
        script.enabled = true;
        Ok(ok())
    }

    fn policy(&self, params: &HashMap<String, String>) -> Result<(), MetaError> {
        match params
            .get("scanPolicyName")
            .map(String::as_str)
            .filter(|value| !value.is_empty())
        {
            None => Ok(()),
            Some(DEFAULT_POLICY) => Ok(()),
            Some(_) => Err(MetaError::DoesNotExist),
        }
    }
}

impl ImportedContext {
    fn in_context(&self, url: &str) -> bool {
        self.include.iter().any(|pattern| pattern.is_match(url))
    }
}

fn active(id: i32, name: &'static str, cwe_id: i32, wasc_id: i32) -> ActiveScanner {
    listed(id, name, cwe_id, wasc_id, INJECTION)
}

fn listed(id: i32, name: &'static str, cwe_id: i32, wasc_id: i32, policy_id: i32) -> ActiveScanner {
    ActiveScanner {
        id,
        name,
        cwe_id,
        wasc_id,
        policy_id,
        enabled: true,
        alert_threshold: "DEFAULT".to_string(),
        attack_strength: "DEFAULT".to_string(),
    }
}

fn scanner_value(scanner: &ActiveScanner) -> Value {
    json!({
        "id": scanner.id.to_string(),
        "name": scanner.name,
        "cweId": scanner.cwe_id.to_string(),
        "wascId": scanner.wasc_id.to_string(),
        "attackStrength": scanner.attack_strength,
        "alertThreshold": scanner.alert_threshold,
        "policyId": scanner.policy_id.to_string(),
        "enabled": scanner.enabled.to_string(),
        "quality": RULE_STATUS,
        "status": RULE_STATUS,
        "allDependenciesAvailable": "true",
        "dependencies": [],
    })
}

fn category_filter(params: &HashMap<String, String>) -> Result<Option<i32>, MetaError> {
    match params
        .get("policyId")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
    {
        None => Ok(None),
        Some(value) => {
            let id: i32 = value.parse().map_err(|_| MetaError::IllegalParameter)?;
            if id < 0 {
                return Err(MetaError::IllegalParameter);
            }
            if id >= CATEGORY_COUNT {
                return Err(MetaError::DoesNotExist);
            }
            Ok(Some(id))
        }
    }
}

fn ok() -> Value {
    json!({ "Result": "OK" })
}

fn required<'a>(params: &'a HashMap<String, String>, key: &str) -> Result<&'a str, MetaError> {
    params
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(MetaError::MissingParameter)
}

fn required_i32(params: &HashMap<String, String>, key: &str) -> Result<i32, MetaError> {
    required(params, key)?
        .parse()
        .map_err(|_| MetaError::IllegalParameter)
}

fn is_boa_engine(name: &str) -> bool {
    name == ENGINE_NAME || name == ENGINE_LIST_ENTRY
}

fn charset_known(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "UTF-8" | "UTF8" | "US-ASCII" | "ASCII" | "ISO-8859-1" | "UTF-16" | "UTF-16BE" | "UTF-16LE"
    )
}

/// `User.decode`: `id;enabled;base64(name);authTypeId;credentials`.
///
/// Form (2) and JSON (5) credentials are `UsernamePasswordAuthenticationCredentials`,
/// encoded with `~` between the base64 username and password.
fn decode_user(encoded: &str) -> Option<ImportedUser> {
    let pieces: Vec<&str> = encoded.split(';').collect();
    if pieces.len() < 4 {
        return None;
    }
    let id: i32 = pieces[0].parse().ok()?;
    let enabled = pieces[1] == "true";
    let name = base64_utf8(pieces[2])?;
    let auth_type: i32 = pieces[3].parse().ok()?;
    if auth_type != 2 && auth_type != 5 {
        return None;
    }
    let encoded_credentials = pieces.get(4).copied().unwrap_or("");
    let (username, password) = if encoded_credentials.is_empty() || encoded_credentials == "AA==" {
        (String::new(), String::new())
    } else {
        let parts: Vec<&str> = encoded_credentials.split('~').collect();
        let username = base64_utf8(parts.first().copied().unwrap_or(""))?;
        let password = if parts.len() > 1 {
            base64_utf8(parts[1]).unwrap_or_default()
        } else {
            String::new()
        };
        (username, password)
    };
    let credentials = json!({
        "type": USERNAME_PASSWORD_TYPE,
        "username": username,
        "password": password,
    })
    .to_string();
    Some(ImportedUser {
        id,
        name,
        enabled,
        credentials,
    })
}

fn element_body<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    element_bodies(xml, tag).into_iter().next()
}

fn element_bodies<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let from = start + open.len();
        let Some(end) = rest[from..].find(&close) else {
            break;
        };
        out.push(&rest[from..from + end]);
        rest = &rest[from + end + close.len()..];
    }
    out
}

fn base64_utf8(input: &str) -> Option<String> {
    let bytes = base64_decode(input)?;
    String::from_utf8(bytes).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let (Some(&a), Some(&b), Some(&c), Some(&d)) =
            (chunk.first(), chunk.get(1), chunk.get(2), chunk.get(3))
        else {
            return None;
        };
        let a = val(a)?;
        let b = val(b)?;
        out.push((a << 2) | (b >> 4));
        if c != b'=' {
            let c = val(c)?;
            out.push((b << 4) | (c >> 2));
            if d != b'=' {
                let d = val(d)?;
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_alerts_per_rule_is_stored() {
        let mut meta = MetaState::new();
        let mut params = HashMap::new();
        params.insert("maxAlerts".to_string(), "10".to_string());
        let body = meta.set_max_alerts_per_rule(&params).unwrap();
        assert_eq!(body["Result"], "OK");
        assert_eq!(meta.max_alerts_per_rule, 10);
    }
}
