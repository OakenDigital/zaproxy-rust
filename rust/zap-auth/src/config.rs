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

//! The subset of a ZAP `.context` file this phase reads.
//!
//! Repeated `<incregexes>` and `<excregexes>` elements, optional form (type 2)
//! or JSON (type 5) authentication, and cookie session management (type 0).

use crate::auth::LoginKind;
use crate::Error;

/// Fields taken from a context XML document.
#[derive(Clone, Debug)]
pub struct ContextConfig {
    pub name: String,
    pub include_regexes: Vec<String>,
    pub exclude_regexes: Vec<String>,
    pub login: Option<LoginConfig>,
}

/// Login request stored under `<authentication><form>`.
#[derive(Clone, Debug)]
pub struct LoginConfig {
    pub kind: LoginKind,
    pub login_url: String,
    pub login_body: String,
    pub login_page_url: String,
}

impl ContextConfig {
    pub fn parse(xml: &str) -> Result<Self, Error> {
        let context = element_body(xml, "context")
            .ok_or_else(|| Error::Config("missing <context> element".to_string()))?;
        let name = element_body(context, "name")
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("context")
            .to_string();
        let include_regexes = tag_texts(context, "incregexes");
        let exclude_regexes = tag_texts(context, "excregexes");
        if let Some(session) = element_body(context, "session") {
            if let Some(kind) = element_body(session, "type") {
                if kind.trim() != "0" {
                    return Err(Error::Config(
                        "only cookie session management (type 0) is implemented".to_string(),
                    ));
                }
            }
        }
        let login = match element_body(context, "authentication") {
            Some(auth) => Some(parse_login(auth)?),
            None => None,
        };
        Ok(Self {
            name,
            include_regexes,
            exclude_regexes,
            login,
        })
    }
}

fn parse_login(auth: &str) -> Result<LoginConfig, Error> {
    let kind = match element_body(auth, "type").map(str::trim) {
        Some("2") => LoginKind::Form,
        Some("5") => LoginKind::Json,
        Some(other) => {
            return Err(Error::Config(format!(
                "authentication type {other} is not form (2) or JSON (5)"
            )));
        }
        None => {
            return Err(Error::Config(
                "authentication is missing <type>".to_string(),
            ));
        }
    };
    let form = element_body(auth, "form")
        .ok_or_else(|| Error::Config("authentication is missing <form>".to_string()))?;
    let login_url = required_text(form, "loginurl")?;
    let login_body = element_body(form, "loginbody")
        .map(decode_and_trim)
        .unwrap_or_default();
    let login_page_url = element_body(form, "loginpageurl")
        .map(decode_and_trim)
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| login_url.clone());
    if login_url.is_empty() {
        return Err(Error::Config("loginurl is empty".to_string()));
    }
    Ok(LoginConfig {
        kind,
        login_url,
        login_body,
        login_page_url,
    })
}

fn required_text(xml: &str, tag: &str) -> Result<String, Error> {
    element_body(xml, tag)
        .map(decode_and_trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| Error::Config(format!("missing <{tag}>")))
}

fn tag_texts(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        let text = decode_and_trim(&after[..end]);
        if !text.is_empty() {
            out.push(text);
        }
        rest = &after[end + close.len()..];
    }
    out
}

fn element_body<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(&xml[start..end])
}

fn decode_and_trim(text: &str) -> String {
    decode_entities(text).trim().to_string()
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}
