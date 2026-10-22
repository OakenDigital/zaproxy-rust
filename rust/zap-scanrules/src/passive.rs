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
// These rules follow pscanrules v70. The Java add-on is not included.
// This is not an official OWASP ZAP build.

//! Passive rules that read response headers and cookie attributes.

use zap_core::HttpMessage;
use zap_pscan::{AlertThreshold, PassiveScanner, ScannerState};
use zap_store::{Confidence, NewAlert, Risk};

use crate::cookies::{attribute_value, cookie_name, has_attribute, is_expired};
use crate::msg::{self, alert};

const COOKIE_HEADERS: [&str; 2] = ["set-cookie", "set-cookie2"];

macro_rules! scanner {
    ($ty:ident) => {
        impl PassiveScanner for $ty {
            fn plugin_id(&self) -> i32 {
                Self::ID
            }

            fn name(&self) -> &'static str {
                Self::NAME
            }

            fn set_threshold(&self, threshold: AlertThreshold) {
                self.state.set_threshold(threshold);
            }

            fn is_enabled(&self) -> bool {
                self.state.is_enabled()
            }

            fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
                if !self.is_enabled() {
                    return Vec::new();
                }
                self.scan(msg)
            }
        }

        impl Default for $ty {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

fn rule(state: AlertThreshold) -> ScannerState {
    ScannerState::new(state)
}

pub const COOKIE_HTTPONLY_ID: i32 = 10010;
pub const COOKIE_SECURE_ID: i32 = 10011;
pub const CONTENT_TYPE_ID: i32 = 10019;
pub const CLICKJACK_ID: i32 = 10020;
pub const SERVER_HEADER_ID: i32 = 10036;
pub const X_POWERED_BY_ID: i32 = 10037;
pub const COOKIE_SAMESITE_ID: i32 = 10054;
pub const X_ASPNET_ID: i32 = 10061;

pub struct CookieHttpOnlyScanRule {
    state: ScannerState,
}

impl CookieHttpOnlyScanRule {
    pub const ID: i32 = COOKIE_HTTPONLY_ID;
    pub const NAME: &'static str = "Cookie No HttpOnly Flag";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        cookie_alerts(msg, "httponly", Self::ID, Self::NAME, 1004)
    }
}
scanner!(CookieHttpOnlyScanRule);

pub struct CookieSecureFlagScanRule {
    state: ScannerState,
}

impl CookieSecureFlagScanRule {
    pub const ID: i32 = COOKIE_SECURE_ID;
    pub const NAME: &'static str = "Cookie Without Secure Flag";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        if !msg::is_https(msg) {
            return Vec::new();
        }
        cookie_alerts(msg, "secure", Self::ID, Self::NAME, 614)
    }
}
scanner!(CookieSecureFlagScanRule);

pub struct CookieSameSiteScanRule {
    state: ScannerState,
}

impl CookieSameSiteScanRule {
    pub const ID: i32 = COOKIE_SAMESITE_ID;
    pub const NAME: &'static str = "Cookie without SameSite Attribute";
    pub const NONE_NAME: &'static str = "Cookie with SameSite Attribute None";
    pub const BAD_NAME: &'static str = "Cookie with Invalid SameSite Attribute";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let high = self.state.resolved() == AlertThreshold::High;
        let mut alerts = Vec::new();
        for cookie in cookies(msg) {
            if is_expired(&cookie) {
                continue;
            }
            let name = match attribute_value(&cookie, "samesite").as_deref() {
                None => Self::NAME,
                Some(value) if value.eq_ignore_ascii_case("none") && !high => Self::NONE_NAME,
                Some(value)
                    if !value.eq_ignore_ascii_case("strict")
                        && !value.eq_ignore_ascii_case("lax")
                        && !value.eq_ignore_ascii_case("none") =>
                {
                    Self::BAD_NAME
                }
                Some(_) => continue,
            };
            alerts.push(cookie_alert(msg, &cookie, Self::ID, name, 1275));
        }
        alerts
    }
}
scanner!(CookieSameSiteScanRule);

pub struct ContentTypeMissingScanRule {
    state: ScannerState,
}

impl ContentTypeMissingScanRule {
    pub const ID: i32 = CONTENT_TYPE_ID;
    pub const NAME: &'static str = "Content-Type Header Missing";
    pub const EMPTY_NAME: &'static str = "Content-Type Header Empty";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        if msg::body(msg).is_empty() {
            return Vec::new();
        }
        let Some(headers) = msg::response_headers(msg) else {
            return Vec::new();
        };
        let values = msg::header_values(headers, "content-type");
        if values.is_empty() {
            return vec![content_type_alert(msg, Self::NAME)];
        }
        values
            .into_iter()
            .filter(|value| value.is_empty())
            .map(|_| content_type_alert(msg, Self::EMPTY_NAME))
            .collect()
    }
}
scanner!(ContentTypeMissingScanRule);

pub struct AntiClickjackingScanRule {
    state: ScannerState,
}

impl AntiClickjackingScanRule {
    pub const ID: i32 = CLICKJACK_ID;
    pub const NAME: &'static str = "Anti-clickjacking Header";
    pub const MISSING_NAME: &'static str = "Missing Anti-clickjacking Header";
    pub const MULTIPLE_NAME: &'static str = "Multiple X-Frame-Options Header Entries";
    pub const META_NAME: &'static str =
        "X-Frame-Options Defined via META (Non-compliant with Spec)";
    pub const MALFORMED_NAME: &'static str = "X-Frame-Options Setting Malformed";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let low = self.state.resolved() == AlertThreshold::Low;
        let Some(headers) = msg::response_headers(msg) else {
            return Vec::new();
        };
        if !low && !msg::is_html(headers) {
            return Vec::new();
        }
        if msg::body(msg).is_empty() || !msg::is_text(headers) {
            return Vec::new();
        }
        if let Some(status) = msg::status(msg) {
            if !low && msg::is_error_or_redirect(status) {
                return Vec::new();
            }
        }
        let csp = msg::header_values(headers, "content-security-policy").join(" ");
        let in_csp = csp.to_ascii_lowercase().contains("frame-ancestors");
        if in_csp && !low {
            return Vec::new();
        }
        let risk = if in_csp {
            Risk::Low.code()
        } else {
            Risk::Medium.code()
        };
        let mut alerts = Vec::new();
        let xfo = msg::header_values(headers, "x-frame-options");
        if xfo.is_empty() {
            alerts.push(click_alert(msg, Self::MISSING_NAME, risk));
        } else {
            for value in &xfo {
                let lower = value.to_ascii_lowercase();
                if !lower.contains("deny") && !lower.contains("sameorigin") {
                    alerts.push(click_alert(msg, Self::MALFORMED_NAME, risk));
                }
            }
            if xfo.len() > 1 {
                alerts.push(click_alert(msg, Self::MULTIPLE_NAME, risk));
            }
        }
        if meta_xfo(msg::body(msg)) {
            alerts.push(click_alert(msg, Self::META_NAME, risk));
        }
        alerts
    }
}
scanner!(AntiClickjackingScanRule);

pub struct ServerHeaderInfoLeakScanRule {
    state: ScannerState,
}

impl ServerHeaderInfoLeakScanRule {
    pub const ID: i32 = SERVER_HEADER_ID;
    pub const NAME: &'static str = "HTTP Server Response Header";
    pub const VERSION_NAME: &'static str =
        "Server Leaks Version Information via \"Server\" HTTP Response Header Field";
    pub const PRESENT_NAME: &'static str =
        "Server Leaks its Webserver Application via \"Server\" HTTP Response Header Field";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let low = self.state.resolved() == AlertThreshold::Low;
        let Some(headers) = msg::response_headers(msg) else {
            return Vec::new();
        };
        msg::header_values(headers, "server")
            .into_iter()
            .filter_map(|value| {
                if value.chars().any(|ch| ch.is_ascii_digit()) {
                    Some(server_alert(msg, Self::VERSION_NAME, Risk::Low.code()))
                } else if low {
                    Some(server_alert(
                        msg,
                        Self::PRESENT_NAME,
                        Risk::Informational.code(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }
}
scanner!(ServerHeaderInfoLeakScanRule);

pub struct XPoweredByHeaderInfoLeakScanRule {
    state: ScannerState,
}

impl XPoweredByHeaderInfoLeakScanRule {
    pub const ID: i32 = X_POWERED_BY_ID;
    pub const NAME: &'static str =
        "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(headers) = msg::response_headers(msg) else {
            return Vec::new();
        };
        if msg::header_values(headers, "x-powered-by").is_empty() {
            return Vec::new();
        }
        vec![alert(
            Self::ID,
            Self::NAME,
            Risk::Low.code(),
            Confidence::Medium.code(),
            497,
            13,
            "",
            &msg.url(),
        )]
    }
}
scanner!(XPoweredByHeaderInfoLeakScanRule);

pub struct XAspNetVersionScanRule {
    state: ScannerState,
}

impl XAspNetVersionScanRule {
    pub const ID: i32 = X_ASPNET_ID;
    pub const NAME: &'static str = "X-AspNet-Version Response Header";

    pub fn new() -> Self {
        Self {
            state: rule(AlertThreshold::Default),
        }
    }

    fn scan(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(headers) = msg::response_headers(msg) else {
            return Vec::new();
        };
        ["x-aspnet-version", "x-aspnetmvc-version"]
            .into_iter()
            .filter(|name| !msg::header_values(headers, name).is_empty())
            .map(|_| {
                alert(
                    Self::ID,
                    Self::NAME,
                    Risk::Low.code(),
                    Confidence::High.code(),
                    933,
                    14,
                    "",
                    &msg.url(),
                )
            })
            .collect()
    }
}
scanner!(XAspNetVersionScanRule);

fn cookies(msg: &HttpMessage) -> Vec<String> {
    let Some(headers) = msg::response_headers(msg) else {
        return Vec::new();
    };
    COOKIE_HEADERS
        .into_iter()
        .flat_map(|name| msg::header_values(headers, name))
        .collect()
}

fn cookie_alerts(
    msg: &HttpMessage,
    attribute: &str,
    plugin_id: i32,
    name: &str,
    cwe: i32,
) -> Vec<NewAlert> {
    cookies(msg)
        .into_iter()
        .filter(|cookie| !has_attribute(cookie, attribute) && !is_expired(cookie))
        .map(|cookie| cookie_alert(msg, &cookie, plugin_id, name, cwe))
        .collect()
}

fn cookie_alert(msg: &HttpMessage, cookie: &str, plugin_id: i32, name: &str, cwe: i32) -> NewAlert {
    alert(
        plugin_id,
        name,
        Risk::Low.code(),
        Confidence::Medium.code(),
        cwe,
        13,
        &cookie_name(cookie),
        &msg.url(),
    )
}

fn content_type_alert(msg: &HttpMessage, name: &str) -> NewAlert {
    alert(
        CONTENT_TYPE_ID,
        name,
        Risk::Informational.code(),
        Confidence::Medium.code(),
        345,
        12,
        "content-type",
        &msg.url(),
    )
}

fn click_alert(msg: &HttpMessage, name: &str, risk: i32) -> NewAlert {
    alert(
        CLICKJACK_ID,
        name,
        risk,
        Confidence::Medium.code(),
        1021,
        15,
        "x-frame-options",
        &msg.url(),
    )
}

fn server_alert(msg: &HttpMessage, name: &str, risk: i32) -> NewAlert {
    alert(
        SERVER_HEADER_ID,
        name,
        risk,
        Confidence::High.code(),
        497,
        13,
        "",
        &msg.url(),
    )
}

fn meta_xfo(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("<meta") {
        let start = search + rel;
        let end = lower[start..]
            .find('>')
            .map(|index| start + index + 1)
            .unwrap_or(lower.len());
        let tag = &lower[start..end];
        if tag.contains("http-equiv") && tag.contains("x-frame-options") {
            return true;
        }
        search = end;
        if search >= lower.len() {
            break;
        }
    }
    false
}
