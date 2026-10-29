// Copyright 2012-2018 The ZAP Development Team
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
// This file is a Rust derivative of pscanrules v70 (zaproxy/zap-extensions
// tag pscanrules-v70). It changes the language and the architecture
// (Apache License 2.0, section 4). It is not an official OWASP ZAP build.
// The Java add-on is not included.

//! Header and body information-disclosure rules that do not need a browser.
//!
//! Directory browsing (10033), debug errors (10023), suspicious comments
//! (10027), in-page banners (10009), X-Backend-Server (10039),
//! X-ChromeLogger-Data (10052), and X-Debug-Token (10056).

use std::sync::OnceLock;

use http::HeaderMap;
use regex::{Regex, RegexBuilder};
use zap_core::{HttpMessage, HttpResponse};
use zap_store::{Confidence, NewAlert, Risk};

use crate::scanner::PassiveScanner;
use crate::threshold::{AlertThreshold, ScannerState};

pub const DIRECTORY_BROWSING_ID: i32 = 10033;
pub const DIRECTORY_BROWSING_NAME: &str = "Directory Browsing";
pub const DEBUG_ERRORS_ID: i32 = 10023;
pub const DEBUG_ERRORS_NAME: &str = "Information Disclosure - Debug Error Messages";
pub const SUSPICIOUS_COMMENTS_ID: i32 = 10027;
pub const SUSPICIOUS_COMMENTS_NAME: &str = "Information Disclosure - Suspicious Comments";
pub const BANNER_ID: i32 = 10009;
pub const BANNER_NAME: &str = "In Page Banner Information Leak";
pub const BACKEND_SERVER_ID: i32 = 10039;
pub const BACKEND_SERVER_NAME: &str = "X-Backend-Server Header Information Leak";
pub const CHROME_LOGGER_ID: i32 = 10052;
pub const CHROME_LOGGER_NAME: &str = "X-ChromeLogger-Data (XCOLD) Header Information Leak";
pub const DEBUG_TOKEN_ID: i32 = 10056;
pub const DEBUG_TOKEN_NAME: &str = "X-Debug-Token Information Leak";

const COMMENT_WORDS: &[&str] = &[
    "TODO",
    "FIXME",
    "BUG",
    "BUGS",
    "XXX",
    "QUERY",
    "DB",
    "ADMIN",
    "ADMINISTRATOR",
    "USER",
    "USERNAME",
    "SELECT",
    "WHERE",
    "FROM",
    "LATER",
    "DEBUG",
];

/// Strings from pscanrules `xml/debug-error-messages.txt`, excluding comments.
const DEBUG_ERRORS: &[&str] = &[
    "Error Occurred While Processing Request",
    "Internal Server Error",
    "test page for apache",
    "failed to open stream: HTTP request failed!",
    "Parse error: parse error, unexpected T_VARIABLE",
    "The script whose uid is",
    "PHP Parse error",
    "PHP Warning",
    "PHP Error",
    "Warning: Cannot modify header information - headers already sent",
    "mysqli error is",
    "mysql error is",
    "404 SC_NOT_FOUND",
    "ASP.NET_SessionId",
    "servlet error:",
    "Under construction",
    "Welcome to Windows 2000 Internet Services",
    "welcome to iis 4.0",
    "Warning: Supplied argument is not a valid File-Handle resource",
    "Warning: Division by zero in",
    "Warning: SAFE MODE Restriction in effect.",
    "Error Message : Error loading required libraries.",
    "Fatal error: Call to undefined function",
    "access denied for user",
    "incorrect syntax near",
    "Unclosed quotation mark before the character string",
    "There seems to have been a problem with the",
    "customErrors mode",
    "This error page might contain sensitive information because ASP.NET",
];

fn alert(
    msg: &HttpMessage,
    plugin_id: i32,
    name: &str,
    risk: Risk,
    confidence: Confidence,
    cwe_id: i32,
    wasc_id: i32,
) -> NewAlert {
    NewAlert {
        plugin_id,
        name: name.to_string(),
        risk: risk.code(),
        confidence: confidence.code(),
        cwe_id,
        wasc_id,
        param: String::new(),
        url: msg.url(),
    }
}

fn response(msg: &HttpMessage) -> Option<&HttpResponse> {
    msg.response.as_ref()
}

fn body_text(response: &HttpResponse) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_text(headers: &HeaderMap) -> bool {
    let value = content_type(headers);
    ["text", "html", "javascript", "json", "xml"]
        .iter()
        .any(|token| value.contains(token))
}

fn is_javascript(headers: &HeaderMap) -> bool {
    content_type(headers).contains("javascript")
}

fn header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect()
}

fn regex(pattern: &str, case_insensitive: bool, dot_matches: bool) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(true)
        .dot_matches_new_line(dot_matches)
        .build()
        .expect("disclosure pattern")
}

fn apache_listing() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex("<title>Index of /[^<]+?</title>", false, true))
}

fn iis_listing() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex(
            "<pre><A\\s+HREF\\s*=\\s*\"/[^>]*\">\\[To Parent Directory\\]</A><br><br>",
            false,
            true,
        )
    })
}

fn comment_patterns() -> &'static Vec<Regex> {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        COMMENT_WORDS
            .iter()
            .map(|word| regex(&format!("\\b{word}\\b"), true, false))
            .collect()
    })
}

fn html_comment() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex("<!--.*?-->", false, true))
}

fn js_line_comment() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex("//.*", false, false))
}

fn js_block_comment() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex("/\\*.*?\\*/", false, true))
}

fn banner_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            "Tomcat/\\d\\.\\d\\.\\d{1,2}",
            "Apache/\\d\\.\\d\\.\\d{1,2}",
            "nginx/\\d\\.\\d{1,2}\\.\\d{1,2}",
            "Jetty://\\d\\.\\d{1,2}",
            "squid/\\d\\.\\d{1,2}",
        ]
        .into_iter()
        .map(|pattern| regex(pattern, true, false))
        .collect()
    })
}

macro_rules! passive_rule {
    ($type:ident, $id:expr, $name:expr, $method:ident) => {
        pub struct $type {
            state: ScannerState,
        }

        impl $type {
            pub fn new() -> Self {
                Self {
                    state: ScannerState::new(AlertThreshold::Default),
                }
            }
        }

        impl Default for $type {
            fn default() -> Self {
                Self::new()
            }
        }

        impl PassiveScanner for $type {
            fn plugin_id(&self) -> i32 {
                $id
            }

            fn name(&self) -> &'static str {
                $name
            }

            fn set_threshold(&self, threshold: AlertThreshold) {
                self.state.set_threshold(threshold);
            }

            fn is_enabled(&self) -> bool {
                self.state.is_enabled()
            }

            fn scan_http_response(&self, msg: &HttpMessage) -> Vec<NewAlert> {
                self.$method(msg)
            }
        }
    };
}

passive_rule!(
    DirectoryBrowsingScanRule,
    DIRECTORY_BROWSING_ID,
    DIRECTORY_BROWSING_NAME,
    scan_directory
);
passive_rule!(
    DebugErrorsScanRule,
    DEBUG_ERRORS_ID,
    DEBUG_ERRORS_NAME,
    scan_debug
);
passive_rule!(
    SuspiciousCommentsScanRule,
    SUSPICIOUS_COMMENTS_ID,
    SUSPICIOUS_COMMENTS_NAME,
    scan_comments
);
passive_rule!(InPageBannerScanRule, BANNER_ID, BANNER_NAME, scan_banner);
passive_rule!(
    XBackendServerScanRule,
    BACKEND_SERVER_ID,
    BACKEND_SERVER_NAME,
    scan_backend
);
passive_rule!(
    XChromeLoggerScanRule,
    CHROME_LOGGER_ID,
    CHROME_LOGGER_NAME,
    scan_chrome
);
passive_rule!(
    XDebugTokenScanRule,
    DEBUG_TOKEN_ID,
    DEBUG_TOKEN_NAME,
    scan_debug_token
);

impl DirectoryBrowsingScanRule {
    fn scan_directory(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        let body = body_text(response);
        if apache_listing().find(&body).is_none() && iis_listing().find(&body).is_none() {
            return Vec::new();
        }
        vec![alert(
            msg,
            DIRECTORY_BROWSING_ID,
            DIRECTORY_BROWSING_NAME,
            Risk::Medium,
            Confidence::Medium,
            548,
            16,
        )]
    }
}

impl DebugErrorsScanRule {
    fn scan_debug(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        if response.body.is_empty() || !is_text(&response.headers) {
            return Vec::new();
        }
        if self.state.resolved() != AlertThreshold::Low && is_javascript(&response.headers) {
            return Vec::new();
        }
        let lower = body_text(response).to_lowercase();
        if DEBUG_ERRORS
            .iter()
            .any(|needle| lower.contains(&needle.to_lowercase()))
        {
            return vec![alert(
                msg,
                DEBUG_ERRORS_ID,
                DEBUG_ERRORS_NAME,
                Risk::Low,
                Confidence::Medium,
                1295,
                13,
            )];
        }
        Vec::new()
    }
}

impl SuspiciousCommentsScanRule {
    fn scan_comments(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        if response.body.is_empty()
            || !is_text(&response.headers)
            || content_type(&response.headers).contains("font")
        {
            return Vec::new();
        }
        let body = body_text(response);
        let mut comments = Vec::new();
        let mut html_confidence = false;
        if is_javascript(&response.headers) {
            comments.extend(js_comments(&body));
        } else {
            let html: Vec<String> = html_comment()
                .find_iter(&body)
                .map(|item| item.as_str().to_string())
                .collect();
            if !html.is_empty() {
                html_confidence = true;
                comments.extend(html);
            }
            for script in script_bodies(&body) {
                comments.extend(js_comments(&script));
            }
        }
        let confidence = if html_confidence {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        comment_patterns()
            .iter()
            .filter(|pattern| comments.iter().any(|comment| pattern.is_match(comment)))
            .map(|_| {
                alert(
                    msg,
                    SUSPICIOUS_COMMENTS_ID,
                    SUSPICIOUS_COMMENTS_NAME,
                    Risk::Informational,
                    confidence,
                    615,
                    13,
                )
            })
            .collect()
    }
}

impl InPageBannerScanRule {
    fn scan_banner(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        let status = response.status;
        let error = status.is_client_error() || status.is_server_error();
        let low_success = self.state.resolved() == AlertThreshold::Low && status.is_success();
        if !error && !low_success {
            return Vec::new();
        }
        let body = body_text(response);
        if banner_patterns()
            .iter()
            .any(|pattern| pattern.is_match(&body))
        {
            return vec![alert(
                msg,
                BANNER_ID,
                BANNER_NAME,
                Risk::Low,
                Confidence::High,
                497,
                13,
            )];
        }
        Vec::new()
    }
}

impl XBackendServerScanRule {
    fn scan_backend(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        header_values(&response.headers, "x-backend-server")
            .into_iter()
            .map(|_| {
                alert(
                    msg,
                    BACKEND_SERVER_ID,
                    BACKEND_SERVER_NAME,
                    Risk::Low,
                    Confidence::Medium,
                    497,
                    13,
                )
            })
            .collect()
    }
}

impl XChromeLoggerScanRule {
    fn scan_chrome(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        let mut count = header_values(&response.headers, "x-chromelogger-data").len();
        count += header_values(&response.headers, "x-chromephp-data").len();
        (0..count)
            .map(|_| {
                alert(
                    msg,
                    CHROME_LOGGER_ID,
                    CHROME_LOGGER_NAME,
                    Risk::Medium,
                    Confidence::High,
                    532,
                    13,
                )
            })
            .collect()
    }
}

impl XDebugTokenScanRule {
    fn scan_debug_token(&self, msg: &HttpMessage) -> Vec<NewAlert> {
        let Some(response) = response(msg) else {
            return Vec::new();
        };
        let present = !header_values(&response.headers, "x-debug-token-link").is_empty()
            || !header_values(&response.headers, "x-debug-token").is_empty();
        if present {
            vec![alert(
                msg,
                DEBUG_TOKEN_ID,
                DEBUG_TOKEN_NAME,
                Risk::Low,
                Confidence::High,
                489,
                13,
            )]
        } else {
            Vec::new()
        }
    }
}

fn js_comments(content: &str) -> Vec<String> {
    if !content.contains("//") && !content.contains("/*") {
        return Vec::new();
    }
    js_line_comment()
        .find_iter(content)
        .chain(js_block_comment().find_iter(content))
        .map(|item| item.as_str().to_string())
        .collect()
}

fn script_bodies(body: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let lower = body.to_ascii_lowercase();
    let mut rest = body;
    let mut lower_rest = lower.as_str();
    while let Some(start) = lower_rest.find("<script") {
        let Some(open_end) = lower_rest[start..].find('>') else {
            break;
        };
        let content_from = start + open_end + 1;
        let Some(close) = lower_rest[content_from..].find("</script>") else {
            break;
        };
        bodies.push(rest[content_from..content_from + close].to_string());
        let next = content_from + close + "</script>".len();
        rest = &rest[next..];
        lower_rest = &lower_rest[next..];
    }
    bodies
}
