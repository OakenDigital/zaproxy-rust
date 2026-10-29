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
// This file is a Rust derivative of the spiderAjax idea in
// zaproxy/zap-extensions at spiderAjax-v23.29.0. It changes the language
// and the architecture (Apache License 2.0, section 4). It is not an
// official OWASP ZAP build. The Java add-on is not included. A browser
// runtime is not included: Chrome, Firefox, WebDriver, and Crawljax are
// not started, and this crate does not shell out.

//! AJAX spider without a browser runtime.
//!
//! Not an official OWASP ZAP build. spiderAjax 23.29.0 drives a browser.
//! This crate does not. It accepts a seed URL, fetches it over HTTP, and
//! records the in-scope URLs it finds in HTML links and in inline `<script>`
//! string literals. Context include and exclude regexes are the phase 5
//! check. Fragment routes are not clicked.

#![forbid(unsafe_code)]

mod canon;
mod engine;
mod parse;
mod sender;

pub use engine::AjaxSpider;
pub use sender::{AjaxSender, DefaultSender, FetchResponse};

/// Crawl surface printed by `zapd`. A browser runtime is not included.
pub const SUMMARY: &str =
    "HTML links and inline script string literals; a browser runtime is not included";

#[cfg(test)]
mod tests;
