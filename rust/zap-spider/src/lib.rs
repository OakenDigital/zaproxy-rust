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
// This file is a Rust derivative of the traditional spider in zaproxy/zap-extensions
// at spider-v0.18.0. It changes the language and the architecture (Apache License
// 2.0, section 4). It is not an official OWASP ZAP build. The Java add-on is not
// included. The AJAX spider is not included.

//! Traditional spider.
//!
//! Not an official OWASP ZAP build. The crawl follows spider 0.18.0: HTML,
//! forms, redirects, robots.txt, and sitemap.xml. A context, when set, is
//! the phase 5 include/exclude check. URLs outside that context are not
//! fetched.

#![forbid(unsafe_code)]

mod canon;
mod engine;
mod filter;
mod options;
mod parse;
mod sender;

pub use engine::Spider;
pub use options::SpiderOptions;
pub use sender::{DefaultSender, FetchResponse, SpiderSender};

/// Phase 9 surface printed by `zapd` at startup.
pub const PHASE9: &str =
    "traditional spider (spider 0.18.0): HTML, forms, robots.txt, sitemap.xml; AJAX spider is not included";

#[cfg(test)]
mod tests;
