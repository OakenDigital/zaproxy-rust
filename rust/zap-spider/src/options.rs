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
// This file is a Rust derivative of SpiderParam in spider 0.18.0. It is not
// an official OWASP ZAP build.

//! Defaults from `SpiderParam` in spider 0.18.0.
//!
//! SVN, Git, and `.DS_Store` parsing are off. Max depth is 5. A max depth of
//! 0 is unlimited (`SpiderParam.UNLIMITED_DEPTH`). A URL at exactly
//! `max_depth` is fetched. Deeper URLs are not.

/// Options that change which URLs the spider fetches.
#[derive(Clone, Debug)]
pub struct SpiderOptions {
    pub max_depth: u32,
    pub parse_comments: bool,
    pub parse_robots_txt: bool,
    pub parse_sitemap_xml: bool,
    pub process_form: bool,
    pub post_form: bool,
}

impl Default for SpiderOptions {
    fn default() -> Self {
        Self {
            max_depth: 5,
            parse_comments: true,
            parse_robots_txt: true,
            parse_sitemap_xml: true,
            process_form: true,
            post_form: true,
        }
    }
}
