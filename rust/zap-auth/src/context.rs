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
// official OWASP ZAP build. Include and exclude matching follows
// `org.zaproxy.zap.model.Context`.

//! Context include and exclude regexes.
//!
//! A URL is in context when it matches an include regex and no exclude
//! regex. Patterns are full-string and ASCII case-insensitive, like Java
//! `Pattern.CASE_INSENSITIVE` plus `Matcher.matches`. The query string is
//! removed when `?` is not the first character.

use regex::RegexBuilder;

use crate::config::ContextConfig;
use crate::Error;

/// One ZAP context: include/exclude regexes and optional login config.
#[derive(Clone, Debug)]
pub struct Context {
    name: String,
    include_regexes: Vec<String>,
    exclude_regexes: Vec<String>,
    include: Vec<regex::Regex>,
    exclude: Vec<regex::Regex>,
    config: ContextConfig,
}

impl Context {
    /// Load a ZAP context XML document.
    pub fn from_zap_config(xml: &str) -> Result<Self, Error> {
        let config = ContextConfig::parse(xml)?;
        let include = compile_all(&config.include_regexes)?;
        let exclude = compile_all(&config.exclude_regexes)?;
        Ok(Self {
            name: config.name.clone(),
            include_regexes: config.include_regexes.clone(),
            exclude_regexes: config.exclude_regexes.clone(),
            include,
            exclude,
            config,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn include_regexes(&self) -> &[String] {
        &self.include_regexes
    }

    pub fn exclude_regexes(&self) -> &[String] {
        &self.exclude_regexes
    }

    pub(crate) fn config(&self) -> &ContextConfig {
        &self.config
    }

    /// Whether `url` matches an include regex. A null URL in ZAP is false;
    /// this takes the URL ZAP would test after stripping the query.
    pub fn is_included(&self, url: &str) -> bool {
        any_match(&self.include, url)
    }

    /// Whether `url` matches an exclude regex.
    pub fn is_excluded(&self, url: &str) -> bool {
        any_match(&self.exclude, url)
    }

    /// Included and not excluded. This is `Context.isInContext`.
    pub fn is_in_context(&self, url: &str) -> bool {
        self.is_included(url) && !self.is_excluded(url)
    }
}

fn any_match(patterns: &[regex::Regex], url: &str) -> bool {
    let url = strip_query(url).to_ascii_lowercase();
    patterns.iter().any(|pattern| pattern.is_match(&url))
}

fn strip_query(url: &str) -> &str {
    match url.find('?') {
        Some(index) if index > 0 => &url[..index],
        _ => url,
    }
}

fn compile_all(patterns: &[String]) -> Result<Vec<regex::Regex>, Error> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        // Java `Pattern.CASE_INSENSITIVE` without `UNICODE_CASE` folds ASCII
        // only. Lowercase both sides the same way. The regex crate's own
        // case-insensitive flag also folds non-ASCII letters.
        let lowered = pattern.to_ascii_lowercase();
        let anchored = format!(r"\A(?:{lowered})\z");
        let regex = RegexBuilder::new(&anchored)
            .build()
            .map_err(|source| Error::Regex {
                pattern: pattern.clone(),
                source,
            })?;
        compiled.push(regex);
    }
    Ok(compiled)
}
