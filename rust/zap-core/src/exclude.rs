// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
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
// official OWASP ZAP build. Full-string matching follows Paros
// `ProxyServer.excludeUrl` (`Matcher.matches`, case-insensitive).

//! Exclude-URL patterns. A match skips history and the listener chain.

use regex::RegexBuilder;
use thiserror::Error;

/// A pattern failed to compile.
#[derive(Debug, Error)]
#[error("invalid exclude regex `{pattern}`: {source}")]
pub struct ExcludeError {
    pub pattern: String,
    #[source]
    pub source: regex::Error,
}

/// Case-insensitive patterns matched against the entire URL.
#[derive(Clone, Debug, Default)]
pub struct ExcludeList {
    patterns: Vec<regex::Regex>,
}

impl ExcludeList {
    /// Compile `patterns`. Each one must match the whole URL, ASCII case-insensitive.
    pub fn try_new<I, S>(patterns: I) -> Result<Self, ExcludeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut compiled = Vec::new();
        for pattern in patterns {
            let pattern = pattern.as_ref();
            let anchored = format!(r"\A(?:{pattern})\z");
            let regex = RegexBuilder::new(&anchored)
                .case_insensitive(true)
                .build()
                .map_err(|source| ExcludeError {
                    pattern: pattern.to_string(),
                    source,
                })?;
            compiled.push(regex);
        }
        Ok(Self { patterns: compiled })
    }

    /// Whether `url` matches any exclude pattern.
    pub fn excludes(&self, url: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(url))
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::ExcludeList;

    #[test]
    fn exclude_is_full_match_and_case_insensitive() {
        let list = ExcludeList::try_new([
            r"http://example\.test/secret",
            r"http://example\.test/logout\?.*",
        ])
        .unwrap();

        assert!(list.excludes("http://example.test/secret"));
        assert!(list.excludes("HTTP://EXAMPLE.TEST/SECRET"));
        assert!(list.excludes("http://example.test/logout?next=1"));
        assert!(!list.excludes("http://example.test/secret/more"));
        assert!(
            !list.excludes("http://example.test/app/secret"),
            "a substring is not enough; the pattern must cover the whole URL"
        );
        assert!(!list.excludes("http://example.test/visible"));
    }

    #[test]
    fn bare_token_does_not_exclude_a_longer_url() {
        let list = ExcludeList::try_new(["logout"]).unwrap();
        assert!(!list.excludes("http://example.test/logout"));
        assert!(list.excludes("logout"));
    }

    #[test]
    fn invalid_pattern_is_an_error() {
        let err = ExcludeList::try_new(["("]).unwrap_err();
        assert_eq!(err.pattern, "(");
    }
}
