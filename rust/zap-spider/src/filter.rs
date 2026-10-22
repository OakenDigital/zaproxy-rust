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
// This file is a Rust derivative of DefaultFetchFilter in spider 0.18.0.
// It is not an official OWASP ZAP build.

//! Fetch filter: HTTP(S), then context or seed host.

use regex::Regex;
use zap_auth::Context;

use crate::canon::host_of;

pub struct FetchFilter {
    context: Option<Context>,
    scopes: Vec<Regex>,
}

impl FetchFilter {
    pub fn new(context: Option<Context>) -> Self {
        Self {
            context,
            scopes: Vec::new(),
        }
    }

    /// Remember a seed host. ZAP stores the host as a full-match regex.
    pub fn add_scope_host(&mut self, host: &str) {
        let pattern = format!(r"\A(?i){host}\z");
        if let Ok(regex) = Regex::new(&pattern) {
            self.scopes.push(regex);
        }
    }

    pub fn allows(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return false;
        }
        if let Some(context) = &self.context {
            return context.is_in_context(url);
        }
        let Some(host) = host_of(url) else {
            return false;
        };
        self.scopes.iter().any(|scope| scope.is_match(&host))
    }
}
