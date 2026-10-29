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
// This file is a Rust derivative of the ZAP AJAX spider crawl loop, reduced
// to HTTP fetches. It is not an official OWASP ZAP build. A browser runtime
// is not included.

//! Seed crawl. The recorded set is the URLs that were fetched.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::sync::Arc;

use zap_auth::Context;

use crate::canon::{self, host_of};
use crate::parse;
use crate::sender::AjaxSender;
use crate::SUMMARY;

/// Default from spider `SpiderParam`: a URL at this depth is fetched.
const DEFAULT_MAX_DEPTH: u32 = 5;

struct Job {
    url: String,
    depth: u32,
}

/// AJAX spider on one sender. No browser is started.
pub struct AjaxSpider {
    sender: Arc<dyn AjaxSender>,
    max_depth: u32,
}

impl AjaxSpider {
    pub fn new(sender: Arc<dyn AjaxSender>) -> Self {
        Self {
            sender,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    pub fn with_max_depth(sender: Arc<dyn AjaxSender>, max_depth: u32) -> Self {
        Self { sender, max_depth }
    }

    pub fn describe(&self) -> &'static str {
        SUMMARY
    }

    /// Absolute HTTP(S) form of `seed`, with the fragment removed.
    pub fn normalize_seed(seed: &str) -> Result<String, String> {
        let seed = seed.trim();
        canon::resolve(seed, seed).ok_or_else(|| format!("seed is not an HTTP URL: {seed}"))
    }

    /// Fetch the seed and every in-scope URL found in HTML links and inline
    /// script string literals.
    ///
    /// `context`, when set, is the phase 5 include/exclude check. A URL
    /// outside that context is not fetched and is not recorded. Without a
    /// context, only the seed host is in scope. The returned set is the
    /// crawled URLs.
    pub fn crawl(&self, seed: &str, context: Option<&Context>) -> Result<BTreeSet<String>, String> {
        let seed = Self::normalize_seed(seed)?;
        let host = host_of(&seed).ok_or_else(|| format!("seed is not an HTTP URL: {seed}"))?;
        let mut crawl = Crawl {
            queue: VecDeque::new(),
            seen: HashSet::new(),
            recorded: BTreeSet::new(),
            scope: Scope { context, host },
            max_depth: self.max_depth,
            sender: self.sender.as_ref(),
        };
        crawl.enqueue(seed, 0);
        crawl.run()
    }
}

struct Scope<'a> {
    context: Option<&'a Context>,
    host: String,
}

impl Scope<'_> {
    fn allows(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return false;
        }
        if let Some(context) = self.context {
            return context.is_in_context(url);
        }
        host_of(url).as_deref() == Some(self.host.as_str())
    }
}

struct Crawl<'a> {
    queue: VecDeque<Job>,
    seen: HashSet<String>,
    recorded: BTreeSet<String>,
    scope: Scope<'a>,
    max_depth: u32,
    sender: &'a dyn AjaxSender,
}

impl Crawl<'_> {
    fn enqueue(&mut self, url: String, depth: u32) {
        if self.max_depth != 0 && depth > self.max_depth {
            return;
        }
        if !self.scope.allows(&url) {
            return;
        }
        if self.seen.insert(url.clone()) {
            self.queue.push_back(Job { url, depth });
        }
    }

    fn run(mut self) -> Result<BTreeSet<String>, String> {
        while let Some(job) = self.queue.pop_front() {
            let response = self.sender.fetch(&job.url)?;
            self.recorded.insert(job.url.clone());
            for url in parse::links(&job.url, &response) {
                self.enqueue(url, job.depth + 1);
            }
        }
        Ok(self.recorded)
    }
}
