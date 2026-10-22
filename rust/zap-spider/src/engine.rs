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
// This file is a Rust derivative of Spider and SpiderTask in spider 0.18.0.
// It is not an official OWASP ZAP build. Seeds are the start URL plus
// /robots.txt and /sitemap.xml. Out-of-context URLs are not fetched.

//! Host crawl. The fetched set is unordered.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::sync::Arc;

use zap_auth::Context;

use crate::canon::{canonicalize, host_of, root_file};
use crate::filter::FetchFilter;
use crate::options::SpiderOptions;
use crate::parse::{self, Found};
use crate::sender::SpiderSender;
use crate::PHASE9;

struct Job {
    url: String,
    method: String,
    body: String,
    depth: u32,
}

/// Traditional spider on one sender.
pub struct Spider {
    sender: Arc<dyn SpiderSender>,
    options: SpiderOptions,
}

impl Spider {
    pub fn new(sender: Arc<dyn SpiderSender>) -> Self {
        Self {
            sender,
            options: SpiderOptions::default(),
        }
    }

    pub fn with_options(sender: Arc<dyn SpiderSender>, options: SpiderOptions) -> Self {
        Self { sender, options }
    }

    pub fn describe(&self) -> &'static str {
        PHASE9
    }

    /// Fetch the seed and every in-scope URL the parsers find.
    ///
    /// `context` is the phase 5 include/exclude check. When it is set, a URL
    /// outside the context is not fetched, including `/robots.txt` and
    /// `/sitemap.xml` when those seeds are outside the context. Without a
    /// context, only the seed host is in scope.
    pub fn crawl(&self, seed: &str, context: Option<&Context>) -> Result<BTreeSet<String>, String> {
        let seed =
            canonicalize(seed, seed).ok_or_else(|| format!("seed is not an HTTP URL: {seed}"))?;
        let mut filter = FetchFilter::new(context.cloned());
        if let Some(host) = host_of(&seed) {
            filter.add_scope_host(&host);
        }
        let mut crawl = Crawl {
            queue: VecDeque::new(),
            seen: HashSet::new(),
            filter,
            options: &self.options,
            sender: self.sender.as_ref(),
        };
        crawl.enqueue(seed.clone(), "GET", String::new(), 0);
        crawl.seed_file(self.options.parse_robots_txt, &seed, "robots.txt");
        crawl.seed_file(self.options.parse_sitemap_xml, &seed, "sitemap.xml");
        crawl.run()
    }
}

struct Crawl<'a> {
    queue: VecDeque<Job>,
    seen: HashSet<(String, String)>,
    filter: FetchFilter,
    options: &'a SpiderOptions,
    sender: &'a dyn SpiderSender,
}

impl Crawl<'_> {
    fn seed_file(&mut self, enabled: bool, seed: &str, name: &str) {
        if !enabled {
            return;
        }
        let Some(url) = root_file(seed, name) else {
            return;
        };
        self.enqueue(url, "GET", String::new(), 0);
    }

    fn enqueue(&mut self, url: String, method: &str, body: String, depth: u32) {
        if self.options.max_depth != 0 && depth > self.options.max_depth {
            return;
        }
        if !self.filter.allows(&url) {
            return;
        }
        if self.seen.insert((method.to_string(), url.clone())) {
            self.queue.push_back(Job {
                url,
                method: method.to_string(),
                body,
                depth,
            });
        }
    }

    fn run(mut self) -> Result<BTreeSet<String>, String> {
        let mut fetched = BTreeSet::new();
        while let Some(job) = self.queue.pop_front() {
            let response = self
                .sender
                .fetch(&job.method, &job.url, job.body.as_bytes())?;
            fetched.insert(job.url.clone());
            for found in parse::parse(&job.url, &response, self.options) {
                let Found { url, method, body } = found;
                self.enqueue(url, &method, body, job.depth + 1);
            }
        }
        Ok(fetched)
    }
}
