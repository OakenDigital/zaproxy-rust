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
// official OWASP ZAP build.

//! Traditional spider and active scan started from the desktop page.
//!
//! The AJAX spider is not included. Responses from the spider are stored
//! and passed through the same passive-scan listener the proxy uses, so
//! those alerts show up in the session. Active-scan alerts are written by
//! the engine into that same session.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use zap_ascan::{Engine, ScanOptions};
use zap_core::{HttpMessage, HttpResponse, ProxyListener};
use zap_pscan::PassiveScanListener;
use zap_spider::{DefaultSender as SpiderSender, FetchResponse, Spider};
use zap_store::Session;

/// One crawl or scan the page can show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobView {
    pub state: &'static str,
    pub url: String,
    pub detail: String,
}

impl JobView {
    pub fn line(&self, label: &str) -> String {
        match self.state {
            "running" => format!("{label}: running {}", self.url),
            "finished" => format!("{label}: finished {}", self.detail),
            "failed" => format!("{label}: failed {}", self.detail),
            _ => format!("{label}: idle"),
        }
    }
}

struct Job {
    state: &'static str,
    url: String,
    detail: String,
}

impl Job {
    fn idle() -> Self {
        Self {
            state: "idle",
            url: String::new(),
            detail: String::new(),
        }
    }

    fn view(&self) -> JobView {
        JobView {
            state: self.state,
            url: self.url.clone(),
            detail: self.detail.clone(),
        }
    }
}

/// Spider and active scan for one desktop session.
pub struct ScanControls {
    spider: Arc<Spider>,
    engine: Arc<Engine>,
    spider_job: Arc<Mutex<Job>>,
    ascan_job: Arc<Mutex<Job>>,
}

impl ScanControls {
    /// Build both senders on the current Tokio runtime.
    pub fn start(session: Arc<Session>, pscan: Arc<PassiveScanListener>) -> Result<Self, String> {
        let spider_sender = Arc::new(RecordingSender {
            inner: SpiderSender::from_current()?,
            session: Arc::clone(&session),
            pscan,
        });
        let ascan_sender = zap_ascan::DefaultSender::from_current()?;
        Ok(Self {
            spider: Arc::new(Spider::new(spider_sender)),
            engine: Arc::new(Engine::new(session, Arc::new(ascan_sender))),
            spider_job: Arc::new(Mutex::new(Job::idle())),
            ascan_job: Arc::new(Mutex::new(Job::idle())),
        })
    }

    pub fn spider(&self) -> JobView {
        self.spider_job.lock().expect("spider job").view()
    }

    pub fn active_scan(&self) -> JobView {
        self.ascan_job.lock().expect("ascan job").view()
    }

    /// Start a traditional crawl. The AJAX spider is not started.
    pub fn start_spider(&self, url: &str) -> Result<(), String> {
        let url = parse_http_url(url)?;
        {
            let mut job = self.spider_job.lock().expect("spider job");
            if job.state == "running" {
                return Err("spider is already running".to_string());
            }
            *job = Job {
                state: "running",
                url: url.clone(),
                detail: String::new(),
            };
        }
        let spider = Arc::clone(&self.spider);
        let jobs = Arc::clone(&self.spider_job);
        std::thread::spawn(move || {
            let _mark = FinishJob {
                job: Arc::clone(&jobs),
            };
            match spider.crawl(&url, None) {
                Ok(urls) => {
                    let mut job = jobs.lock().expect("spider job");
                    job.detail = format!("{} urls", urls.len());
                    job.state = "finished";
                }
                Err(err) => {
                    let mut job = jobs.lock().expect("spider job");
                    job.detail = err;
                    job.state = "failed";
                }
            }
        });
        Ok(())
    }

    /// Start an active scan of one URL. The seed is a GET with no body.
    pub fn start_active_scan(&self, url: &str) -> Result<(), String> {
        let url = parse_http_url(url)?;
        let uri: Uri = url
            .parse()
            .map_err(|_| "url must be http or https".to_string())?;
        let seed = HttpMessage {
            method: Method::GET,
            uri,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        };
        {
            let mut job = self.ascan_job.lock().expect("ascan job");
            if job.state == "running" {
                return Err("active scan is already running".to_string());
            }
            *job = Job {
                state: "running",
                url: url.clone(),
                detail: String::new(),
            };
        }
        let id = self.engine.start(seed, ScanOptions::default());
        let engine = Arc::clone(&self.engine);
        let jobs = Arc::clone(&self.ascan_job);
        std::thread::spawn(move || {
            let _mark = FinishJob {
                job: Arc::clone(&jobs),
            };
            let finished = engine.wait(id, Duration::from_secs(300));
            let mut job = jobs.lock().expect("ascan job");
            if finished {
                job.detail = format!("scan {id}");
                job.state = "finished";
            } else {
                job.detail = format!("scan {id} timed out");
                job.state = "failed";
            }
        });
        Ok(())
    }
}

/// Accept only absolute http and https URLs.
pub fn parse_http_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("url must be http or https".to_string());
    }
    let uri: Uri = raw
        .parse()
        .map_err(|_| "url must be http or https".to_string())?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
        return Err("url must be http or https".to_string());
    }
    Ok(raw.to_string())
}

struct FinishJob {
    job: Arc<Mutex<Job>>,
}

impl Drop for FinishJob {
    fn drop(&mut self) {
        if let Ok(mut job) = self.job.lock() {
            if job.state == "running" {
                job.state = "failed";
                if job.detail.is_empty() {
                    job.detail = "stopped".to_string();
                }
            }
        }
    }
}

struct RecordingSender {
    inner: SpiderSender,
    session: Arc<Session>,
    pscan: Arc<PassiveScanListener>,
}

impl zap_spider::SpiderSender for RecordingSender {
    fn fetch(&self, method: &str, url: &str, body: &[u8]) -> Result<FetchResponse, String> {
        let response = zap_spider::SpiderSender::fetch(&self.inner, method, url, body)?;
        let mut message = http_message(method, url, body, &response)?;
        self.session
            .record_exchange(&message)
            .map_err(|err| err.to_string())?;
        let _ = ProxyListener::on_http_response_receive(self.pscan.as_ref(), &mut message);
        Ok(response)
    }
}

fn http_message(
    method: &str,
    url: &str,
    body: &[u8],
    response: &FetchResponse,
) -> Result<HttpMessage, String> {
    let method = Method::from_bytes(method.as_bytes()).map_err(|err| err.to_string())?;
    let uri = url
        .parse()
        .map_err(|err: http::uri::InvalidUri| err.to_string())?;
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (name, value) in &response.headers {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        headers.append(name, value);
    }
    Ok(HttpMessage {
        method,
        uri,
        headers: HeaderMap::new(),
        body: Bytes::copy_from_slice(body),
        response: Some(HttpResponse {
            status,
            headers,
            body: Bytes::from(response.body.clone()),
        }),
    })
}
