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
// This file is a Rust derivative of the ZAP automation framework. It changes
// the language and the architecture (Apache License 2.0, section 4). It is
// not an official OWASP ZAP build. There is no JDK and no browser.

//! Run plan jobs on the in-process engines.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use zap_ascan::{Engine, ScanOptions, ScanSender};
use zap_auth::Context;
use zap_core::{HttpMessage, HttpResponse, ProxyListener};
use zap_pscan::PassiveScanListener;
use zap_spider::{FetchResponse, Spider, SpiderOptions, SpiderSender};
use zap_store::Session;

use crate::error::{self, Error};
use crate::plan::{Job, Plan, PlanContext, PlannedRequest};
use crate::report::{write_report, write_summary};
use crate::Hosts;

/// One finished job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishedJob {
    /// Job type string.
    pub kind: String,
    /// Short result, such as a fetch count or a report path.
    pub detail: String,
}

/// What a plan run produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanResult {
    /// Jobs that finished.
    pub jobs: Vec<FinishedJob>,
    /// Non-fatal notes. The plan fails when `failOnWarning` is set and this
    /// is not empty.
    pub warnings: Vec<String>,
    /// Job errors kept when `continueOnFailure` is set and `failOnError` is
    /// not. Otherwise the run returns [`Error`] instead of a result.
    pub errors: Vec<String>,
}

pub(crate) fn run_plan(plan: &Plan, hosts: &Hosts, base_dir: &Path) -> Result<PlanResult, Error> {
    let gate = Arc::new(PassiveGate::new(Arc::clone(&hosts.passive)));
    let mut jobs = Vec::with_capacity(plan.jobs.len());
    let warnings = Vec::new();
    let mut errors = Vec::new();
    for job in &plan.jobs {
        if plan.env.progress_to_stdout {
            println!("automation: {}", job.kind());
        }
        match execute(job, plan, hosts, &gate, base_dir) {
            Ok(detail) => {
                if plan.env.progress_to_stdout {
                    println!("automation: {} {detail}", job.kind());
                }
                jobs.push(FinishedJob {
                    kind: job.kind().to_string(),
                    detail,
                });
            }
            Err(err) => {
                if plan.env.continue_on_failure {
                    errors.push(err.to_string());
                } else {
                    return Err(err);
                }
            }
        }
    }
    if plan.env.fail_on_warning && !warnings.is_empty() {
        return Err(error::plan(warnings.join("; ")));
    }
    if plan.env.fail_on_error && !errors.is_empty() {
        return Err(error::plan(errors.join("; ")));
    }
    Ok(PlanResult {
        jobs,
        warnings,
        errors,
    })
}

fn execute(
    job: &Job,
    plan: &Plan,
    hosts: &Hosts,
    gate: &Arc<PassiveGate>,
    base_dir: &Path,
) -> Result<String, Error> {
    match job {
        Job::PassiveScanConfig {
            enable_tags,
            max_alerts_per_rule,
        } => Ok(format!(
            "enableTags={enable_tags} maxAlertsPerRule={max_alerts_per_rule} (in-process queue has no tags or per-rule cap)"
        )),
        Job::Requestor { user, requests } => requestor(user, requests, hosts, gate),
        Job::Spider {
            context,
            url,
            max_duration_mins,
            max_depth,
            parse_comments,
            parse_robots_txt,
            parse_sitemap_xml,
            process_form,
            post_form,
        } => spider(
            plan,
            hosts,
            gate,
            context,
            url,
            *max_duration_mins,
            *max_depth,
            *parse_comments,
            *parse_robots_txt,
            *parse_sitemap_xml,
            *process_form,
            *post_form,
        ),
        Job::PassiveScanWait { max_duration_mins } => passive_wait(gate, *max_duration_mins),
        Job::ActiveScan {
            context,
            url,
            user,
            max_scan_duration_mins,
            policy,
        } => active_scan(
            plan,
            hosts,
            gate,
            context,
            url,
            user,
            *max_scan_duration_mins,
            policy,
        ),
        Job::Report { .. } => {
            let alerts = hosts
                .session
                .alerts()
                .map_err(|err| Error::Engine(err.to_string()))?;
            write_report(job, &alerts, base_dir)
        }
        Job::OutputSummary {
            format,
            summary_file,
            rules,
        } => {
            let alerts = hosts
                .session
                .alerts()
                .map_err(|err| Error::Engine(err.to_string()))?;
            write_summary(format, summary_file, rules, &alerts, base_dir)
        }
    }
}

fn requestor(
    user: &str,
    requests: &[PlannedRequest],
    hosts: &Hosts,
    gate: &PassiveGate,
) -> Result<String, Error> {
    reject_user("requestor", user)?;
    for request in requests {
        let mut msg = request_message(request)?;
        let response = hosts
            .requests
            .send(&mut msg)
            .map_err(|message| error::job("requestor", format!("{}: {message}", request.url)))?;
        if let Some(expected) = request.response_code {
            let actual = response.status.as_u16();
            if actual != expected {
                return Err(error::job(
                    "requestor",
                    format!("{} returned {actual}, expected {expected}", request.url),
                ));
            }
        }
        msg.response = Some(response);
        gate.submit(&hosts.session, &mut msg)?;
    }
    Ok(format!("sent {} requests", requests.len()))
}

fn request_message(request: &PlannedRequest) -> Result<HttpMessage, Error> {
    let method = Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
        .map_err(|err| error::job("requestor", err.to_string()))?;
    let uri: Uri = request.url.parse().map_err(|err: http::uri::InvalidUri| {
        error::job("requestor", format!("{}: {err}", request.url))
    })?;
    if uri.scheme_str() != Some("http") && uri.scheme_str() != Some("https") {
        return Err(error::job(
            "requestor",
            format!("{} is not an HTTP URL", request.url),
        ));
    }
    let mut headers = HeaderMap::new();
    for line in &request.headers {
        let Some((name, value)) = line.split_once(':') else {
            return Err(error::job(
                "requestor",
                format!("header `{line}` is missing ':'"),
            ));
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|err| error::job("requestor", err.to_string()))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|err| error::job("requestor", err.to_string()))?;
        headers.insert(name, value);
    }
    let body = Bytes::from(request.data.clone());
    if !body.is_empty() && !headers.contains_key(http::header::CONTENT_TYPE) {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
    }
    Ok(HttpMessage {
        method,
        uri,
        headers,
        body,
        response: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn spider(
    plan: &Plan,
    hosts: &Hosts,
    gate: &Arc<PassiveGate>,
    context_name: &str,
    url: &str,
    max_duration_mins: u64,
    max_depth: Option<u32>,
    parse_comments: Option<bool>,
    parse_robots_txt: Option<bool>,
    parse_sitemap_xml: Option<bool>,
    process_form: Option<bool>,
    post_form: Option<bool>,
) -> Result<String, Error> {
    let selected = select_context(plan, context_name)?;
    let seed = if url.is_empty() {
        selected
            .and_then(|ctx| ctx.urls.first())
            .map(String::as_str)
            .ok_or_else(|| error::job("spider", "spider has no url"))?
            .to_string()
    } else {
        url.to_string()
    };
    let context = match selected {
        Some(ctx) => Some(auth_context(ctx)?),
        None => None,
    };
    let mut options = SpiderOptions::default();
    if let Some(depth) = max_depth {
        options.max_depth = depth;
    }
    if let Some(value) = parse_comments {
        options.parse_comments = value;
    }
    if let Some(value) = parse_robots_txt {
        options.parse_robots_txt = value;
    }
    if let Some(value) = parse_sitemap_xml {
        options.parse_sitemap_xml = value;
    }
    if let Some(value) = process_form {
        options.process_form = value;
    }
    if let Some(value) = post_form {
        options.post_form = value;
    }
    let sender = Arc::new(RecordingSpider {
        inner: Arc::clone(&hosts.spider),
        session: Arc::clone(&hosts.session),
        gate: Arc::clone(gate),
    });
    let fetched = Spider::with_options(sender, options)
        .crawl(&seed, context.as_ref())
        .map_err(|message| error::job("spider", message))?;
    let duration = if max_duration_mins == 0 {
        "maxDuration is unlimited".to_string()
    } else {
        format!("maxDuration {max_duration_mins} min is not applied; the in-process spider runs to completion")
    };
    Ok(format!("fetched {} urls; {duration}", fetched.len()))
}

#[allow(clippy::too_many_arguments)]
fn active_scan(
    plan: &Plan,
    hosts: &Hosts,
    gate: &Arc<PassiveGate>,
    context_name: &str,
    url: &str,
    user: &str,
    max_scan_duration_mins: u64,
    policy: &zap_ascan::Policy,
) -> Result<String, Error> {
    reject_user("activeScan", user)?;
    let selected = select_context(plan, context_name)?;
    let seed_url = if !url.is_empty() {
        url.to_string()
    } else if let Some(ctx_url) = selected.and_then(|ctx| ctx.urls.first()) {
        ctx_url.clone()
    } else {
        let rows = hosts
            .session
            .history_rows()
            .map_err(|err| Error::Engine(err.to_string()))?;
        rows.into_iter()
            .next()
            .map(|row| row.url)
            .ok_or_else(|| error::job("activeScan", "active scan has no url"))?
    };
    if let Some(ctx) = selected {
        let auth = auth_context(ctx)?;
        if !auth.is_in_context(&seed_url) {
            return Err(error::job(
                "activeScan",
                format!("{seed_url} is outside context {}", ctx.name),
            ));
        }
    }
    let seed = seed_message(&seed_url)?;
    let sender = Arc::new(RecordingScan {
        inner: Arc::clone(&hosts.active),
        session: Arc::clone(&hosts.session),
        gate: Arc::clone(gate),
    });
    let engine = Engine::new(Arc::clone(&hosts.session), sender);
    let id = engine.start(
        seed,
        ScanOptions {
            policy: policy.clone(),
            recurse: true,
        },
    );
    let timeout = if max_scan_duration_mins == 0 {
        Duration::from_secs(60 * 60)
    } else {
        Duration::from_secs(max_scan_duration_mins.saturating_mul(60))
    };
    if !engine.wait(id, timeout) {
        engine.stop(id);
        let _ = engine.wait(id, Duration::from_secs(2));
        return Err(error::job(
            "activeScan",
            format!("scan {id} exceeded {max_scan_duration_mins} minutes"),
        ));
    }
    let alerts = engine.alerts(id).unwrap_or_default().len();
    Ok(format!("scan {id} finished with {alerts} alerts"))
}

fn seed_message(url: &str) -> Result<HttpMessage, Error> {
    let uri: Uri = url
        .parse()
        .map_err(|err: http::uri::InvalidUri| error::job("activeScan", format!("{url}: {err}")))?;
    if uri.scheme_str() != Some("http") && uri.scheme_str() != Some("https") {
        return Err(error::job(
            "activeScan",
            format!("{url} is not an HTTP URL"),
        ));
    }
    Ok(HttpMessage {
        method: Method::GET,
        uri,
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    })
}

fn passive_wait(gate: &PassiveGate, max_duration_mins: u64) -> Result<String, Error> {
    let started = Instant::now();
    let limit =
        (max_duration_mins > 0).then(|| Duration::from_secs(max_duration_mins.saturating_mul(60)));
    loop {
        let left = gate.records_to_scan();
        if left == 0 {
            let scanned = gate.listener.queued_urls().len();
            return Ok(format!(
                "passive scan queue empty ({scanned} responses scanned)"
            ));
        }
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            return Err(error::job(
                "passiveScan-wait",
                format!("{left} responses still queued after {max_duration_mins} minutes"),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn reject_user(kind: &str, user: &str) -> Result<(), Error> {
    if user.trim().is_empty() {
        Ok(())
    } else {
        Err(error::job(
            kind,
            format!("user `{user}` is not applied; this runner has no browser login"),
        ))
    }
}

fn select_context<'a>(plan: &'a Plan, name: &str) -> Result<Option<&'a PlanContext>, Error> {
    if name.is_empty() {
        return Ok(plan.env.contexts.first());
    }
    plan.env
        .contexts
        .iter()
        .find(|ctx| ctx.name == name)
        .map(Some)
        .ok_or_else(|| error::plan(format!("context `{name}` is not in the plan")))
}

fn auth_context(ctx: &PlanContext) -> Result<Context, Error> {
    let mut xml = String::from("<context>");
    push_tag(&mut xml, "name", &ctx.name);
    let includes: Vec<String> = if ctx.include_paths.is_empty() {
        ctx.urls.iter().map(|url| url_include_regex(url)).collect()
    } else {
        ctx.include_paths.clone()
    };
    for pattern in &includes {
        push_tag(&mut xml, "incregexes", pattern);
    }
    for pattern in &ctx.exclude_paths {
        push_tag(&mut xml, "excregexes", pattern);
    }
    xml.push_str("</context>");
    Context::from_zap_config(&xml).map_err(|err| Error::Engine(err.to_string()))
}

fn url_include_regex(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    let mut escaped = String::with_capacity(without_query.len());
    for ch in without_query.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push_str(".*");
    escaped
}

fn push_tag(xml: &mut String, tag: &str, text: &str) {
    xml.push('<');
    xml.push_str(tag);
    xml.push('>');
    xml.push_str(&xml_escape(text));
    xml.push_str("</");
    xml.push_str(tag);
    xml.push('>');
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

struct PassiveGate {
    listener: Arc<PassiveScanListener>,
    pending: AtomicUsize,
}

impl PassiveGate {
    fn new(listener: Arc<PassiveScanListener>) -> Self {
        Self {
            listener,
            pending: AtomicUsize::new(0),
        }
    }

    fn submit(&self, session: &Session, msg: &mut HttpMessage) -> Result<(), Error> {
        self.pending.fetch_add(1, Ordering::SeqCst);
        let _pending = Pending(&self.pending);
        session
            .record_exchange(msg)
            .map_err(|err| Error::Engine(err.to_string()))?;
        let _ = self.listener.on_http_response_receive(msg);
        Ok(())
    }

    fn records_to_scan(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
}

struct Pending<'a>(&'a AtomicUsize);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct RecordingSpider {
    inner: Arc<dyn SpiderSender>,
    session: Arc<Session>,
    gate: Arc<PassiveGate>,
}

impl SpiderSender for RecordingSpider {
    fn fetch(&self, method: &str, url: &str, body: &[u8]) -> Result<FetchResponse, String> {
        let response = self.inner.fetch(method, url, body)?;
        let mut message = message_from_fetch(method, url, body, &response)?;
        self.gate
            .submit(&self.session, &mut message)
            .map_err(|err| err.to_string())?;
        Ok(response)
    }
}

struct RecordingScan {
    inner: Arc<dyn ScanSender>,
    session: Arc<Session>,
    gate: Arc<PassiveGate>,
}

impl ScanSender for RecordingScan {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        let response = self.inner.send(msg)?;
        msg.response = Some(response.clone());
        self.gate
            .submit(&self.session, msg)
            .map_err(|err| err.to_string())?;
        Ok(response)
    }
}

fn message_from_fetch(
    method: &str,
    url: &str,
    body: &[u8],
    response: &FetchResponse,
) -> Result<HttpMessage, String> {
    let method = Method::from_bytes(method.as_bytes()).map_err(|err| err.to_string())?;
    let uri = url
        .parse()
        .map_err(|err: http::uri::InvalidUri| err.to_string())?;
    let status = StatusCode::from_u16(response.status).map_err(|err| err.to_string())?;
    let mut headers = HeaderMap::new();
    for (name, value) in &response.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| err.to_string())?;
        let value = HeaderValue::from_str(value).map_err(|err| err.to_string())?;
        headers.insert(name, value);
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
