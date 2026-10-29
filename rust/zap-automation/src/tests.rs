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

//! Parse a small plan and run it on the in-process engines.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use zap_ascan::{AlertThreshold, AttackStrength, ScanSender};
use zap_core::{HttpMessage, HttpResponse};
use zap_pscan::PassiveScanListener;
use zap_spider::{FetchResponse, SpiderSender};
use zap_store::Session;

use crate::{parse_plan, run_file, Error, Hosts, Job, RequestSender};

const PLAN: &str = r#"
env:
  contexts:
  - name: test
    urls:
    - http://127.0.0.1:9/
    includePaths: []
    excludePaths:
    - http://127.0.0.1:9/b.*
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: false
jobs:
- type: passiveScan-config
  parameters:
    enableTags: false
    maxAlertsPerRule: 10
- type: requestor
  parameters:
    user: ""
  requests:
  - url: http://127.0.0.1:9/
    method: GET
    responseCode: 200
- type: passiveScan-wait
  parameters:
    maxDuration: 0
- type: spider
  parameters:
    context: test
    url: http://127.0.0.1:9/
    maxDuration: 0
    maxDepth: 5
    parseRobotsTxt: true
    parseSitemapXml: true
- type: activeScan
  parameters:
    context: test
    url: http://127.0.0.1:9/search?q=1
    maxScanDurationInMins: 1
  policyDefinition:
    defaultStrength: medium
    defaultThreshold: medium
    rules:
    - id: 40012
      threshold: "off"
- type: outputSummary
  parameters:
    format: Long
    summaryFile: summary.txt
  rules: []
- type: report
  parameters:
    template: traditional-json
    reportDir: ""
    reportFile: report.json
    reportTitle: ZAP Scanning Report
    reportDescription: plan test
"#;

#[test]
fn parses_requestor_spider_wait_active_scan_and_report() {
    let plan = parse_plan(PLAN).expect("parse");
    let kinds: Vec<_> = plan.jobs.iter().map(Job::kind).collect();
    assert_eq!(
        kinds,
        [
            "passiveScan-config",
            "requestor",
            "passiveScan-wait",
            "spider",
            "activeScan",
            "outputSummary",
            "report",
        ]
    );
    assert!(!plan.env.progress_to_stdout);
    assert!(plan.env.fail_on_error);
    assert_eq!(plan.env.contexts[0].name, "test");
    assert_eq!(
        plan.env.contexts[0].exclude_paths,
        ["http://127.0.0.1:9/b.*"]
    );

    match &plan.jobs[1] {
        Job::Requestor { requests, user } => {
            assert!(user.is_empty());
            assert_eq!(requests[0].url, "http://127.0.0.1:9/");
            assert_eq!(requests[0].method, "GET");
            assert_eq!(requests[0].response_code, Some(200));
        }
        other => panic!("requestor was {other:?}"),
    }
    match &plan.jobs[2] {
        Job::PassiveScanWait { max_duration_mins } => assert_eq!(*max_duration_mins, 0),
        other => panic!("wait was {other:?}"),
    }
    match &plan.jobs[3] {
        Job::Spider {
            context,
            url,
            max_depth,
            ..
        } => {
            assert_eq!(context, "test");
            assert_eq!(url, "http://127.0.0.1:9/");
            assert_eq!(*max_depth, Some(5));
        }
        other => panic!("spider was {other:?}"),
    }
    match &plan.jobs[4] {
        Job::ActiveScan { url, policy, .. } => {
            assert_eq!(url, "http://127.0.0.1:9/search?q=1");
            assert_eq!(policy.strength, AttackStrength::Medium);
            assert_eq!(policy.threshold, AlertThreshold::Medium);
            assert!(policy.enables(90021));
            assert!(!policy.enables(40012));
        }
        other => panic!("active scan was {other:?}"),
    }
    match &plan.jobs[6] {
        Job::Report {
            template,
            report_file,
            title,
            description,
            ..
        } => {
            assert_eq!(template, "traditional-json");
            assert_eq!(report_file, "report.json");
            assert_eq!(title, "ZAP Scanning Report");
            assert_eq!(description, "plan test");
        }
        other => panic!("report was {other:?}"),
    }
}

#[test]
fn runs_plan_against_in_process_engines() {
    let dir = temp_dir("run");
    let plan_path = dir.join("plan.yaml");
    std::fs::write(&plan_path, PLAN).unwrap();
    let (hosts, fixture) = hosts_in(&dir);
    let result = run_file(&plan_path, &hosts).expect("run plan");
    let kinds: Vec<_> = result.jobs.iter().map(|job| job.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "passiveScan-config",
            "requestor",
            "passiveScan-wait",
            "spider",
            "activeScan",
            "outputSummary",
            "report",
        ]
    );
    assert!(
        result.jobs[2].detail.contains("empty"),
        "wait detail was {}",
        result.jobs[2].detail
    );
    assert!(
        result.jobs[3].detail.contains("fetched"),
        "spider detail was {}",
        result.jobs[3].detail
    );

    let hits = fixture.hits.lock().unwrap().clone();
    let paths: Vec<String> = hits.iter().map(|url| path_of(url)).collect();
    assert!(
        paths.iter().any(|path| path == "/"),
        "requestor hit {hits:?}"
    );
    assert!(
        paths.iter().any(|path| path == "/a"),
        "spider did not fetch /a from {hits:?}"
    );
    assert!(
        paths.iter().any(|path| path == "/robots.txt"),
        "spider did not fetch robots.txt from {hits:?}"
    );
    assert!(
        paths.iter().any(|path| path == "/sitemap.xml"),
        "spider did not fetch sitemap.xml from {hits:?}"
    );
    assert!(
        !paths.iter().any(|path| path == "/b"),
        "excluded /b was fetched: {hits:?}"
    );
    assert!(
        hits.iter().any(|url| url.contains("%22%27")),
        "active scan did not send the xpath payload: {hits:?}"
    );

    let alerts = hosts.session.alerts().unwrap();
    assert!(
        alerts.iter().any(|alert| alert.plugin_id == 10021),
        "passive scan did not raise 10021: {alerts:?}"
    );
    assert!(
        alerts.iter().any(|alert| alert.plugin_id == 90021),
        "active scan did not raise 90021: {alerts:?}"
    );

    let report = std::fs::read_to_string(dir.join("report.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(value["title"], "ZAP Scanning Report");
    assert_eq!(value["description"], "plan test");
    let ids: Vec<i64> = value["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|alert| alert["pluginId"].as_i64().unwrap())
        .collect();
    assert!(ids.contains(&10021), "{report}");
    assert!(ids.contains(&90021), "{report}");

    let summary = std::fs::read_to_string(dir.join("summary.txt")).unwrap();
    assert!(summary.contains("plugin 10021"), "{summary}");
    assert!(summary.contains("format: Long"), "{summary}");
}

#[test]
fn requestor_unexpected_status_fails_the_plan() {
    let dir = temp_dir("status");
    let plan_path = dir.join("plan.yaml");
    std::fs::write(
        &plan_path,
        r#"
env:
  parameters:
    failOnError: true
    progressToStdout: false
jobs:
- type: requestor
  requests:
  - url: http://127.0.0.1:9/
    method: GET
    responseCode: 500
"#,
    )
    .unwrap();
    let (hosts, _) = hosts_in(&dir);
    let err = run_file(&plan_path, &hosts).expect_err("status must fail");
    let text = err.to_string();
    assert!(text.contains("500"), "{text}");
    assert!(text.contains("200"), "{text}");
}

#[test]
fn browser_and_unrelated_jobs_are_rejected() {
    for kind in ["spiderAjax", "spiderClient"] {
        let yaml = format!("jobs:\n- type: {kind}\n  parameters:\n    url: http://127.0.0.1:9/\n");
        let err = parse_plan(&yaml).expect_err(kind);
        assert!(
            err.to_string().contains("browser"),
            "{kind} error was {err}"
        );
    }
    for kind in ["sonar", "crowdin", "release"] {
        let yaml = format!("jobs:\n- type: {kind}\n");
        let err = parse_plan(&yaml).expect_err(kind);
        let text = err.to_string();
        assert!(text.contains("not implemented"), "{kind}: {text}");
        assert!(matches!(err, Error::Plan(_)));
    }
}

struct Fixture {
    hits: Mutex<Vec<String>>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            hits: Mutex::new(Vec::new()),
        }
    }

    fn respond(&self, url: &str) -> (u16, &'static str, Vec<u8>) {
        self.hits.lock().unwrap().push(url.to_string());
        let uri: Uri = match url.parse() {
            Ok(uri) => uri,
            Err(_) => return (400, "text/plain", b"bad url".to_vec()),
        };
        let query = uri.query().unwrap_or("");
        if query.contains("%22%27") {
            return (200, "text/html", b"XPathException".to_vec());
        }
        match uri.path() {
            "/" => (
                200,
                "text/html",
                b"<html><body><a href=\"/a\">a</a></body></html>".to_vec(),
            ),
            "/a" => (
                200,
                "text/html",
                b"<html><body><a href=\"/b\">b</a></body></html>".to_vec(),
            ),
            "/b" => (200, "text/html", b"<html><body>b</body></html>".to_vec()),
            "/search" => (
                200,
                "text/html",
                b"<html><body>search</body></html>".to_vec(),
            ),
            "/robots.txt" => (200, "text/plain", Vec::new()),
            "/sitemap.xml" => (200, "application/xml", b"<urlset></urlset>".to_vec()),
            _ => (404, "text/plain", Vec::new()),
        }
    }
}

impl RequestSender for Fixture {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        let (status, content_type, body) = self.respond(&msg.url());
        Ok(http_response(status, content_type, body))
    }
}

impl SpiderSender for Fixture {
    fn fetch(&self, _method: &str, url: &str, _body: &[u8]) -> Result<FetchResponse, String> {
        let (status, content_type, body) = self.respond(url);
        Ok(FetchResponse {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body,
        })
    }
}

impl ScanSender for Fixture {
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String> {
        let (status, content_type, body) = self.respond(&msg.url());
        Ok(http_response(status, content_type, body))
    }
}

fn http_response(status: u16, content_type: &str, body: Vec<u8>) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("content type"),
    );
    HttpResponse {
        status: StatusCode::from_u16(status).expect("status"),
        headers,
        body: Bytes::from(body),
    }
}

fn hosts_in(dir: &std::path::Path) -> (Hosts, Arc<Fixture>) {
    let session = Arc::new(Session::open(dir.join("session.sqlite")).unwrap());
    let fixture = Arc::new(Fixture::new());
    let hosts = Hosts {
        session: Arc::clone(&session),
        passive: Arc::new(PassiveScanListener::new(session)),
        requests: Arc::clone(&fixture) as Arc<dyn RequestSender>,
        spider: fixture.clone(),
        active: fixture.clone(),
    };
    (hosts, fixture)
}

fn path_of(url: &str) -> String {
    url.parse::<Uri>()
        .map(|uri| uri.path().to_string())
        .unwrap_or_default()
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zap-automation-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}
