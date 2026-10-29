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

//! YAML plan used by the automation framework.
//!
//! The shape matches the jobs the Docker packaged scans write: `env.contexts`,
//! `env.parameters`, and a `jobs` list. Browser jobs (`spiderAjax`,
//! `spiderClient`) are rejected. Release, Docker Hub, Sonar, and Crowdin are
//! not jobs this runner implements.

use serde::Deserialize;
use serde_yaml::Value;
use zap_ascan::{AlertThreshold, AttackStrength, Policy};

use crate::error::{self, Error};

/// One automation plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Contexts and failure policy.
    pub env: Environment,
    /// Jobs in the order they run.
    pub jobs: Vec<Job>,
}

/// `env` from the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    /// Named contexts. A spider or active scan selects one by name.
    pub contexts: Vec<PlanContext>,
    /// Stop the plan when a job returns an error. Default true.
    pub fail_on_error: bool,
    /// Stop the plan when a job records a warning. Default false.
    pub fail_on_warning: bool,
    /// Keep going after a job error, then apply [`Self::fail_on_error`].
    pub continue_on_failure: bool,
    /// Print one line per job on stdout. Default true, matching ZAP.
    pub progress_to_stdout: bool,
}

/// One context: URLs plus include and exclude regexes.
///
/// When `include_paths` is empty, each URL becomes an include regex of that
/// URL with `.*` appended, which is how the automation framework scopes a
/// context that only lists URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanContext {
    /// Context name referenced by spider and active scan jobs.
    pub name: String,
    /// Seed URLs.
    pub urls: Vec<String>,
    /// Include regexes. Empty means "derive them from [`Self::urls`]".
    pub include_paths: Vec<String>,
    /// Exclude regexes.
    pub exclude_paths: Vec<String>,
}

/// One HTTP request in a requestor job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedRequest {
    /// Absolute HTTP or HTTPS URL.
    pub url: String,
    /// HTTP method. Default `GET`.
    pub method: String,
    /// Request body. Empty when the plan omits `data`.
    pub data: String,
    /// Header lines, `Name: value`.
    pub headers: Vec<String>,
    /// Expected status. `None` accepts any status.
    pub response_code: Option<u16>,
}

/// One rule line on an `outputSummary` job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryRule {
    /// Plugin id.
    pub id: i32,
    /// `IGNORE`, `INFO`, `WARN`, or `FAIL`. Stored as written.
    pub action: String,
}

/// Jobs this runner executes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Job {
    /// Accepts `enableTags` and `maxAlertsPerRule`. The in-process queue has
    /// neither tags nor a per-rule cap, so the job records the values and
    /// does not change the scanners.
    PassiveScanConfig {
        /// Plan value. Not applied.
        enable_tags: bool,
        /// Plan value. Not applied.
        max_alerts_per_rule: u64,
    },
    /// Send the listed requests through the plan's request sender.
    Requestor {
        /// Non-empty user names are rejected. This runner does not log in.
        user: String,
        /// Requests in order.
        requests: Vec<PlannedRequest>,
    },
    /// Traditional spider. `max_duration_mins` is parsed and not enforced:
    /// the in-process spider runs until its queue is empty.
    Spider {
        /// Context name. Empty selects the first context.
        context: String,
        /// Seed URL. Empty selects the first URL of the context.
        url: String,
        /// `maxDuration` in minutes.
        max_duration_mins: u64,
        /// `None` keeps the spider default (5). `Some(0)` is unlimited.
        max_depth: Option<u32>,
        /// `None` keeps the spider default.
        parse_comments: Option<bool>,
        /// `None` keeps the spider default.
        parse_robots_txt: Option<bool>,
        /// `None` keeps the spider default.
        parse_sitemap_xml: Option<bool>,
        /// `None` keeps the spider default.
        process_form: Option<bool>,
        /// `None` keeps the spider default.
        post_form: Option<bool>,
    },
    /// Wait until the passive-scan queue is empty, or until `max_duration_mins`.
    ///
    /// Zero minutes means wait with no deadline. The in-process queue scans
    /// each response before the listener returns, so this job finds an empty
    /// queue once earlier jobs have returned.
    PassiveScanWait {
        /// `maxDuration` in minutes.
        max_duration_mins: u64,
    },
    /// Active scan of one seed URL on the in-process engine.
    ActiveScan {
        /// Context name. Empty selects the first context.
        context: String,
        /// Seed URL. Empty selects the first context URL, then history.
        url: String,
        /// Non-empty user names are rejected. This runner does not log in.
        user: String,
        /// `maxScanDurationInMins`. Zero waits up to one hour.
        max_scan_duration_mins: u64,
        /// Strength, threshold, and per-plugin thresholds.
        policy: Policy,
    },
    /// Write alerts from the session. Templates are `traditional-html`,
    /// `traditional-json`, `traditional-xml`, and `traditional-md`.
    Report {
        /// Template name.
        template: String,
        /// Directory relative to the plan file, unless absolute.
        report_dir: String,
        /// File name. An extension is added when the name has none.
        report_file: String,
        /// Report title.
        title: String,
        /// Report description.
        description: String,
        /// Risk codes to include. Empty includes every risk.
        risks: Vec<i32>,
        /// Confidence codes to include. Empty includes every confidence.
        confidences: Vec<i32>,
    },
    /// Write a text count of session alerts. Used by the baseline plan.
    OutputSummary {
        /// `Long` or `Short`, recorded in the file.
        format: String,
        /// Summary path, relative to the plan file unless absolute.
        summary_file: String,
        /// Per-plugin actions. Empty lists every alert.
        rules: Vec<SummaryRule>,
    },
}

impl Job {
    /// Automation framework type string.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PassiveScanConfig { .. } => "passiveScan-config",
            Self::Requestor { .. } => "requestor",
            Self::Spider { .. } => "spider",
            Self::PassiveScanWait { .. } => "passiveScan-wait",
            Self::ActiveScan { .. } => "activeScan",
            Self::Report { .. } => "report",
            Self::OutputSummary { .. } => "outputSummary",
        }
    }
}

/// Parse `yaml` into a plan. The file is not read here.
pub fn parse_plan(yaml: &str) -> Result<Plan, Error> {
    let doc: Document = serde_yaml::from_str(yaml).map_err(|err| error::plan(err.to_string()))?;
    if doc.jobs.is_empty() {
        return Err(error::plan("plan has no jobs"));
    }
    let mut jobs = Vec::with_capacity(doc.jobs.len());
    for job in doc.jobs {
        jobs.push(parse_job(job)?);
    }
    let env = doc.env;
    Ok(Plan {
        env: Environment {
            contexts: env
                .contexts
                .into_iter()
                .map(|ctx| PlanContext {
                    name: {
                        let name = ctx.name.trim().to_string();
                        if name.is_empty() {
                            "context".to_string()
                        } else {
                            name
                        }
                    },
                    urls: ctx.urls,
                    include_paths: ctx.include_paths,
                    exclude_paths: ctx.exclude_paths,
                })
                .collect(),
            fail_on_error: env.parameters.fail_on_error,
            fail_on_warning: env.parameters.fail_on_warning,
            continue_on_failure: env.parameters.continue_on_failure,
            progress_to_stdout: env.parameters.progress_to_stdout,
        },
        jobs,
    })
}

fn parse_job(job: JobDoc) -> Result<Job, Error> {
    let kind = job.job_type.trim();
    match kind {
        "passiveScan-config" => Ok(Job::PassiveScanConfig {
            enable_tags: field_bool(&job.parameters, "enableTags")?.unwrap_or(false),
            max_alerts_per_rule: field_u64(&job.parameters, "maxAlertsPerRule")?.unwrap_or(0),
        }),
        "requestor" => Ok(Job::Requestor {
            user: field_str(&job.parameters, "user")?.unwrap_or_default(),
            requests: job
                .requests
                .into_iter()
                .map(|request| PlannedRequest {
                    url: request.url,
                    method: {
                        let method = request.method.trim();
                        if method.is_empty() {
                            "GET".to_string()
                        } else {
                            method.to_string()
                        }
                    },
                    data: request.data,
                    headers: request.headers,
                    response_code: request.response_code,
                })
                .collect(),
        }),
        "spider" => Ok(Job::Spider {
            context: field_str(&job.parameters, "context")?.unwrap_or_default(),
            url: field_str(&job.parameters, "url")?.unwrap_or_default(),
            max_duration_mins: field_u64(&job.parameters, "maxDuration")?.unwrap_or(0),
            max_depth: field_u32(&job.parameters, "maxDepth")?,
            parse_comments: field_bool(&job.parameters, "parseComments")?,
            parse_robots_txt: field_bool(&job.parameters, "parseRobotsTxt")?,
            parse_sitemap_xml: field_bool(&job.parameters, "parseSitemapXml")?,
            process_form: field_bool(&job.parameters, "processForm")?,
            post_form: field_bool(&job.parameters, "postForm")?,
        }),
        "passiveScan-wait" => Ok(Job::PassiveScanWait {
            max_duration_mins: field_u64(&job.parameters, "maxDuration")?.unwrap_or(0),
        }),
        "activeScan" => Ok(Job::ActiveScan {
            context: field_str(&job.parameters, "context")?.unwrap_or_default(),
            url: field_str(&job.parameters, "url")?.unwrap_or_default(),
            user: field_str(&job.parameters, "user")?.unwrap_or_default(),
            max_scan_duration_mins: field_u64(&job.parameters, "maxScanDurationInMins")?
                .unwrap_or(0),
            policy: policy_from(&job.policy_definition)?,
        }),
        "report" => Ok(Job::Report {
            template: field_str(&job.parameters, "template")?
                .unwrap_or_else(|| "traditional-html".to_string()),
            report_dir: field_str(&job.parameters, "reportDir")?.unwrap_or_default(),
            report_file: field_str(&job.parameters, "reportFile")?.unwrap_or_default(),
            title: field_str(&job.parameters, "reportTitle")?
                .unwrap_or_else(|| "ZAP Scanning Report".to_string()),
            description: field_str(&job.parameters, "reportDescription")?.unwrap_or_default(),
            risks: risk_codes(&job.risks)?,
            confidences: confidence_codes(&job.confidences)?,
        }),
        "outputSummary" => Ok(Job::OutputSummary {
            format: field_str(&job.parameters, "format")?.unwrap_or_else(|| "Long".to_string()),
            summary_file: field_str(&job.parameters, "summaryFile")?
                .ok_or_else(|| error::plan("outputSummary is missing summaryFile"))?,
            rules: summary_rules(&job.rules)?,
        }),
        "spiderAjax" | "spiderClient" => Err(error::plan(format!(
            "job `{kind}` needs a browser; this runner has no browser"
        ))),
        other => Err(error::plan(format!(
            "job type `{other}` is not implemented"
        ))),
    }
}

fn policy_from(value: &Value) -> Result<Policy, Error> {
    if value.is_null() || !value.is_mapping() {
        return Ok(Policy::default());
    }
    let strength = match field_str(value, "defaultStrength")? {
        Some(text) => parse_strength(&text)?,
        None => AttackStrength::Medium,
    };
    let threshold = match field_str(value, "defaultThreshold")? {
        Some(text) => parse_threshold(&text)?,
        None => AlertThreshold::Medium,
    };
    let mut policy = Policy::new(strength, threshold);
    if let Some(rules) = value.get("rules").and_then(Value::as_sequence) {
        for rule in rules {
            let Some(id) = field_i32(rule, "id")? else {
                continue;
            };
            if let Some(text) = field_str(rule, "threshold")? {
                policy.set_plugin_threshold(id, parse_threshold(&text)?);
            }
        }
    }
    Ok(policy)
}

fn parse_strength(text: &str) -> Result<AttackStrength, Error> {
    match text.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(AttackStrength::Default),
        "low" => Ok(AttackStrength::Low),
        "medium" => Ok(AttackStrength::Medium),
        "high" => Ok(AttackStrength::High),
        "insane" => Ok(AttackStrength::Insane),
        other => Err(error::plan(format!("unknown attack strength `{other}`"))),
    }
}

fn parse_threshold(text: &str) -> Result<AlertThreshold, Error> {
    match text.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(AlertThreshold::Off),
        "default" => Ok(AlertThreshold::Default),
        "low" => Ok(AlertThreshold::Low),
        "medium" => Ok(AlertThreshold::Medium),
        "high" => Ok(AlertThreshold::High),
        other => Err(error::plan(format!("unknown alert threshold `{other}`"))),
    }
}

fn summary_rules(rules: &[Value]) -> Result<Vec<SummaryRule>, Error> {
    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        let id = field_i32(rule, "id")?
            .ok_or_else(|| error::plan("outputSummary rule is missing id"))?;
        let action = field_str(rule, "action")?.unwrap_or_else(|| "WARN".to_string());
        out.push(SummaryRule { id, action });
    }
    Ok(out)
}

fn risk_codes(names: &[String]) -> Result<Vec<i32>, Error> {
    names
        .iter()
        .map(|name| match name.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(0),
            "low" => Ok(1),
            "medium" => Ok(2),
            "high" => Ok(3),
            other => Err(error::plan(format!("unknown risk `{other}`"))),
        })
        .collect()
}

fn confidence_codes(names: &[String]) -> Result<Vec<i32>, Error> {
    names
        .iter()
        .map(|name| match name.trim().to_ascii_lowercase().as_str() {
            "falsepositive" | "false positive" | "fp" => Ok(0),
            "low" => Ok(1),
            "medium" => Ok(2),
            "high" => Ok(3),
            "confirmed" | "userconfirmed" | "user confirmed" => Ok(4),
            other => Err(error::plan(format!("unknown confidence `{other}`"))),
        })
        .collect()
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key).filter(|item| !item.is_null())
}

fn field_str(value: &Value, key: &str) -> Result<Option<String>, Error> {
    let Some(raw) = field(value, key) else {
        return Ok(None);
    };
    match raw {
        Value::String(text) => Ok(Some(text.clone())),
        Value::Bool(flag) => Ok(Some(flag.to_string())),
        Value::Number(number) => Ok(Some(number.to_string())),
        _ => Err(error::plan(format!("{key} must be a string"))),
    }
}

fn field_bool(value: &Value, key: &str) -> Result<Option<bool>, Error> {
    let Some(raw) = field(value, key) else {
        return Ok(None);
    };
    match raw {
        Value::Bool(flag) => Ok(Some(*flag)),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Ok(Some(true)),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Ok(Some(false)),
        _ => Err(error::plan(format!("{key} must be a boolean"))),
    }
}

fn field_i64(value: &Value, key: &str) -> Result<Option<i64>, Error> {
    let Some(raw) = field(value, key) else {
        return Ok(None);
    };
    match raw {
        Value::Number(number) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| error::plan(format!("{key} is out of range"))),
        Value::String(text) => text
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| error::plan(format!("{key} is not an integer"))),
        _ => Err(error::plan(format!("{key} is not an integer"))),
    }
}

fn field_i32(value: &Value, key: &str) -> Result<Option<i32>, Error> {
    let Some(number) = field_i64(value, key)? else {
        return Ok(None);
    };
    i32::try_from(number)
        .map(Some)
        .map_err(|_| error::plan(format!("{key} is out of range")))
}

fn field_u64(value: &Value, key: &str) -> Result<Option<u64>, Error> {
    let Some(number) = field_i64(value, key)? else {
        return Ok(None);
    };
    u64::try_from(number)
        .map(Some)
        .map_err(|_| error::plan(format!("{key} must be zero or greater")))
}

fn field_u32(value: &Value, key: &str) -> Result<Option<u32>, Error> {
    let Some(number) = field_u64(value, key)? else {
        return Ok(None);
    };
    u32::try_from(number)
        .map(Some)
        .map_err(|_| error::plan(format!("{key} is out of range")))
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct Document {
    #[serde(default)]
    env: EnvDoc,
    #[serde(default)]
    jobs: Vec<JobDoc>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvDoc {
    #[serde(default)]
    contexts: Vec<ContextDoc>,
    #[serde(default)]
    parameters: EnvParams,
}

#[derive(Debug, Deserialize)]
struct EnvParams {
    #[serde(default = "default_true", rename = "failOnError")]
    fail_on_error: bool,
    #[serde(default, rename = "failOnWarning")]
    fail_on_warning: bool,
    #[serde(default, rename = "continueOnFailure")]
    continue_on_failure: bool,
    #[serde(default = "default_true", rename = "progressToStdout")]
    progress_to_stdout: bool,
}

impl Default for EnvParams {
    fn default() -> Self {
        Self {
            fail_on_error: true,
            fail_on_warning: false,
            continue_on_failure: false,
            progress_to_stdout: true,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ContextDoc {
    #[serde(default)]
    name: String,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default, rename = "includePaths")]
    include_paths: Vec<String>,
    #[serde(default, rename = "excludePaths")]
    exclude_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JobDoc {
    #[serde(rename = "type")]
    job_type: String,
    #[serde(default)]
    parameters: Value,
    #[serde(default)]
    requests: Vec<RequestDoc>,
    #[serde(default, rename = "policyDefinition")]
    policy_definition: Value,
    #[serde(default)]
    risks: Vec<String>,
    #[serde(default)]
    confidences: Vec<String>,
    #[serde(default)]
    rules: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RequestDoc {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    headers: Vec<String>,
    #[serde(default, rename = "responseCode")]
    response_code: Option<u16>,
}

fn default_method() -> String {
    "GET".to_string()
}
