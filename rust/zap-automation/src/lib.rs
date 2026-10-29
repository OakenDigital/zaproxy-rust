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

//! Automation plan runner for ZAP YAML.
//!
//! Reads a local plan and drives the crates already on main: the traditional
//! spider, the passive-scan listener, and the active-scan engine. Requestor
//! responses are stored in the session and scanned passively. Report jobs
//! write the session alerts.
//!
//! There is no JDK and no browser. `spiderAjax` and `spiderClient` are
//! rejected. Release, Docker Hub, Sonar, and Crowdin are not implemented.
//!
//! Not an official OWASP ZAP build.

#![forbid(unsafe_code)]

mod drive;
mod error;
mod plan;
mod report;
mod upstream;

pub use drive::{FinishedJob, PlanResult};
pub use error::Error;
pub use plan::{parse_plan, Environment, Job, Plan, PlanContext, PlannedRequest, SummaryRule};
pub use upstream::UpstreamRequestSender;

use std::path::Path;
use std::sync::Arc;

use zap_ascan::ScanSender;
use zap_core::{HttpMessage, HttpResponse};
use zap_pscan::PassiveScanListener;
use zap_spider::SpiderSender;
use zap_store::Session;

/// Sends one requestor request.
pub trait RequestSender: Send + Sync {
    /// Perform `msg` and return the origin response. Do not store it.
    fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, String>;
}

/// Engines a plan runs against.
///
/// Tests pass in-process fakes. `zapd -autorun` uses [`Hosts::with_defaults`].
pub struct Hosts {
    /// Session that receives history rows and alerts.
    pub session: Arc<Session>,
    /// Passive scanner. The queue runs inside the listener call.
    pub passive: Arc<PassiveScanListener>,
    /// Requestor transport.
    pub requests: Arc<dyn RequestSender>,
    /// Traditional spider transport.
    pub spider: Arc<dyn SpiderSender>,
    /// Active scan transport.
    pub active: Arc<dyn ScanSender>,
}

impl Hosts {
    /// Default HTTP client for each engine, on the current tokio runtime.
    ///
    /// Run the plan from a worker thread. The default senders call
    /// `Handle::block_on`, which panics on the runtime thread.
    pub fn with_defaults(session: Arc<Session>) -> Result<Self, Error> {
        let passive = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
        let requests = Arc::new(UpstreamRequestSender::from_current()?);
        let spider = Arc::new(zap_spider::DefaultSender::from_current().map_err(Error::Engine)?);
        let active = Arc::new(zap_ascan::DefaultSender::from_current().map_err(Error::Engine)?);
        Ok(Self {
            session,
            passive,
            requests,
            spider,
            active,
        })
    }
}

/// Read `path` and run the plan. Report paths are relative to the plan's
/// directory.
pub fn run_file(path: &Path, hosts: &Hosts) -> Result<PlanResult, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.display().to_string(),
        source,
    })?;
    let plan = parse_plan(&text)?;
    let base = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    run_plan(&plan, hosts, base)
}

/// Run a parsed plan. `base_dir` is the directory report paths are relative to.
pub fn run_plan(plan: &Plan, hosts: &Hosts, base_dir: &Path) -> Result<PlanResult, Error> {
    drive::run_plan(plan, hosts, base_dir)
}

#[cfg(test)]
mod tests;
