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
// official OWASP ZAP build. Scheduling follows `HostProcess`: one host,
// rules in order, stop before the next request.

//! Host process and scan ids.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use zap_core::HttpMessage;
use zap_store::Session;

use crate::context::{dispatch, ActivePlugin, RaisedAlert, ScanContext, ScanParts};
use crate::policy::{AttackStrength, Policy};
use crate::rules::{CrlfInjectionScanRule, XpathInjectionScanRule};
use crate::sender::ScanSender;

/// Options for one scan. `recurse` is recorded; this phase scans the seed only.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub policy: Policy,
    pub recurse: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            recurse: true,
        }
    }
}

struct ScanState {
    progress: AtomicU32,
    stopped: AtomicBool,
    requests: AtomicUsize,
    alerts: Mutex<Vec<RaisedAlert>>,
    strength: AttackStrength,
    recurse: bool,
    host: Mutex<String>,
    done: Mutex<bool>,
    done_cv: Condvar,
}

impl ScanState {
    fn new(_id: i32, options: &ScanOptions) -> Self {
        Self {
            progress: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            requests: AtomicUsize::new(0),
            alerts: Mutex::new(Vec::new()),
            strength: options.policy.strength,
            recurse: options.recurse,
            host: Mutex::new(String::new()),
            done: Mutex::new(false),
            done_cv: Condvar::new(),
        }
    }

    fn finish(&self) {
        self.progress.store(100, Ordering::SeqCst);
        let mut done = self.done.lock().expect("ascan done");
        *done = true;
        self.done_cv.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let guard = self.done.lock().expect("ascan done");
        let (guard, _) = self
            .done_cv
            .wait_timeout_while(guard, timeout, |done| !*done)
            .expect("ascan done wait");
        *guard
    }
}

/// Active scans for one session.
pub struct Engine {
    session: Arc<Session>,
    sender: Arc<dyn ScanSender>,
    plugins: Vec<Arc<dyn ActivePlugin>>,
    scans: Mutex<HashMap<i32, Arc<ScanState>>>,
    order: Mutex<Vec<i32>>,
    next_id: AtomicI32,
}

impl Engine {
    pub fn new(session: Arc<Session>, sender: Arc<dyn ScanSender>) -> Self {
        Self::with_plugins(session, sender, default_plugins())
    }

    pub fn with_plugins(
        session: Arc<Session>,
        sender: Arc<dyn ScanSender>,
        plugins: Vec<Arc<dyn ActivePlugin>>,
    ) -> Self {
        Self {
            session,
            sender,
            plugins,
            scans: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            next_id: AtomicI32::new(0),
        }
    }

    /// Start a scan of `seed` and return the scan id. The first id is 0.
    pub fn start(&self, seed: HttpMessage, options: ScanOptions) -> i32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let state = Arc::new(ScanState::new(id, &options));
        self.scans
            .lock()
            .expect("ascan scans")
            .insert(id, Arc::clone(&state));
        self.order.lock().expect("ascan order").push(id);
        let sender = Arc::clone(&self.sender);
        let plugins = self.plugins.clone();
        let session = Arc::clone(&self.session);
        std::thread::spawn(move || run_host(state, seed, options, sender, plugins, session));
        id
    }

    pub fn status(&self, id: i32) -> Option<u32> {
        let scan = self.scan(id)?;
        if scan.stopped.load(Ordering::SeqCst) {
            Some(100)
        } else {
            Some(scan.progress.load(Ordering::SeqCst))
        }
    }

    pub fn stop(&self, id: i32) -> bool {
        let Some(scan) = self.scan(id) else {
            return false;
        };
        scan.stopped.store(true, Ordering::SeqCst);
        true
    }

    pub fn last_id(&self) -> Option<i32> {
        self.order.lock().expect("ascan order").last().copied()
    }

    pub fn alerts(&self, id: i32) -> Option<Vec<RaisedAlert>> {
        self.scan(id)
            .map(|scan| scan.alerts.lock().expect("ascan alerts").clone())
    }

    pub fn request_count(&self, id: i32) -> Option<usize> {
        self.scan(id)
            .map(|scan| scan.requests.load(Ordering::SeqCst))
    }

    pub fn strength(&self, id: i32) -> Option<AttackStrength> {
        self.scan(id).map(|scan| scan.strength.resolved())
    }

    pub fn recurse(&self, id: i32) -> Option<bool> {
        self.scan(id).map(|scan| scan.recurse)
    }

    pub fn host(&self, id: i32) -> Option<String> {
        self.scan(id)
            .map(|scan| scan.host.lock().expect("ascan host").clone())
    }

    pub fn wait(&self, id: i32, timeout: Duration) -> bool {
        self.scan(id).is_some_and(|scan| scan.wait(timeout))
    }

    fn scan(&self, id: i32) -> Option<Arc<ScanState>> {
        self.scans.lock().expect("ascan scans").get(&id).cloned()
    }
}

fn default_plugins() -> Vec<Arc<dyn ActivePlugin>> {
    vec![
        Arc::new(CrlfInjectionScanRule),
        Arc::new(XpathInjectionScanRule),
    ]
}

fn run_host(
    state: Arc<ScanState>,
    mut seed: HttpMessage,
    options: ScanOptions,
    sender: Arc<dyn ScanSender>,
    plugins: Vec<Arc<dyn ActivePlugin>>,
    session: Arc<Session>,
) {
    {
        let mut host = state.host.lock().expect("ascan host");
        *host = host_key(&seed);
    }
    if seed.response.is_none() {
        let mut baseline = seed.clone();
        match dispatch(
            &state.stopped,
            &state.requests,
            sender.as_ref(),
            &mut baseline,
        ) {
            Ok(response) => seed.response = Some(response),
            Err(_) => {
                state.finish();
                return;
            }
        }
    }
    let base_body = seed
        .response
        .as_ref()
        .map(|response| String::from_utf8_lossy(&response.body).into_owned())
        .unwrap_or_default();
    let enabled: Vec<_> = plugins
        .iter()
        .filter(|plugin| options.policy.enables(plugin.plugin_id()))
        .cloned()
        .collect();
    let total = enabled.len();
    if total == 0 {
        state.finish();
        return;
    }
    for (index, plugin) in enabled.iter().enumerate() {
        if state.stopped.load(Ordering::SeqCst) {
            break;
        }
        let ctx = context(&state, &seed, &base_body, &session, sender.as_ref());
        plugin.scan(&ctx);
        if !state.stopped.load(Ordering::SeqCst) {
            let progress = ((index as u32 + 1) * 100) / total as u32;
            state.progress.store(progress, Ordering::SeqCst);
        }
    }
    state.finish();
}

fn context<'a>(
    state: &'a ScanState,
    base: &'a HttpMessage,
    base_body: &'a str,
    session: &'a Session,
    sender: &'a dyn ScanSender,
) -> ScanContext<'a> {
    ScanContext::new(ScanParts {
        base,
        base_body,
        strength: state.strength,
        stopped: &state.stopped,
        requests: &state.requests,
        alerts: &state.alerts,
        session,
        sender,
    })
}

/// Authority of the seed, which is the host process key.
pub fn host_key(msg: &HttpMessage) -> String {
    msg.uri
        .authority()
        .map(|authority| authority.to_string())
        .unwrap_or_default()
}
