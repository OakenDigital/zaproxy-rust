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

//! What one active rule can see while it scans a message.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use zap_core::{HttpMessage, HttpResponse};
use zap_store::{NewAlert, Session};

use crate::policy::AttackStrength;
use crate::sender::ScanSender;

/// Alert raised by a rule. The session row stores the fields the store has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaisedAlert {
    pub plugin_id: i32,
    pub name: &'static str,
    pub risk: i32,
    pub confidence: i32,
    pub cwe_id: i32,
    pub wasc_id: i32,
    pub param: String,
    pub url: String,
    pub evidence: String,
    pub attack: String,
}

/// Why a send did not return a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    Stopped,
    Failed(String),
}

/// One active rule.
pub trait ActivePlugin: Send + Sync {
    fn plugin_id(&self) -> i32;

    fn name(&self) -> &'static str;

    fn scan(&self, ctx: &ScanContext<'_>);
}

/// Borrowed view of the host process for a single rule invocation.
pub struct ScanContext<'a> {
    base: &'a HttpMessage,
    base_body: &'a str,
    strength: AttackStrength,
    stopped: &'a AtomicBool,
    requests: &'a AtomicUsize,
    alerts: &'a Mutex<Vec<RaisedAlert>>,
    session: &'a Session,
    sender: &'a dyn ScanSender,
}

pub(crate) struct ScanParts<'a> {
    pub base: &'a HttpMessage,
    pub base_body: &'a str,
    pub strength: AttackStrength,
    pub stopped: &'a AtomicBool,
    pub requests: &'a AtomicUsize,
    pub alerts: &'a Mutex<Vec<RaisedAlert>>,
    pub session: &'a Session,
    pub sender: &'a dyn ScanSender,
}

impl<'a> ScanContext<'a> {
    pub(crate) fn new(parts: ScanParts<'a>) -> Self {
        Self {
            base: parts.base,
            base_body: parts.base_body,
            strength: parts.strength,
            stopped: parts.stopped,
            requests: parts.requests,
            alerts: parts.alerts,
            session: parts.session,
            sender: parts.sender,
        }
    }

    pub fn base(&self) -> &HttpMessage {
        self.base
    }

    pub fn base_body(&self) -> &str {
        self.base_body
    }

    pub fn strength(&self) -> AttackStrength {
        self.strength.resolved()
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Send one request unless stop has been requested.
    ///
    /// A stopped scan does not call the sender, so no further request leaves.
    pub fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, SendError> {
        dispatch(self.stopped, self.requests, self.sender, msg)
    }

    pub fn raise(&self, alert: RaisedAlert) {
        let row = NewAlert {
            plugin_id: alert.plugin_id,
            risk: alert.risk,
            confidence: alert.confidence,
            cwe_id: alert.cwe_id,
            wasc_id: alert.wasc_id,
            param: alert.param.clone(),
            url: alert.url.clone(),
        };
        if let Err(err) = self.session.insert_alert(&row) {
            tracing::error!(%err, plugin_id = alert.plugin_id, "active scan alert write failed");
        }
        self.alerts.lock().expect("ascan alerts").push(alert);
    }
}

pub(crate) fn dispatch(
    stopped: &AtomicBool,
    requests: &AtomicUsize,
    sender: &dyn ScanSender,
    msg: &mut HttpMessage,
) -> Result<HttpResponse, SendError> {
    if stopped.load(Ordering::SeqCst) {
        return Err(SendError::Stopped);
    }
    requests.fetch_add(1, Ordering::SeqCst);
    match sender.send(msg) {
        Ok(response) => {
            msg.response = Some(response.clone());
            Ok(response)
        }
        Err(err) => Err(SendError::Failed(err)),
    }
}
