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
// official OWASP ZAP build. Holding a message until Forward or Drop follows
// the manual break that the proxy milestone left for the desktop.

//! Request and response breakpoints.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use bytes::Bytes;
use http::HeaderValue;
use zap_core::{HttpMessage, ProxyListener};

/// Runs before history so a dropped exchange is not stored.
pub const BREAK_LISTENER_ORDER: i32 = 1;

/// Which side of the exchange is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakSide {
    Request,
    Response,
}

impl BreakSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// What the UI shows while a message is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiting {
    pub id: u64,
    pub side: BreakSide,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub body: String,
    pub text: String,
}

#[derive(Clone, Debug)]
enum Action {
    Forward(String),
    Drop,
}

#[derive(Debug)]
struct Held {
    id: u64,
    side: BreakSide,
    method: String,
    url: String,
    status: Option<u16>,
    body: String,
    text: String,
    decision: Option<Action>,
}

/// Queue of messages waiting for Forward or Drop.
#[derive(Debug)]
pub struct Breakpoint {
    request_on: AtomicBool,
    response_on: AtomicBool,
    next_id: AtomicU64,
    queue: Mutex<VecDeque<Held>>,
    cv: Condvar,
}

impl Breakpoint {
    pub fn new() -> Self {
        Self {
            request_on: AtomicBool::new(false),
            response_on: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }

    pub fn request_enabled(&self) -> bool {
        self.request_on.load(Ordering::SeqCst)
    }

    pub fn response_enabled(&self) -> bool {
        self.response_on.load(Ordering::SeqCst)
    }

    pub fn set_request_enabled(&self, enabled: bool) {
        self.request_on.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.release(BreakSide::Request);
        }
    }

    pub fn set_response_enabled(&self, enabled: bool) {
        self.response_on.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.release(BreakSide::Response);
        }
    }

    /// Oldest message that still has no decision.
    pub fn waiting(&self) -> Option<Waiting> {
        let queue = self.queue.lock().expect("break queue");
        queue
            .iter()
            .find(|held| held.decision.is_none())
            .map(waiting_of)
    }

    /// Apply Forward to `id`. Returns false when that id is not waiting.
    pub fn forward(&self, id: u64, body: String) -> bool {
        self.decide(id, Action::Forward(body))
    }

    /// Apply Drop to `id`. Returns false when that id is not waiting.
    pub fn drop_message(&self, id: u64) -> bool {
        self.decide(id, Action::Drop)
    }

    fn side_enabled(&self, side: BreakSide) -> bool {
        match side {
            BreakSide::Request => self.request_enabled(),
            BreakSide::Response => self.response_enabled(),
        }
    }

    fn decide(&self, id: u64, action: Action) -> bool {
        let mut queue = self.queue.lock().expect("break queue");
        let Some(held) = queue.iter_mut().find(|held| held.id == id) else {
            return false;
        };
        if held.decision.is_some() {
            return false;
        }
        held.decision = Some(action);
        self.cv.notify_all();
        true
    }

    fn release(&self, side: BreakSide) {
        let mut queue = self.queue.lock().expect("break queue");
        for held in queue.iter_mut().filter(|held| held.side == side) {
            if held.decision.is_none() {
                held.decision = Some(Action::Forward(held.body.clone()));
            }
        }
        self.cv.notify_all();
    }

    fn hold(&self, side: BreakSide, preview: Preview) -> Action {
        if !self.side_enabled(side) {
            return Action::Forward(preview.body);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut queue = self.queue.lock().expect("break queue");
            queue.push_back(Held {
                id,
                side,
                method: preview.method,
                url: preview.url,
                status: preview.status,
                body: preview.body,
                text: preview.text,
                decision: None,
            });
        }
        self.cv.notify_all();
        self.wait(id)
    }

    fn wait(&self, id: u64) -> Action {
        let wait = || {
            let mut queue = self.queue.lock().expect("break queue");
            loop {
                let enabled = queue
                    .iter()
                    .find(|held| held.id == id)
                    .is_some_and(|held| self.side_enabled(held.side));
                if let Some(held) = queue.iter_mut().find(|held| held.id == id) {
                    if held.decision.is_none() && !enabled {
                        held.decision = Some(Action::Forward(held.body.clone()));
                    }
                    if held.decision.is_some() {
                        let position = queue
                            .iter()
                            .position(|held| held.id == id)
                            .expect("held id");
                        return queue
                            .remove(position)
                            .expect("held id")
                            .decision
                            .expect("decision");
                    }
                } else {
                    return Action::Forward(String::new());
                }
                queue = self.cv.wait(queue).expect("break wait");
            }
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(wait)
        } else {
            wait()
        }
    }
}

impl Default for Breakpoint {
    fn default() -> Self {
        Self::new()
    }
}

fn waiting_of(held: &Held) -> Waiting {
    Waiting {
        id: held.id,
        side: held.side,
        method: held.method.clone(),
        url: held.url.clone(),
        status: held.status,
        body: held.body.clone(),
        text: held.text.clone(),
    }
}

struct Preview {
    method: String,
    url: String,
    status: Option<u16>,
    body: String,
    text: String,
}

/// Proxy listener that pauses while break is on for that side.
pub struct BreakListener {
    breakpoint: Arc<Breakpoint>,
}

impl BreakListener {
    pub fn new(breakpoint: Arc<Breakpoint>) -> Self {
        Self { breakpoint }
    }
}

impl ProxyListener for BreakListener {
    fn order(&self) -> i32 {
        BREAK_LISTENER_ORDER
    }

    fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
        if !self.breakpoint.request_enabled() {
            return true;
        }
        let action = self
            .breakpoint
            .hold(BreakSide::Request, preview_request(msg));
        apply(msg, BreakSide::Request, action)
    }

    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
        if !self.breakpoint.response_enabled() {
            return true;
        }
        let action = self
            .breakpoint
            .hold(BreakSide::Response, preview_response(msg));
        apply(msg, BreakSide::Response, action)
    }
}

fn preview_request(msg: &HttpMessage) -> Preview {
    let body = String::from_utf8_lossy(&msg.body).into_owned();
    let text = message_text(
        &format!("{} {}", msg.method, msg.url()),
        &header_block(&msg.headers),
        &body,
    );
    Preview {
        method: msg.method.to_string(),
        url: msg.url(),
        status: None,
        body,
        text,
    }
}

fn preview_response(msg: &HttpMessage) -> Preview {
    let status = msg
        .response
        .as_ref()
        .map(|response| response.status.as_u16());
    let headers = msg
        .response
        .as_ref()
        .map(|response| header_block(&response.headers))
        .unwrap_or_default();
    let body = msg
        .response
        .as_ref()
        .map(|response| String::from_utf8_lossy(&response.body).into_owned())
        .unwrap_or_default();
    let status_line = status
        .map(|code| format!("HTTP/1.1 {code}"))
        .unwrap_or_else(|| "HTTP/1.1".to_string());
    Preview {
        method: msg.method.to_string(),
        url: msg.url(),
        status,
        body: body.clone(),
        text: message_text(&status_line, &headers, &body),
    }
}

fn header_block(headers: &http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())))
        .collect::<Vec<_>>()
        .join("\n")
}

fn message_text(start: &str, headers: &str, body: &str) -> String {
    if headers.is_empty() {
        format!("{start}\n\n{body}")
    } else {
        format!("{start}\n{headers}\n\n{body}")
    }
}

fn apply(msg: &mut HttpMessage, side: BreakSide, action: Action) -> bool {
    match action {
        Action::Drop => {
            if side == BreakSide::Response {
                msg.response = None;
            }
            false
        }
        Action::Forward(body) => {
            match side {
                BreakSide::Request => {
                    set_length(&mut msg.headers, body.len());
                    msg.body = Bytes::from(body);
                }
                BreakSide::Response => {
                    if let Some(response) = msg.response.as_mut() {
                        set_length(&mut response.headers, body.len());
                        response.body = Bytes::from(body);
                    }
                }
            }
            true
        }
    }
}

fn set_length(headers: &mut http::HeaderMap, length: usize) {
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
}
