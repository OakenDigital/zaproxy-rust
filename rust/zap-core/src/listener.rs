// Copyright 2010-2024 The ZAP Development Team
// Copyright (C) 2003-2004 Chinotec Technologies Company
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
// official OWASP ZAP build. Ordering and the true/false return follow
// Paros `ProxyListener` as carried in the ZAP core.

//! Ordered proxy listeners.
//!
//! A listener may mutate the message, set [`crate::HttpMessage::response`]
//! (the origin is then skipped), or return `false` to stop later listeners.

use std::sync::Arc;

use crate::HttpMessage;

/// History uses this order so earlier listeners' edits are what gets stored.
/// Listeners with a greater order still run; the stored row does not include
/// edits they make after history records.
pub const HISTORY_LISTENER_ORDER: i32 = 5_000;

/// Notification hook for a proxied HTTP exchange.
///
/// `order` is ascending: a smaller value runs first. Equal orders keep
/// registration order (stable sort).
pub trait ProxyListener: Send + Sync {
    fn order(&self) -> i32;

    /// Called before the origin is contacted.
    ///
    /// Return `true` to notify later listeners. Return `false` to stop the
    /// request chain and skip the origin. A response already stored on `msg`
    /// is what the client receives.
    fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool;

    /// Called after a response exists and before it is sent to the client.
    ///
    /// Return `true` to notify later listeners. Return `false` to stop the
    /// response chain. The response already on `msg` is still sent.
    fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool;
}

/// Result of walking one side of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainFlow {
    Continue,
    Stopped { order: i32 },
}

/// What the proxy should do after the request chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangePlan {
    /// Contact the origin only when every request listener returned true and
    /// none of them supplied a response.
    pub contact_origin: bool,
    /// Response listeners run only when every request listener returned true.
    pub notify_response_listeners: bool,
}

/// Decide origin I/O from the request-chain result.
pub fn plan_after_request(flow: ChainFlow, msg: &HttpMessage) -> ExchangePlan {
    ExchangePlan {
        contact_origin: matches!(flow, ChainFlow::Continue) && msg.response.is_none(),
        notify_response_listeners: matches!(flow, ChainFlow::Continue),
    }
}

/// Run request listeners. `listeners` is sorted by [`ProxyListener::order`].
pub fn run_request_listeners(
    listeners: &[Arc<dyn ProxyListener>],
    msg: &mut HttpMessage,
) -> ChainFlow {
    run(listeners, msg, true)
}

/// Run response listeners. `listeners` is sorted by [`ProxyListener::order`].
pub fn run_response_listeners(
    listeners: &[Arc<dyn ProxyListener>],
    msg: &mut HttpMessage,
) -> ChainFlow {
    run(listeners, msg, false)
}

fn run(listeners: &[Arc<dyn ProxyListener>], msg: &mut HttpMessage, request: bool) -> ChainFlow {
    let mut ordered = listeners.to_vec();
    ordered.sort_by_key(|listener| listener.order());
    for listener in ordered {
        let proceed = if request {
            listener.on_http_request_send(msg)
        } else {
            listener.on_http_response_receive(msg)
        };
        if !proceed {
            return ChainFlow::Stopped {
                order: listener.order(),
            };
        }
    }
    ChainFlow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpResponse;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, StatusCode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn message() -> HttpMessage {
        HttpMessage {
            method: Method::GET,
            uri: "http://example.test/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        }
    }

    struct Probe {
        order: i32,
        log: Arc<Mutex<Vec<(char, i32)>>>,
        stop_request: bool,
        stop_response: bool,
    }

    impl ProxyListener for Probe {
        fn order(&self) -> i32 {
            self.order
        }

        fn on_http_request_send(&self, _: &mut HttpMessage) -> bool {
            self.log.lock().unwrap().push(('q', self.order));
            !self.stop_request
        }

        fn on_http_response_receive(&self, _: &mut HttpMessage) -> bool {
            self.log.lock().unwrap().push(('r', self.order));
            !self.stop_response
        }
    }

    fn probe(
        order: i32,
        log: &Arc<Mutex<Vec<(char, i32)>>>,
        stop_request: bool,
        stop_response: bool,
    ) -> Arc<dyn ProxyListener> {
        Arc::new(Probe {
            order,
            log: Arc::clone(log),
            stop_request,
            stop_response,
        })
    }

    #[test]
    fn listeners_run_in_ascending_order_on_both_sides() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let listeners = vec![
            probe(30, &log, false, false),
            probe(10, &log, false, false),
            probe(20, &log, false, false),
        ];
        let mut msg = message();
        assert_eq!(
            run_request_listeners(&listeners, &mut msg),
            ChainFlow::Continue
        );
        msg.response = Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"ok"),
        });
        assert_eq!(
            run_response_listeners(&listeners, &mut msg),
            ChainFlow::Continue
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![
                ('q', 10),
                ('q', 20),
                ('q', 30),
                ('r', 10),
                ('r', 20),
                ('r', 30),
            ]
        );
    }

    #[test]
    fn earlier_listener_mutation_is_visible_to_later_ones() {
        struct SetHeader;
        impl ProxyListener for SetHeader {
            fn order(&self) -> i32 {
                1
            }
            fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
                msg.headers
                    .insert("x-mutated", HeaderValue::from_static("yes"));
                true
            }
            fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
                if let Some(response) = msg.response.as_mut() {
                    response.body = Bytes::from_static(b"changed");
                }
                true
            }
        }

        let saw_header = Arc::new(AtomicBool::new(false));
        let saw_body = Arc::new(AtomicBool::new(false));
        struct See {
            saw_header: Arc<AtomicBool>,
            saw_body: Arc<AtomicBool>,
        }
        impl ProxyListener for See {
            fn order(&self) -> i32 {
                2
            }
            fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
                let matched = msg
                    .headers
                    .get("x-mutated")
                    .and_then(|value| value.to_str().ok())
                    == Some("yes");
                self.saw_header.store(matched, Ordering::SeqCst);
                true
            }
            fn on_http_response_receive(&self, msg: &mut HttpMessage) -> bool {
                let matched = msg
                    .response
                    .as_ref()
                    .map(|response| response.body.as_ref() == b"changed")
                    .unwrap_or(false);
                self.saw_body.store(matched, Ordering::SeqCst);
                true
            }
        }

        let listeners: Vec<Arc<dyn ProxyListener>> = vec![
            Arc::new(See {
                saw_header: Arc::clone(&saw_header),
                saw_body: Arc::clone(&saw_body),
            }),
            Arc::new(SetHeader),
        ];
        let mut msg = message();
        run_request_listeners(&listeners, &mut msg);
        msg.response = Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"origin"),
        });
        run_response_listeners(&listeners, &mut msg);
        assert!(saw_header.load(Ordering::SeqCst));
        assert!(saw_body.load(Ordering::SeqCst));
    }

    #[test]
    fn response_replacement_skips_origin_and_continues_the_chain() {
        struct Replace;
        impl ProxyListener for Replace {
            fn order(&self) -> i32 {
                1
            }
            fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
                msg.response = Some(HttpResponse {
                    status: StatusCode::CREATED,
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"from-listener"),
                });
                true
            }
            fn on_http_response_receive(&self, _: &mut HttpMessage) -> bool {
                true
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        struct Later {
            calls: Arc<AtomicUsize>,
        }
        impl ProxyListener for Later {
            fn order(&self) -> i32 {
                2
            }
            fn on_http_request_send(&self, _: &mut HttpMessage) -> bool {
                self.calls.fetch_add(1, Ordering::SeqCst);
                true
            }
            fn on_http_response_receive(&self, _: &mut HttpMessage) -> bool {
                true
            }
        }

        let listeners: Vec<Arc<dyn ProxyListener>> = vec![
            Arc::new(Later {
                calls: Arc::clone(&calls),
            }),
            Arc::new(Replace),
        ];
        let mut msg = message();
        let flow = run_request_listeners(&listeners, &mut msg);
        let plan = plan_after_request(flow, &msg);
        assert_eq!(flow, ChainFlow::Continue);
        assert!(!plan.contact_origin);
        assert!(plan.notify_response_listeners);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(msg.response.unwrap().body.as_ref(), b"from-listener");
    }

    #[test]
    fn stop_on_request_skips_later_listeners_and_the_origin() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let listeners = vec![probe(20, &log, false, false), probe(10, &log, true, false)];
        let mut msg = message();
        let flow = run_request_listeners(&listeners, &mut msg);
        assert_eq!(flow, ChainFlow::Stopped { order: 10 });
        let plan = plan_after_request(flow, &msg);
        assert!(!plan.contact_origin);
        assert!(!plan.notify_response_listeners);
        assert_eq!(*log.lock().unwrap(), vec![('q', 10)]);
    }

    #[test]
    fn stop_on_response_skips_later_response_listeners() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let listeners = vec![probe(20, &log, false, false), probe(10, &log, false, true)];
        let mut msg = message();
        msg.response = Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"origin"),
        });
        let flow = run_response_listeners(&listeners, &mut msg);
        assert_eq!(flow, ChainFlow::Stopped { order: 10 });
        assert_eq!(*log.lock().unwrap(), vec![('r', 10)]);
        assert_eq!(msg.response.unwrap().body.as_ref(), b"origin");
    }
}
