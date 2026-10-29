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
// official OWASP ZAP build.

//! WebSocket upgrade on an already-accepted proxy connection.
//!
//! The opening handshake is an ordinary exchange: listeners run, and history
//! stores that request and the `101`. After the `101` is written, the framed
//! bytes are copied both ways and are not parsed or stored.

use bytes::Bytes;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::Full;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use zap_core::{
    plan_after_request, run_request_listeners, run_response_listeners, ChainFlow, HttpMessage,
    HttpResponse,
};

use crate::server::{client_response, text_response, State};

pub(crate) async fn proxy_websocket(
    message: &mut HttpMessage,
    client_upgrade: OnUpgrade,
    state: &State,
) -> Response<Full<Bytes>> {
    if let Some(handler) = &state.early_override {
        if handler(message) {
            let response = message.response.clone().unwrap_or_else(|| {
                text_response(StatusCode::BAD_GATEWAY, "handler did not set a response")
            });
            return client_response(&response);
        }
    }

    let excluded = state.exclude.excludes(&message.url());
    let mut origin = None;
    if excluded {
        match state.upstream.open_websocket(message).await {
            Ok(handshake) => {
                origin = handshake.origin;
                message.response = Some(handshake.response);
            }
            Err(err) => {
                message.response = Some(text_response(StatusCode::BAD_GATEWAY, &err.to_string()));
            }
        }
    } else {
        let flow = run_request_listeners(&state.listeners, message);
        let plan = plan_after_request(flow, message);
        if plan.contact_origin {
            match state.upstream.open_websocket(message).await {
                Ok(handshake) => {
                    origin = handshake.origin;
                    message.response = Some(handshake.response);
                }
                Err(err) => {
                    message.response =
                        Some(text_response(StatusCode::BAD_GATEWAY, &err.to_string()));
                }
            }
        }
        if plan.notify_response_listeners {
            let response_flow = run_response_listeners(&state.listeners, message);
            if matches!(response_flow, ChainFlow::Stopped { .. }) {
                tracing::debug!(url = %message.url(), "response listener stopped the chain");
            }
        }
    }

    let response = message
        .response
        .clone()
        .unwrap_or_else(|| text_response(StatusCode::BAD_GATEWAY, "listener stopped the request"));
    if response.status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(origin) = origin {
            spawn_tunnel(client_upgrade, origin);
            return switching_response(&response);
        }
    }
    client_response(&response)
}

fn switching_response(response: &HttpResponse) -> Response<Full<Bytes>> {
    let mut out = Response::new(Full::new(Bytes::new()));
    *out.status_mut() = response.status;
    *out.headers_mut() = switching_response_headers(&response.headers);
    out
}

/// `Connection` and `Upgrade` stay so the client can finish the handshake.
/// A length is not added; the following bytes are frames.
fn switching_response_headers(src: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in src.iter() {
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        if matches!(
            name.as_str(),
            "keep-alive"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "proxy-authorization"
                | "proxy-authenticate"
        ) {
            continue;
        }
        headers.append(name, value.clone());
    }
    headers
}

fn spawn_tunnel(client_upgrade: OnUpgrade, origin: hyper::upgrade::Upgraded) {
    tokio::spawn(async move {
        let client = match client_upgrade.await {
            Ok(io) => io,
            Err(err) => {
                tracing::debug!(%err, "client websocket upgrade failed");
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let mut origin = TokioIo::new(origin);
        if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut origin).await {
            tracing::debug!(%err, "websocket tunnel ended");
        }
    });
}
