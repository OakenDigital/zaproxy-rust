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

//! Intercepting HTTP/1.1 proxy.
//!
//! Not an official OWASP ZAP build. Binds a port, forwards HTTP, tunnels
//! `CONNECT` and terminates TLS with a CA written to disk, stores one
//! in-memory history row per exchange, and runs an ordered listener chain.
//! A valid WebSocket opening handshake is forwarded and the framed bytes
//! are copied both ways; the history row is the handshake, not the frames.
//! A caller can seed that history from a SQLite session and can answer
//! `http://zap/` before the origin is contacted. This crate does not open
//! the database or route the API itself.

#![forbid(unsafe_code)]

mod ca;
mod listeners;
mod server;
mod websocket;

pub use ca::CertificateAuthority;
pub use listeners::{HistoryListener, LoggingListener};
pub use server::{EarlyOverride, Proxy, ProxyConfig, RunningProxy};
pub use zap_core::{
    ChainFlow, ExcludeList, HistoryRow, HttpMessage, HttpResponse, InMemoryHistory, ProxyListener,
    HISTORY_LISTENER_ORDER,
};
pub use zap_http::{install_crypto_provider, UpstreamError, INJECTED_HEADER_NAMES, VIA_VALUE};

use thiserror::Error;

/// Proxy startup or certificate failure.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Exclude(#[from] zap_core::ExcludeError),
    #[error("certificate authority: {0}")]
    Certificate(String),
    #[error("listen: {0}")]
    Listen(#[source] std::io::Error),
    #[error("upstream client: {0}")]
    Upstream(#[from] UpstreamError),
}
