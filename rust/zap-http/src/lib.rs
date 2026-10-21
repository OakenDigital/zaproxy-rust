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
// official OWASP ZAP build. The send path follows Paros `HttpSender` as
// carried in the ZAP core.

//! Outbound HTTP/1.1 client (hyper + rustls).
//!
//! Not an official OWASP ZAP build. Every upstream request gets a `Via`
//! header; see [`INJECTED_HEADER_NAMES`].

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use zap_core::{headers_for_forwarding, HttpMessage, HttpResponse};

/// Header names this client may add. Ignore them when diffing headers.
/// Status and body are not rewritten.
pub const INJECTED_HEADER_NAMES: &[&str] = &["via"];

/// Value appended to `Via` on upstream requests.
pub const VIA_VALUE: &str = "1.1 zapd";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Failure talking to an origin.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct UpstreamError(String);

impl UpstreamError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

type Https = hyper_rustls::HttpsConnector<HttpConnector>;

/// Shared origin client. HTTP and HTTPS, HTTP/1.1 only.
#[derive(Clone)]
pub struct UpstreamClient {
    client: Client<Https, Full<Bytes>>,
    timeout: Duration,
}

impl UpstreamClient {
    /// Build a client that trusts the webpki roots plus any extra PEM certificates.
    pub fn new(extra_root_pems: &[String]) -> Result<Self, UpstreamError> {
        install_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for pem in extra_root_pems {
            for cert in read_certs(pem)? {
                roots
                    .add(cert)
                    .map_err(|err| UpstreamError::new(format!("trust anchor rejected: {err}")))?;
            }
        }
        // hyper-rustls sets ALPN from `enable_http1` and panics if it is preset.
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Send `msg` to its absolute URI. Inserts [`VIA_VALUE`] on the request.
    pub async fn send(&self, msg: &mut HttpMessage) -> Result<HttpResponse, UpstreamError> {
        append_via(&mut msg.headers);
        let mut headers = headers_for_forwarding(&msg.headers);
        headers.remove(http::header::HOST);
        let mut builder = Request::builder()
            .method(msg.method.clone())
            .uri(msg.uri.clone());
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Full::new(msg.body.clone()))
            .map_err(|err| UpstreamError::new(format!("request build: {err}")))?;

        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| UpstreamError::new("upstream timed out"))?
            .map_err(|err| UpstreamError::new(format!("upstream: {err}")))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|err| UpstreamError::new(format!("upstream body: {err}")))?
            .to_bytes();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Install the ring crypto provider once. Later calls are ignored.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn read_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, UpstreamError> {
    let mut reader = Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| UpstreamError::new(format!("pem: {err}")))
}

/// Record that this proxy handled the request. Safe to call more than once.
pub fn append_via(headers: &mut HeaderMap) {
    if let Some(existing) = headers.get(http::header::VIA) {
        if let Ok(text) = existing.to_str() {
            if text.split(',').any(|part| part.trim() == VIA_VALUE) {
                return;
            }
            let merged = format!("{text}, {VIA_VALUE}");
            if let Ok(value) = HeaderValue::from_str(&merged) {
                headers.insert(http::header::VIA, value);
            }
            return;
        }
    }
    headers.insert(http::header::VIA, HeaderValue::from_static(VIA_VALUE));
}

#[cfg(test)]
mod tests {
    use super::{append_via, INJECTED_HEADER_NAMES, VIA_VALUE};
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn injected_header_list_names_via() {
        assert!(INJECTED_HEADER_NAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case("via")));
    }

    #[test]
    fn via_is_added_once() {
        let mut headers = HeaderMap::new();
        append_via(&mut headers);
        append_via(&mut headers);
        assert_eq!(
            headers.get(http::header::VIA).unwrap(),
            HeaderValue::from_static(VIA_VALUE)
        );

        headers.insert(http::header::VIA, HeaderValue::from_static("1.1 other"));
        append_via(&mut headers);
        assert_eq!(
            headers.get(http::header::VIA).unwrap().to_str().unwrap(),
            "1.1 other, 1.1 zapd"
        );
    }
}
