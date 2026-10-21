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
// official OWASP ZAP build. The listener contract follows Paros
// `ProxyListener` as carried in the ZAP core.

//! Accept loop, HTTP forwarding, and CONNECT MITM.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use zap_core::{
    headers_for_forwarding, plan_after_request, run_request_listeners, run_response_listeners,
    ChainFlow, ExcludeList, HttpMessage, HttpResponse, InMemoryHistory, ProxyListener,
};
use zap_http::{install_crypto_provider, UpstreamClient};

use crate::listeners::HistoryListener;
use crate::CertificateAuthority;
use crate::Error;

const MAX_BODY: usize = 32 * 1024 * 1024;

/// How to bind the proxy and which listeners to run.
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub ca_dir: PathBuf,
    pub exclude: Vec<String>,
    pub listeners: Vec<Arc<dyn ProxyListener>>,
    /// PEM certificates added to the upstream trust store (tests, private origins).
    pub extra_root_pems: Vec<String>,
    /// Seed for the built-in history listener. `None` starts an empty table.
    /// `zapd` passes the rows reloaded from the SQLite session.
    pub history: Option<Arc<InMemoryHistory>>,
    /// Called before exclusions and listeners. When it returns true, the
    /// response already on the message is sent and the origin is not contacted.
    /// `zapd` uses this for `http://zap/` and `https://zap/`.
    pub early_override: Option<EarlyOverride>,
}

/// Handles a request before the proxy applies exclusions or listeners.
pub type EarlyOverride = Arc<dyn Fn(&mut HttpMessage) -> bool + Send + Sync>;

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            ca_dir: PathBuf::from("zapd-ca"),
            exclude: Vec::new(),
            listeners: Vec::new(),
            extra_root_pems: Vec::new(),
            history: None,
            early_override: None,
        }
    }
}

/// A running proxy. Dropping it stops the accept loop.
pub struct RunningProxy {
    local_addr: SocketAddr,
    ca_cert_pem: String,
    ca_dir: PathBuf,
    history: Arc<InMemoryHistory>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl RunningProxy {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_dir(&self) -> &std::path::Path {
        &self.ca_dir
    }

    pub fn history(&self) -> &InMemoryHistory {
        &self.history
    }

    /// Stop accepting connections and wait for the accept loop to finish.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Bind `config.listen` and serve until [`RunningProxy`] is dropped.
pub struct Proxy;

impl Proxy {
    pub async fn start(config: ProxyConfig) -> Result<RunningProxy, Error> {
        install_crypto_provider();
        let exclude = ExcludeList::try_new(&config.exclude)?;
        let ca = CertificateAuthority::open(&config.ca_dir)?;
        let ca_cert_pem = ca.cert_pem().to_string();
        let upstream = UpstreamClient::new(&config.extra_root_pems)?;
        let history = config
            .history
            .unwrap_or_else(|| Arc::new(InMemoryHistory::new()));
        let mut listeners = config.listeners;
        listeners.push(Arc::new(HistoryListener::new(Arc::clone(&history))));

        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(Error::Listen)?;
        let local_addr = listener.local_addr().map_err(Error::Listen)?;
        let state = Arc::new(State {
            listeners,
            exclude,
            upstream,
            ca,
            early_override: config.early_override,
        });
        let (shutdown, watch_rx) = watch::channel(false);
        let task = tokio::spawn(accept_loop(listener, state, watch_rx));
        Ok(RunningProxy {
            local_addr,
            ca_cert_pem,
            ca_dir: config.ca_dir,
            history,
            shutdown,
            task: Some(task),
        })
    }
}

struct State {
    listeners: Vec<Arc<dyn ProxyListener>>,
    exclude: ExcludeList,
    upstream: UpstreamClient,
    ca: CertificateAuthority,
    early_override: Option<EarlyOverride>,
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<State>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(err) = serve_client(stream, state).await {
                                tracing::debug!(%err, "client connection ended");
                            }
                        });
                    }
                    Err(err) => {
                        tracing::debug!(%err, "accept failed");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }
}

async fn serve_client(stream: TcpStream, state: Arc<State>) -> Result<(), hyper::Error> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move {
            let response = handle_request(request, state).await;
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    http1::Builder::new()
        .auto_date_header(false)
        .serve_connection(io, service)
        .with_upgrades()
        .await
}

async fn handle_request(request: Request<Incoming>, state: Arc<State>) -> Response<Full<Bytes>> {
    if request.method() == Method::CONNECT {
        return accept_connect(request, state);
    }
    let uri = match resolve_http_uri(&request) {
        Ok(uri) => uri,
        Err(err) => return client_response(&text_response(StatusCode::BAD_REQUEST, &err)),
    };
    let method = request.method().clone();
    let headers = request.headers().clone();
    let body = match collect_limited(request.into_body()).await {
        Ok(body) => body,
        Err(err) => return client_response(&text_response(StatusCode::BAD_REQUEST, &err)),
    };
    let mut message = HttpMessage {
        method,
        uri,
        headers,
        body,
        response: None,
    };
    let response = proxy_message(&mut message, &state).await;
    client_response(&response)
}

fn accept_connect(request: Request<Incoming>, state: Arc<State>) -> Response<Full<Bytes>> {
    let Some(authority) = request.uri().authority().cloned() else {
        return client_response(&text_response(
            StatusCode::BAD_REQUEST,
            "CONNECT is missing an authority",
        ));
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => {
                if let Err(err) = mitm(upgraded, host, port, state).await {
                    tracing::debug!(%err, "mitm ended");
                }
            }
            Err(err) => tracing::debug!(%err, "CONNECT upgrade failed"),
        }
    });
    Response::new(Full::new(Bytes::new()))
}

async fn mitm(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    port: u16,
    state: Arc<State>,
) -> Result<(), String> {
    let config = state
        .ca
        .server_config(&host)
        .map_err(|err| err.to_string())?;
    let acceptor = TlsAcceptor::from(config);
    let tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(|err| err.to_string())?;
    let authority = format_authority(&host, port);
    serve_tunneled(tls, authority, state).await;
    Ok(())
}

async fn serve_tunneled<S>(stream: S, authority: String, state: Arc<State>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        let authority = authority.clone();
        async move {
            let response = handle_tunneled(request, &authority, &state).await;
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    if let Err(err) = http1::Builder::new()
        .auto_date_header(false)
        .serve_connection(io, service)
        .await
    {
        tracing::debug!(%err, "tunneled connection ended");
    }
}

async fn handle_tunneled(
    request: Request<Incoming>,
    authority: &str,
    state: &State,
) -> Response<Full<Bytes>> {
    let uri = match resolve_https_uri(authority, request.uri()) {
        Ok(uri) => uri,
        Err(err) => return client_response(&text_response(StatusCode::BAD_REQUEST, &err)),
    };
    let method = request.method().clone();
    let headers = request.headers().clone();
    let body = match collect_limited(request.into_body()).await {
        Ok(body) => body,
        Err(err) => return client_response(&text_response(StatusCode::BAD_REQUEST, &err)),
    };
    let mut message = HttpMessage {
        method,
        uri,
        headers,
        body,
        response: None,
    };
    let response = proxy_message(&mut message, state).await;
    client_response(&response)
}

async fn proxy_message(message: &mut HttpMessage, state: &State) -> HttpResponse {
    if let Some(handler) = &state.early_override {
        if handler(message) {
            return message.response.clone().unwrap_or_else(|| {
                text_response(StatusCode::BAD_GATEWAY, "handler did not set a response")
            });
        }
    }
    if state.exclude.excludes(&message.url()) {
        return match state.upstream.send(message).await {
            Ok(response) => response,
            Err(err) => text_response(StatusCode::BAD_GATEWAY, &err.to_string()),
        };
    }

    let flow = run_request_listeners(&state.listeners, message);
    let plan = plan_after_request(flow, message);
    if plan.contact_origin {
        message.response = Some(match state.upstream.send(message).await {
            Ok(response) => response,
            Err(err) => text_response(StatusCode::BAD_GATEWAY, &err.to_string()),
        });
    }
    if plan.notify_response_listeners {
        let response_flow = run_response_listeners(&state.listeners, message);
        if matches!(response_flow, ChainFlow::Stopped { .. }) {
            tracing::debug!(url = %message.url(), "response listener stopped the chain");
        }
    }
    message
        .response
        .clone()
        .unwrap_or_else(|| text_response(StatusCode::BAD_GATEWAY, "listener stopped the request"))
}

fn resolve_http_uri(request: &Request<Incoming>) -> Result<Uri, String> {
    if request.uri().scheme().is_some() {
        return Ok(request.uri().clone());
    }
    let host = request
        .headers()
        .get(http::header::HOST)
        .ok_or_else(|| "origin-form request is missing Host".to_string())?
        .to_str()
        .map_err(|_| "Host is not valid text".to_string())?;
    join_origin("http", host, request.uri())
}

fn resolve_https_uri(authority: &str, uri: &Uri) -> Result<Uri, String> {
    if uri.scheme().is_some() {
        return Ok(uri.clone());
    }
    join_origin("https", authority, uri)
}

fn join_origin(scheme: &str, authority: &str, uri: &Uri) -> Result<Uri, String> {
    let path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|err| format!("bad target URI: {err}"))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn collect_limited(body: Incoming) -> Result<Bytes, String> {
    let bytes = body
        .collect()
        .await
        .map_err(|err| format!("reading body: {err}"))?
        .to_bytes();
    if bytes.len() > MAX_BODY {
        return Err(format!("body exceeds {MAX_BODY} bytes"));
    }
    Ok(bytes)
}

fn text_response(status: StatusCode, message: &str) -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    HttpResponse {
        status,
        headers,
        body: Bytes::from(format!("zapd: {message}\n")),
    }
}

fn client_response(response: &HttpResponse) -> Response<Full<Bytes>> {
    let mut headers = headers_for_forwarding(&response.headers);
    if let Ok(length) = HeaderValue::from_str(&response.body.len().to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, length);
    }
    let mut out = Response::new(Full::new(response.body.clone()));
    *out.status_mut() = response.status;
    *out.headers_mut() = headers;
    out
}
