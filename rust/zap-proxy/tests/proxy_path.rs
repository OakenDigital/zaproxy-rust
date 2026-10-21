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

//! Proxy against a local origin: HTTP, HTTPS MITM, exclude, listeners.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zap_proxy::{
    install_crypto_provider, CertificateAuthority, HttpMessage, HttpResponse, InMemoryHistory,
    LoggingListener, Proxy, ProxyConfig, ProxyListener,
};
use zap_store::{Session, SessionHistoryListener};

const HTTP_BODY: &[u8] = b"origin-http-body";
const HTTPS_BODY: &[u8] = b"origin-https-body";

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zapd-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

async fn spawn_http_origin(status: u16, body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let hits_task = Arc::clone(&hits_task);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_request: Request<Incoming>| {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let response = Response::builder()
                            .status(status)
                            .header(http::header::CONTENT_TYPE, "text/plain")
                            .body(Full::new(Bytes::from_static(body)))
                            .unwrap();
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });
    (addr, hits)
}

async fn spawn_echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(|request: Request<Incoming>| async move {
                    let bytes = request
                        .into_body()
                        .collect()
                        .await
                        .expect("origin body")
                        .to_bytes();
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/octet-stream")
                        .body(Full::new(bytes))
                        .unwrap();
                    Ok::<_, std::convert::Infallible>(response)
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });
    addr
}

async fn spawn_https_origin(
    status: u16,
    body: &'static [u8],
    ca_dir: &Path,
) -> (SocketAddr, String, Arc<AtomicUsize>) {
    install_crypto_provider();
    let ca = CertificateAuthority::open(ca_dir).unwrap();
    let pem = ca.cert_pem().to_string();
    let acceptor = TlsAcceptor::from(ca.server_config("127.0.0.1").unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let hits_task = Arc::clone(&hits_task);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let service = service_fn(move |_request: Request<Incoming>| {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let response = Response::builder()
                            .status(status)
                            .header(http::header::CONTENT_TYPE, "text/plain")
                            .body(Full::new(Bytes::from_static(body)))
                            .unwrap();
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });
    (addr, pem, hits)
}

async fn start_proxy(
    ca_dir: PathBuf,
    exclude: Vec<String>,
    listeners: Vec<Arc<dyn ProxyListener>>,
    extra_root_pems: Vec<String>,
) -> zap_proxy::RunningProxy {
    Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir,
        exclude,
        listeners,
        extra_root_pems,
        history: None,
    })
    .await
    .expect("proxy start")
}

async fn http_exchange(addr: SocketAddr, request: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_http(&mut stream).await
}

fn direct_http(origin: SocketAddr, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    )
}

fn proxy_http(origin: SocketAddr, path: &str) -> String {
    let url = format!("http://127.0.0.1:{}{path}", origin.port());
    format!(
        "GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    )
}

async fn read_headers<R>(reader: &mut R) -> String
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await.expect("response header");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(buf.len() < 65_536, "header too large");
    }
    String::from_utf8(buf).expect("header utf-8")
}

fn status_of(header: &str) -> u16 {
    header.split_whitespace().nth(1).unwrap().parse().unwrap()
}

async fn read_http<R>(reader: &mut R) -> (u16, Vec<u8>)
where
    R: AsyncRead + Unpin,
{
    let header = read_headers(reader).await;
    let status = status_of(&header);
    let mut length = None;
    for line in header.split("\r\n") {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let length = length.unwrap_or_else(|| panic!("no content-length in {header:?}"));
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await.expect("response body");
    (status, body)
}

fn tls_config(ca_pem: &str) -> ClientConfig {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.expect("pem")).expect("trust anchor");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn https_get(addr: SocketAddr, ca_pem: &str, path: &str) -> (u16, Vec<u8>) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(ca_pem)));
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector.connect(name, tcp).await.expect("tls");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        addr.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    read_http(&mut tls).await
}

async fn https_via_proxy(
    proxy: SocketAddr,
    origin: SocketAddr,
    proxy_ca_pem: &str,
    path: &str,
) -> (u16, Vec<u8>) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        origin.port(),
        origin.port()
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let connect_header = read_headers(&mut tcp).await;
    assert_eq!(
        status_of(&connect_header),
        200,
        "CONNECT failed: {connect_header:?}"
    );

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(proxy_ca_pem)));
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector.connect(name, tcp).await.expect("mitm tls");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.port()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    read_http(&mut tls).await
}

struct FlagListener {
    order: i32,
    called: Arc<AtomicBool>,
    stop: bool,
}

impl ProxyListener for FlagListener {
    fn order(&self) -> i32 {
        self.order
    }

    fn on_http_request_send(&self, _: &mut HttpMessage) -> bool {
        self.called.store(true, Ordering::SeqCst);
        !self.stop
    }

    fn on_http_response_receive(&self, _: &mut HttpMessage) -> bool {
        true
    }
}

struct ReplaceListener;

impl ProxyListener for ReplaceListener {
    fn order(&self) -> i32 {
        10
    }

    fn on_http_request_send(&self, msg: &mut HttpMessage) -> bool {
        msg.response = Some(HttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"from-listener"),
        });
        true
    }

    fn on_http_response_receive(&self, _: &mut HttpMessage) -> bool {
        true
    }
}

#[tokio::test]
async fn http_status_and_body_match_the_origin() {
    let (origin, hits) = spawn_http_origin(201, HTTP_BODY).await;
    let dir = temp_dir("http");
    let proxy = start_proxy(
        dir.clone(),
        Vec::new(),
        vec![Arc::new(LoggingListener::new(0))],
        Vec::new(),
    )
    .await;

    let direct = http_exchange(origin, &direct_http(origin, "/hello")).await;
    let proxied = http_exchange(proxy.local_addr(), &proxy_http(origin, "/hello")).await;
    assert_eq!(proxied.0, direct.0);
    assert_eq!(proxied.1, direct.1);
    assert_eq!(proxied.0, 201);
    assert_eq!(proxied.1, HTTP_BODY);
    assert!(hits.load(Ordering::SeqCst) >= 2);

    let urls = proxy.history().urls();
    assert_eq!(urls.len(), 1, "history urls: {urls:?}");
    assert!(urls[0].ends_with("/hello"), "history urls: {urls:?}");

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn chunked_http_body_is_forwarded() {
    let origin = spawn_echo_origin().await;
    let dir = temp_dir("chunk");
    let proxy = start_proxy(dir.clone(), Vec::new(), Vec::new(), Vec::new()).await;
    let request = format!(
        "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        port = origin.port()
    );
    let (status, body) = http_exchange(proxy.local_addr(), &request).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");
    assert_eq!(proxy.history().len(), 1);
    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn https_status_and_body_match_the_origin_and_ca_is_on_disk() {
    let origin_dir = temp_dir("origin-ca");
    let (origin, origin_pem, hits) = spawn_https_origin(202, HTTPS_BODY, &origin_dir).await;
    let proxy_dir = temp_dir("proxy-ca");
    let proxy = start_proxy(
        proxy_dir.clone(),
        Vec::new(),
        Vec::new(),
        vec![origin_pem.clone()],
    )
    .await;

    let cert_path = proxy_dir.join("ca.crt");
    let key_path = proxy_dir.join("ca.key");
    let cert = std::fs::read_to_string(&cert_path).expect("ca.crt");
    let key = std::fs::read_to_string(&key_path).expect("ca.key");
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(key.contains("PRIVATE KEY"));
    assert_eq!(cert, proxy.ca_cert_pem());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "ca.key mode {mode:o}");
    }

    let direct = https_get(origin, &origin_pem, "/secure").await;
    let proxied = https_via_proxy(proxy.local_addr(), origin, proxy.ca_cert_pem(), "/secure").await;
    assert_eq!(proxied, direct);
    assert_eq!(proxied.0, 202);
    assert_eq!(proxied.1, HTTPS_BODY);
    assert!(hits.load(Ordering::SeqCst) >= 2);

    let urls = proxy.history().urls();
    assert_eq!(urls.len(), 1, "history urls: {urls:?}");
    assert!(
        urls[0].starts_with("https://127.0.0.1:"),
        "history urls: {urls:?}"
    );
    assert!(urls[0].ends_with("/secure"), "history urls: {urls:?}");

    proxy.shutdown().await;

    let reloaded = start_proxy(proxy_dir.clone(), Vec::new(), Vec::new(), vec![origin_pem]).await;
    assert_eq!(reloaded.ca_cert_pem(), cert);
    let again = https_via_proxy(
        reloaded.local_addr(),
        origin,
        reloaded.ca_cert_pem(),
        "/secure",
    )
    .await;
    assert_eq!(again.0, 202);
    assert_eq!(again.1, HTTPS_BODY);
    reloaded.shutdown().await;

    let _ = std::fs::remove_dir_all(origin_dir);
    let _ = std::fs::remove_dir_all(proxy_dir);
}

#[tokio::test]
async fn excluded_url_is_forwarded_but_not_stored() {
    let (origin, _hits) = spawn_http_origin(200, b"visible-body").await;
    let called = Arc::new(AtomicBool::new(false));
    let dir = temp_dir("exclude");
    let proxy = start_proxy(
        dir.clone(),
        vec![r"http://127\.0\.0\.1:\d+/secret".to_string()],
        vec![Arc::new(FlagListener {
            order: 1,
            called: Arc::clone(&called),
            stop: false,
        })],
        Vec::new(),
    )
    .await;

    let (secret_status, secret_body) =
        http_exchange(proxy.local_addr(), &proxy_http(origin, "/secret")).await;
    assert!(!called.load(Ordering::SeqCst), "exclude skips listeners");
    assert_eq!(secret_status, 200);
    assert_eq!(secret_body, b"visible-body");
    assert!(proxy.history().is_empty());

    let (status, body) = http_exchange(proxy.local_addr(), &proxy_http(origin, "/kept")).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"visible-body");
    assert!(called.load(Ordering::SeqCst));
    let urls = proxy.history().urls();
    assert_eq!(urls.len(), 1, "history urls: {urls:?}");
    assert!(urls[0].ends_with("/kept"), "history urls: {urls:?}");
    assert!(
        urls.iter().all(|url| !url.contains("/secret")),
        "history urls: {urls:?}"
    );

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn listener_can_replace_the_response_and_skip_the_origin() {
    let (origin, hits) = spawn_http_origin(200, b"from-origin").await;
    let dir = temp_dir("replace");
    let proxy = start_proxy(
        dir.clone(),
        Vec::new(),
        vec![Arc::new(ReplaceListener)],
        Vec::new(),
    )
    .await;

    let (status, body) = http_exchange(proxy.local_addr(), &proxy_http(origin, "/swap")).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"from-listener");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let rows = proxy.history().rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].response_body.as_ref(), b"from-listener");

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn listener_stop_skips_later_listeners_and_the_origin() {
    let (origin, hits) = spawn_http_origin(200, b"from-origin").await;
    let later = Arc::new(AtomicBool::new(false));
    let dir = temp_dir("stop");
    let proxy = start_proxy(
        dir.clone(),
        Vec::new(),
        vec![
            Arc::new(FlagListener {
                order: 20,
                called: Arc::clone(&later),
                stop: false,
            }),
            Arc::new(FlagListener {
                order: 10,
                called: Arc::new(AtomicBool::new(false)),
                stop: true,
            }),
        ],
        Vec::new(),
    )
    .await;

    let (status, body) = http_exchange(proxy.local_addr(), &proxy_http(origin, "/stop")).await;
    assert_eq!(status, 502);
    assert!(!body.is_empty());
    assert!(!later.load(Ordering::SeqCst));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(proxy.history().is_empty());

    proxy.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn phase1_session_survives_restart() {
    let (origin, _) = spawn_http_origin(201, HTTP_BODY).await;
    let dir = temp_dir("session");
    let db_path = dir.join("session.sqlite");
    let ca_dir = dir.join("ca");
    let exclude = vec![r"http://127\.0\.0\.1:\d+/secret".to_string()];

    let session = Arc::new(Session::open(&db_path).unwrap());
    let history = Arc::new(InMemoryHistory::new());
    let proxy = Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir: ca_dir.clone(),
        exclude: exclude.clone(),
        listeners: vec![Arc::new(SessionHistoryListener::new(Arc::clone(&session)))],
        extra_root_pems: Vec::new(),
        history: Some(Arc::clone(&history)),
    })
    .await
    .expect("proxy start");

    let (status, body) = http_exchange(proxy.local_addr(), &proxy_http(origin, "/hello")).await;
    assert_eq!(status, 201);
    assert_eq!(body, HTTP_BODY);
    let (secret_status, secret_body) =
        http_exchange(proxy.local_addr(), &proxy_http(origin, "/secret")).await;
    assert_eq!(secret_status, 201);
    assert_eq!(secret_body, HTTP_BODY);

    let rows = proxy.history().rows();
    assert_eq!(rows.len(), 1, "excluded URL must not be stored");
    assert!(rows[0].url.ends_with("/hello"), "history urls: {rows:?}");
    assert_eq!(rows[0].status, 201);
    assert_eq!(rows[0].response_body.as_ref(), HTTP_BODY);

    proxy.shutdown().await;
    drop(history);
    drop(session);

    let session = Session::open(&db_path).unwrap();
    let stored = session.history_rows().unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].url.ends_with("/hello"), "{}", stored[0].url);
    assert_eq!(stored[0].status, 201);
    assert_eq!(stored[0].method, "GET");
    assert_eq!(stored[0].response_body.as_ref(), HTTP_BODY);
    assert!(stored.iter().all(|row| !row.url.contains("/secret")));
    let nodes = session.site_nodes().unwrap();
    assert!(
        nodes.iter().any(|node| {
            node.history_id == Some(i64::try_from(stored[0].id).unwrap())
                && node.url.ends_with("/hello")
                && node.method.as_deref() == Some("GET")
        }),
        "site nodes: {nodes:?}"
    );

    let history = Arc::new(InMemoryHistory::new());
    history.restore(stored);
    let session = Arc::new(session);
    let proxy = Proxy::start(ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir,
        exclude,
        listeners: vec![Arc::new(SessionHistoryListener::new(Arc::clone(&session)))],
        extra_root_pems: Vec::new(),
        history: Some(Arc::clone(&history)),
    })
    .await
    .expect("proxy restart");

    let reloaded = proxy.history().rows();
    assert_eq!(reloaded.len(), 1);
    assert!(reloaded[0].url.ends_with("/hello"));
    assert_eq!(reloaded[0].status, 201);
    assert_eq!(reloaded[0].response_body.as_ref(), HTTP_BODY);

    let (status, body) = http_exchange(proxy.local_addr(), &proxy_http(origin, "/again")).await;
    assert_eq!(status, 201);
    assert_eq!(body, HTTP_BODY);
    let urls = proxy.history().urls();
    assert_eq!(urls.len(), 2, "history urls: {urls:?}");
    assert!(urls[0].ends_with("/hello"), "history urls: {urls:?}");
    assert!(urls[1].ends_with("/again"), "history urls: {urls:?}");
    assert!(urls.iter().all(|url| !url.contains("/secret")));

    proxy.shutdown().await;
    drop(history);
    drop(session);

    let session = Session::open(&db_path).unwrap();
    let stored = session.history_rows().unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored[0].url.ends_with("/hello"), "{}", stored[0].url);
    assert!(stored[1].url.ends_with("/again"), "{}", stored[1].url);
    assert_eq!(stored[0].response_body.as_ref(), HTTP_BODY);
    assert_eq!(stored[1].response_body.as_ref(), HTTP_BODY);
    assert!(stored.iter().all(|row| !row.url.contains("/secret")));

    let _ = std::fs::remove_dir_all(dir);
}
