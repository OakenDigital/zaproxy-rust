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

//! The fetched URL set for one static fixture, and out-of-context exclusion.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zap_auth::Context;

use crate::canon::canonicalize;
use crate::options::SpiderOptions;
use crate::sender::{FetchResponse, SpiderSender};
use crate::Spider;

const ABSENT_SUFFIXES: &[&str] = &[
    "/secret/hidden.html",
    "/secret/robots-hidden",
    "/secret/from-sitemap",
    "/app/skip-redirect-body",
    "/app/skip-robots-text",
    "/app/skip-sitemap-text",
    "/app/Fixture",
    "/app/Page",
];

fn html_page(body: &str) -> FetchResponse {
    FetchResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn empty_html() -> FetchResponse {
    html_page("<html><head><title>Page</title></head><body></body></html>")
}

fn response(status: u16, content_type: &str, body: &str, location: Option<&str>) -> FetchResponse {
    let mut headers = vec![("content-type".into(), content_type.to_string())];
    if let Some(location) = location {
        headers.push(("location".into(), location.to_string()));
    }
    FetchResponse {
        status,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

/// Static site whose fetched set is the spider 0.18.0 set for one seed.
fn fixture(origin: &str) -> HashMap<String, FetchResponse> {
    let index = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<title>Fixture</title>
<link href="/app/style.css">
<meta http-equiv="refresh" content="0;url=/app/from-meta">
</head>
<body>
<a href="/app/page.html">page</a>
<a href="/app/page.html#frag">same</a>
<a href="/secret/hidden.html">secret</a>
<a href="http://evil.example/out">out</a>
<a href="mailto:a@b.c">mail</a>
<iframe src="/app/frame.html"></iframe>
<img src="/app/pixel.gif">
<p>{origin}/app/from-paragraph</p>
<!-- {origin}/app/from-comment -->
<form action="/app/search" method="get">
<input type="text" name="q" value="zap">
</form>
<form action="/app/posted" method="post">
<input type="text" name="a" value="1">
</form>
<a href="/app/redir">redir</a>
</body>
</html>"#
    );
    let robots = format!(
        "User-agent: *\nDisallow: /secret/robots-hidden\nAllow: /app/from-robots\nNote {origin}/app/skip-robots-text\n"
    );
    let sitemap = format!(
        r#"<?xml version="1.0"?>
<urlset>
  <url><loc>/app/from-sitemap</loc></url>
  <url><loc>/secret/from-sitemap</loc></url>
</urlset>
<!-- See {origin}/app/skip-sitemap-text -->"#
    );
    let mut pages = HashMap::new();
    pages.insert(format!("{origin}/app/"), html_page(&index));
    pages.insert(
        format!("{origin}/robots.txt"),
        response(200, "text/plain", &robots, None),
    );
    pages.insert(
        format!("{origin}/sitemap.xml"),
        response(200, "application/xml", &sitemap, None),
    );
    pages.insert(
        format!("{origin}/app/redir"),
        response(
            302,
            "text/html",
            "<html><body><a href=\"/app/skip-redirect-body\">no</a></body></html>",
            Some("/app/after-redirect"),
        ),
    );
    pages.insert(
        format!("{origin}/app/style.css"),
        response(200, "text/css", "", None),
    );
    pages.insert(
        format!("{origin}/app/pixel.gif"),
        response(200, "image/gif", "", None),
    );
    for path in [
        "/app/page.html",
        "/app/frame.html",
        "/app/from-meta",
        "/app/from-comment",
        "/app/from-paragraph",
        "/app/from-robots",
        "/app/from-sitemap",
        "/app/after-redirect",
        "/app/search",
        "/app/posted",
    ] {
        pages.insert(format!("{origin}{path}"), empty_html());
    }
    pages
}

fn expected(origin: &str) -> BTreeSet<String> {
    [
        "/app/",
        "/robots.txt",
        "/sitemap.xml",
        "/app/page.html",
        "/app/frame.html",
        "/app/style.css",
        "/app/pixel.gif",
        "/app/search?q=zap",
        "/app/posted",
        "/app/from-robots",
        "/app/from-sitemap",
        "/app/from-meta",
        "/app/from-comment",
        "/app/from-paragraph",
        "/app/redir",
        "/app/after-redirect",
    ]
    .into_iter()
    .map(|path| format!("{origin}{path}"))
    .collect()
}

fn context_xml(origin: &str) -> String {
    format!(
        r#"<configuration>
<context>
<name>spider</name>
<incregexes>{origin}/.*</incregexes>
<excregexes>{origin}/secret.*</excregexes>
</context>
</configuration>"#
    )
}

fn context_for(origin: &str) -> Context {
    Context::from_zap_config(&context_xml(origin)).expect("context")
}

struct MapSender {
    pages: HashMap<String, FetchResponse>,
}

impl SpiderSender for MapSender {
    fn fetch(&self, _method: &str, url: &str, _body: &[u8]) -> Result<FetchResponse, String> {
        Ok(self
            .pages
            .get(url)
            .cloned()
            .unwrap_or_else(|| FetchResponse {
                status: 404,
                headers: vec![("content-type".into(), "text/html".into())],
                body: Vec::new(),
            }))
    }
}

fn crawl_fixture(origin: &str, context: Option<&Context>) -> BTreeSet<String> {
    let spider = Spider::new(Arc::new(MapSender {
        pages: fixture(origin),
    }));
    spider
        .crawl(&format!("{origin}/app/"), context)
        .expect("crawl")
}

fn assert_absent(origin: &str, fetched: &BTreeSet<String>) {
    for suffix in ABSENT_SUFFIXES {
        let url = format!("{origin}{suffix}");
        assert!(!fetched.contains(&url), "{url} was fetched");
    }
    assert!(!fetched.iter().any(|url| url.contains("evil.example")));
    assert!(!fetched.iter().any(|url| url.starts_with("mailto:")));
}

#[test]
fn fetched_set_matches_spider_and_drops_out_of_context() {
    let origin = "http://127.0.0.1:9";
    let context = context_for(origin);
    let fetched = crawl_fixture(origin, Some(&context));
    assert_eq!(fetched, expected(origin));
    assert_absent(origin, &fetched);
}

#[test]
fn without_context_same_host_is_in_scope_and_other_hosts_are_not() {
    let origin = "http://127.0.0.1:9";
    let fetched = crawl_fixture(origin, None);
    let mut with_secrets = expected(origin);
    for path in [
        "/secret/hidden.html",
        "/secret/robots-hidden",
        "/secret/from-sitemap",
    ] {
        with_secrets.insert(format!("{origin}{path}"));
    }
    assert_eq!(fetched, with_secrets);
    assert!(!fetched.iter().any(|url| url.contains("evil.example")));
    assert!(!fetched.contains(&format!("{origin}/app/skip-redirect-body")));
    assert!(!fetched.contains(&format!("{origin}/app/skip-robots-text")));
    assert!(!fetched.contains(&format!("{origin}/app/skip-sitemap-text")));
}

#[test]
fn seed_outside_context_fetches_nothing() {
    let origin = "http://127.0.0.1:9";
    let xml = format!(
        r#"<configuration><context><name>other</name>
        <incregexes>{origin}/other/.*</incregexes>
        </context></configuration>"#
    );
    let context = Context::from_zap_config(&xml).expect("context");
    let fetched = crawl_fixture(origin, Some(&context));
    assert!(fetched.is_empty());
}

#[test]
fn query_parameters_are_sorted_and_non_http_schemes_are_dropped() {
    assert_eq!(
        canonicalize(
            "http://127.0.0.1/app/page.html",
            "/app/page.html?b=2&a=1#frag"
        )
        .as_deref(),
        Some("http://127.0.0.1/app/page.html?a=1&b=2")
    );
    assert_eq!(
        canonicalize("http://127.0.0.1/%7Euser", "http://127.0.0.1/%7Euser").as_deref(),
        Some("http://127.0.0.1/~user")
    );
    assert!(canonicalize("http://127.0.0.1/", "mailto:a@b.c").is_none());
    assert!(canonicalize("http://127.0.0.1/", "javascript:void(0)").is_none());
}

#[test]
fn max_depth_fetches_through_the_limit_and_zero_is_unlimited() {
    let mut pages = HashMap::new();
    for index in 0..8 {
        let next = index + 1;
        let body = if index < 7 {
            format!(r#"<html><body><a href="/d{next}"></a></body></html>"#)
        } else {
            "<html><body></body></html>".to_string()
        };
        pages.insert(format!("http://127.0.0.1:9/d{index}"), html_page(&body));
    }
    let sender = Arc::new(MapSender { pages });
    let limited = Spider::with_options(
        Arc::clone(&sender) as Arc<dyn SpiderSender>,
        SpiderOptions {
            max_depth: 5,
            parse_robots_txt: false,
            parse_sitemap_xml: false,
            ..SpiderOptions::default()
        },
    );
    let fetched = limited.crawl("http://127.0.0.1:9/d0", None).expect("depth");
    let expected_limited: BTreeSet<_> = (0..=5)
        .map(|index| format!("http://127.0.0.1:9/d{index}"))
        .collect();
    assert_eq!(fetched, expected_limited);

    let unlimited = Spider::with_options(
        sender,
        SpiderOptions {
            max_depth: 0,
            parse_robots_txt: false,
            parse_sitemap_xml: false,
            ..SpiderOptions::default()
        },
    );
    let fetched = unlimited
        .crawl("http://127.0.0.1:9/d0", None)
        .expect("unlimited");
    assert_eq!(fetched.len(), 8);
    assert!(fetched.contains("http://127.0.0.1:9/d7"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_sender_fetches_the_same_fixture_set() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let pages = fixture(&origin);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let pages = pages.clone();
            let origin = origin.clone();
            tokio::spawn(async move {
                let request = read_http(&mut socket).await;
                let target = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                let url = if target.starts_with("http://") || target.starts_with("https://") {
                    target
                } else {
                    format!("{origin}{target}")
                };
                let page = pages.get(&url).cloned().unwrap_or_else(|| FetchResponse {
                    status: 404,
                    headers: vec![("content-type".into(), "text/html".into())],
                    body: Vec::new(),
                });
                let reason = match page.status {
                    200 => "OK",
                    302 => "Found",
                    404 => "Not Found",
                    _ => "OK",
                };
                let mut head = format!("HTTP/1.1 {} {reason}\r\n", page.status);
                for (name, value) in &page.headers {
                    head.push_str(name);
                    head.push_str(": ");
                    head.push_str(value);
                    head.push_str("\r\n");
                }
                head.push_str(&format!("Content-Length: {}\r\n", page.body.len()));
                head.push_str("Connection: close\r\n\r\n");
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&page.body).await;
            });
        }
    });

    let origin = format!("http://{addr}");
    let context = context_for(&origin);
    let seed = format!("{origin}/app/");
    let spider = Spider::new(Arc::new(
        crate::DefaultSender::from_current().expect("sender"),
    ));
    let fetched = tokio::task::spawn_blocking(move || spider.crawl(&seed, Some(&context)))
        .await
        .expect("join")
        .expect("crawl");
    assert_eq!(fetched, expected(&origin));
    assert_absent(&origin, &fetched);
}

async fn read_http(socket: &mut tokio::net::TcpStream) -> String {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        socket.read_exact(&mut byte).await.expect("request");
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8(header).unwrap();
    let length = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    if let Some(length) = length {
        if length > 0 {
            let mut body = vec![0_u8; length];
            socket.read_exact(&mut body).await.expect("body");
        }
    }
    text
}
