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

//! HTML links, inline script string literals, and context include/exclude.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use zap_auth::Context;

use crate::sender::{AjaxSender, FetchResponse};
use crate::AjaxSpider;

fn page(body: &str, content_type: &str) -> FetchResponse {
    FetchResponse {
        status: 200,
        headers: vec![("content-type".into(), content_type.into())],
        body: body.as_bytes().to_vec(),
    }
}

fn html(body: &str) -> FetchResponse {
    page(body, "text/html; charset=utf-8")
}

fn empty_html() -> FetchResponse {
    html("<html><body></body></html>")
}

struct MapSender {
    pages: HashMap<String, FetchResponse>,
    fetched: Mutex<Vec<String>>,
}

impl MapSender {
    fn new(pages: HashMap<String, FetchResponse>) -> Self {
        Self {
            pages,
            fetched: Mutex::new(Vec::new()),
        }
    }

    fn fetched(&self) -> BTreeSet<String> {
        self.fetched.lock().unwrap().iter().cloned().collect()
    }
}

impl AjaxSender for MapSender {
    fn fetch(&self, url: &str) -> Result<FetchResponse, String> {
        self.fetched.lock().unwrap().push(url.to_string());
        self.pages
            .get(url)
            .cloned()
            .ok_or_else(|| format!("unexpected fetch {url}"))
    }
}

fn crawl(
    pages: HashMap<String, FetchResponse>,
    seed: &str,
    context: Option<&Context>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let sender = Arc::new(MapSender::new(pages));
    let spider = AjaxSpider::new(sender.clone());
    let urls = spider.crawl(seed, context).unwrap();
    (urls, sender.fetched())
}

#[test]
fn html_links_are_crawled() {
    let seed = "http://app.test/";
    let mut pages = HashMap::new();
    pages.insert(
        seed.to_string(),
        html(
            r#"<!DOCTYPE html>
<html><body>
<a href="/from-anchor">a</a>
<img src="/from-img.png" alt="pic">
<form action="/from-form" method="post"></form>
<a href="mailto:a@b.c">m</a>
<a href="javascript:void(0)">j</a>
<a href="http://other.test/off">off</a>
<p>http://app.test/from-text</p>
<script src="/bundle.js"></script>
</body></html>"#,
        ),
    );
    pages.insert("http://app.test/from-anchor".into(), empty_html());
    pages.insert("http://app.test/from-img.png".into(), page("", "image/png"));
    pages.insert("http://app.test/from-form".into(), empty_html());
    pages.insert(
        "http://app.test/bundle.js".into(),
        page(
            r#"var hidden = "/inside-bundle";"#,
            "application/javascript",
        ),
    );

    let (urls, fetched) = crawl(pages, seed, None);
    let expected = BTreeSet::from([
        "http://app.test/".to_string(),
        "http://app.test/from-anchor".to_string(),
        "http://app.test/from-img.png".to_string(),
        "http://app.test/from-form".to_string(),
        "http://app.test/bundle.js".to_string(),
    ]);
    assert_eq!(urls, expected);
    assert_eq!(fetched, expected);
    assert!(!urls.iter().any(|url| url.contains("from-text")));
    assert!(!urls.iter().any(|url| url.contains("inside-bundle")));
    assert!(!urls.iter().any(|url| url.contains("other.test")));
}

#[test]
fn inline_script_string_literals_are_crawled() {
    let seed = "http://app.test/";
    let mut pages = HashMap::new();
    pages.insert(
        seed.to_string(),
        html(
            r#"<!DOCTYPE html>
<html><body>
<script type="text/javascript">
  var label = "click me";
  var mime = "application/json";
  var abs = "https://app.test/from-literal";
  var path = "/from-path";
  var dot = "./from-dot";
  var up = "../from-up";
  var proto = "//app.test/from-proto";
  var escaped = "http:\/\/app.test\/from-escaped";
  var slash = "http:\u002f\u002fapp.test\u002ffrom-unicode";
  // "/from-comment"
  /* "/from-block" */
  var js = "javascript:alert(1)";
  var tmpl = `/from-template`;
  var interp = `/from-${name}`;
  var off = "http://evil.test/nope";
</script>
<script type="application/json">{"u":"/from-json"}</script>
<script src="/ext.js">
  var hidden = "/from-src-body";
</script>
</body></html>"#,
        ),
    );
    for path in [
        "https://app.test/from-literal",
        "http://app.test/from-path",
        "http://app.test/from-dot",
        "http://app.test/from-up",
        "http://app.test/from-proto",
        "http://app.test/from-escaped",
        "http://app.test/from-unicode",
        "http://app.test/from-template",
        "http://app.test/ext.js",
    ] {
        pages.insert(path.to_string(), empty_html());
    }
    pages.insert(
        "http://app.test/ext.js".into(),
        page(r#"var x = "/inside-ext";"#, "application/javascript"),
    );

    let (urls, fetched) = crawl(pages, seed, None);
    let expected = BTreeSet::from([
        "http://app.test/".to_string(),
        "https://app.test/from-literal".to_string(),
        "http://app.test/from-path".to_string(),
        "http://app.test/from-dot".to_string(),
        "http://app.test/from-up".to_string(),
        "http://app.test/from-proto".to_string(),
        "http://app.test/from-escaped".to_string(),
        "http://app.test/from-unicode".to_string(),
        "http://app.test/from-template".to_string(),
        "http://app.test/ext.js".to_string(),
    ]);
    assert_eq!(urls, expected);
    assert_eq!(fetched, expected);
    for absent in [
        "from-comment",
        "from-block",
        "from-json",
        "from-src-body",
        "inside-ext",
        "evil.test",
        "click",
    ] {
        assert!(
            !urls.iter().any(|url| url.contains(absent)),
            "{absent} was recorded in {urls:?}"
        );
    }
}

#[test]
fn include_and_exclude_regexes_limit_the_crawl() {
    let seed = "http://app.test/start";
    let mut pages = HashMap::new();
    pages.insert(
        seed.to_string(),
        html(
            r#"<!DOCTYPE html>
<html><body>
<a href="/keep">k</a>
<a href="/secret">s</a>
<a href="http://other.test/out">o</a>
<script>
  var a = "/keep-js";
  var b = "/secret-js";
  var c = "http://other.test/js-out";
</script>
</body></html>"#,
        ),
    );
    pages.insert("http://app.test/keep".into(), empty_html());
    pages.insert("http://app.test/keep-js".into(), empty_html());

    let context = Context::from_zap_config(
        r#"<context>
            <name>ajax</name>
            <incregexes>http://app.test/.*</incregexes>
            <excregexes>http://app.test/secret.*</excregexes>
        </context>"#,
    )
    .unwrap();

    let (urls, fetched) = crawl(pages, seed, Some(&context));
    let expected = BTreeSet::from([
        "http://app.test/start".to_string(),
        "http://app.test/keep".to_string(),
        "http://app.test/keep-js".to_string(),
    ]);
    assert_eq!(urls, expected);
    assert_eq!(fetched, expected);

    let excluded = AjaxSpider::new(Arc::new(MapSender::new(HashMap::new())));
    let none = excluded
        .crawl("http://app.test/secret", Some(&context))
        .unwrap();
    assert!(none.is_empty());
}
