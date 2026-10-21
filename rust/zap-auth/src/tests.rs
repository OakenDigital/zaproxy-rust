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

//! Unit tests for context regexes, login bodies, and the cookie jar.

use std::path::PathBuf;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use zap_core::{HttpMessage, HttpResponse};
use zap_http::SessionManagement;

use crate::auth::{form_encode, json_escape};
use crate::context::Context;
use crate::user::User;

fn phase5_config() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase5.context");
    std::fs::read_to_string(path).unwrap()
}

/// Decisions from Java `Pattern.compile(regex, Pattern.CASE_INSENSITIVE)`
/// and `Matcher.matches`, with the query stripped when `indexOf('?') > 0`.
/// In context means included and not excluded (`Context.isInContext`).
#[test]
fn fixed_context_file_matches_zap_include_and_exclude() {
    let context = Context::from_zap_config(&phase5_config()).unwrap();
    assert_eq!(context.name(), "phase5");
    assert_eq!(
        context.include_regexes(),
        ["https://www.example.com/.*".to_string()]
    );
    assert_eq!(
        context.exclude_regexes(),
        [
            "https://www.example.com/logout".to_string(),
            "https://www.example.com/status/.*".to_string(),
        ]
    );

    let cases = [
        ("https://www.example.com/", true, false, true),
        ("https://www.example.com", false, false, false),
        ("https://www.example.com/login.jsp", true, false, true),
        ("HTTPS://WWW.EXAMPLE.COM/Login.jsp", true, false, true),
        ("https://www.example.com/logout", true, true, false),
        ("https://www.example.com/logout/", true, false, true),
        ("https://www.example.com/logout/extra", true, false, true),
        ("https://www.example.com/LOGOUT", true, true, false),
        ("https://www.example.com/status", true, false, true),
        ("https://www.example.com/status/", true, true, false),
        ("https://www.example.com/status/health", true, true, false),
        (
            "https://www.example.com/status/health?x=1",
            true,
            true,
            false,
        ),
        ("https://www.example.com/page?x=1", true, false, true),
        ("https://www.example.com/logout?next=/", true, true, false),
        ("https://other.example/", false, false, false),
        ("http://www.example.com/", false, false, false),
        ("https://www.example.com/app/item", true, false, true),
        ("?https://www.example.com/", false, false, false),
        ("https://www.example.com/status/HEALTH", true, true, false),
    ];
    for (url, included, excluded, in_context) in cases {
        assert_eq!(context.is_included(url), included, "included {url}");
        assert_eq!(context.is_excluded(url), excluded, "excluded {url}");
        assert_eq!(context.is_in_context(url), in_context, "in context {url}");
    }
}

#[test]
fn empty_include_list_matches_nothing_and_bad_regex_is_rejected() {
    let empty = Context::from_zap_config(
        "<configuration><context><name>empty</name></context></configuration>",
    )
    .unwrap();
    assert!(!empty.is_included("https://www.example.com/"));
    assert!(!empty.is_in_context("https://www.example.com/"));

    let err = Context::from_zap_config(
        "<configuration><context><incregexes>(</incregexes></context></configuration>",
    );
    assert!(err.is_err());
}

#[test]
fn form_and_json_bodies_encode_credentials_like_zap() {
    assert_eq!(form_encode("a b"), "a+b");
    assert_eq!(form_encode("p&q"), "p%26q");
    assert_eq!(form_encode("a*b"), "a*b");
    assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");

    let form = User::form(
        "Ada",
        "a b",
        "p&q",
        "http://example.test/login?user={%username%}",
        "username={%username%}&password={%password%}",
        Some("http://example.test/login"),
    )
    .unwrap();
    let login = form.login_request();
    assert_eq!(login.method, Method::POST);
    assert_eq!(login.uri.to_string(), "http://example.test/login?user=a+b");
    assert_eq!(login.body.as_ref(), b"username=a+b&password=p%26q");
    assert_eq!(
        login
            .headers
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/x-www-form-urlencoded; charset=utf-8"
    );
    let page = form.login_page_request().unwrap();
    assert_eq!(page.method, Method::GET);
    assert_eq!(page.uri.to_string(), "http://example.test/login");

    let json = User::json(
        "Ada",
        "a\"b",
        "secret",
        "http://example.test/api/login",
        r#"{"username":"{%username%}","password":"{%password%}"}"#,
        Some("http://example.test/api/login"),
    )
    .unwrap();
    let body = json.login_request().body;
    assert_eq!(body.as_ref(), br#"{"username":"a\"b","password":"secret"}"#);
    assert_eq!(
        json.login_request()
            .headers
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json; charset=utf-8"
    );
}

#[test]
fn context_file_decodes_form_login_body_entities() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<configuration><context><name>form</name>
<authentication><type>2</type><form>
<loginurl>http://example.test/login</loginurl>
<loginbody>username={%username%}&amp;password={%password%}</loginbody>
</form></authentication>
<session><type>0</type></session>
</context></configuration>"#;
    let context = Context::from_zap_config(xml).unwrap();
    let user = User::from_context(&context, "Ada", "alice", "secret").unwrap();
    assert_eq!(
        user.login_request().body.as_ref(),
        b"username=alice&password=secret"
    );
    let rejected = Context::from_zap_config(
        "<configuration><context><session><type>1</type></session></context></configuration>",
    );
    assert!(rejected.is_err());
}

#[test]
fn cookie_session_replaces_same_name_and_keeps_other_cookies() {
    let mut user = User::form(
        "Ada",
        "alice",
        "secret",
        "http://example.test/login",
        "username={%username%}&password={%password%}",
        None,
    )
    .unwrap();
    assert!(user.needs_authentication());

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::SET_COOKIE,
        HeaderValue::from_static("session=form-ok; Path=/"),
    );
    user.extract_web_session(
        "http://example.test/login",
        &HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"ok"),
        },
    );
    user.note_authenticated();
    assert!(!user.needs_authentication());

    let mut follow = HttpMessage {
        method: Method::GET,
        uri: "http://example.test/private".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    follow.headers.insert(
        http::header::COOKIE,
        HeaderValue::from_static("session=stale; theme=dark"),
    );
    user.process_message_to_match_session(&mut follow);
    assert_eq!(
        follow
            .headers
            .get(http::header::COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
        "theme=dark; session=form-ok"
    );

    let mut other_host = HttpMessage {
        method: Method::GET,
        uri: "http://other.test/private".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
        response: None,
    };
    user.process_message_to_match_session(&mut other_host);
    assert!(other_host.headers.get(http::header::COOKIE).is_none());
}
