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
// official OWASP ZAP build. The user session follows `org.zaproxy.zap.users.User`.

//! A context user with username and password credentials.

use zap_core::{HttpMessage, HttpResponse};
use zap_http::SessionManagement;

use crate::auth::{LoginKind, LoginSpec};
use crate::context::Context;
use crate::cookies::CookieJar;
use crate::Error;

/// One user. Pass it to `UpstreamClient::send_as_user`.
pub struct User {
    name: String,
    username: String,
    password: String,
    login: LoginSpec,
    jar: CookieJar,
    authenticated: bool,
}

impl User {
    /// Form authentication. A missing login page URL uses the login URL, as ZAP does.
    pub fn form(
        name: &str,
        username: &str,
        password: &str,
        login_url: &str,
        login_body: &str,
        login_page_url: Option<&str>,
    ) -> Result<Self, Error> {
        Self::new(
            name,
            username,
            password,
            LoginSpec::parse(LoginKind::Form, login_url, login_body, login_page_url)?,
        )
    }

    /// JSON authentication. A missing login page URL uses the login URL.
    pub fn json(
        name: &str,
        username: &str,
        password: &str,
        login_url: &str,
        login_body: &str,
        login_page_url: Option<&str>,
    ) -> Result<Self, Error> {
        Self::new(
            name,
            username,
            password,
            LoginSpec::parse(LoginKind::Json, login_url, login_body, login_page_url)?,
        )
    }

    /// User for a context whose file configured form or JSON authentication.
    pub fn from_context(
        context: &Context,
        name: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let login = context.config().login.as_ref().ok_or_else(|| {
            Error::Config(format!(
                "context {} has no form or JSON authentication",
                context.name()
            ))
        })?;
        Self::new(
            name,
            username,
            password,
            LoginSpec::parse(
                login.kind,
                &login.login_url,
                &login.login_body,
                Some(&login.login_page_url),
            )?,
        )
    }

    fn new(name: &str, username: &str, password: &str, login: LoginSpec) -> Result<Self, Error> {
        if username.is_empty() {
            return Err(Error::Config("username is empty".to_string()));
        }
        Ok(Self {
            name: name.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            login,
            jar: CookieJar::default(),
            authenticated: false,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl SessionManagement for User {
    fn needs_authentication(&self) -> bool {
        !self.authenticated
    }

    fn login_page_request(&self) -> Option<HttpMessage> {
        Some(self.login.page_request())
    }

    fn login_request(&self) -> HttpMessage {
        self.login.login_request(&self.username, &self.password)
    }

    fn process_message_to_match_session(&self, msg: &mut HttpMessage) {
        self.jar.apply(&msg.url(), &mut msg.headers);
    }

    fn extract_web_session(&mut self, request_url: &str, response: &HttpResponse) {
        self.jar.store_response(request_url, response);
    }

    fn note_authenticated(&mut self) {
        self.authenticated = true;
    }
}
