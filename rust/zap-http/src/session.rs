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
// official OWASP ZAP build. Send-as-user follows `HttpSender.sendAuthenticated`
// and `User.processMessageToMatchUser`.

//! Session hook used by [`crate::UpstreamClient::send_as_user`].
//!
//! The concrete user, form and JSON login, and cookie jar live in `zap-auth`.
//! This trait is the sender's view of that session.

use zap_core::{HttpMessage, HttpResponse};

/// What the HTTP client needs in order to send one request as a user.
pub trait SessionManagement: Send {
    /// True until a login attempt has finished for this user.
    fn needs_authentication(&self) -> bool;

    /// GET that refreshes cookies before the login POST. ZAP always requests
    /// the login page URL (or the login URL when the page URL is blank).
    fn login_page_request(&self) -> Option<HttpMessage>;

    /// POST (or GET) that submits the credentials.
    fn login_request(&self) -> HttpMessage;

    /// Rewrite `msg` so it carries the authenticated cookie session.
    fn process_message_to_match_session(&self, msg: &mut HttpMessage);

    /// Keep `Set-Cookie` values from `response` on the session.
    fn extract_web_session(&mut self, request_url: &str, response: &HttpResponse);

    /// Record that the login POST completed, so the next request does not log in again.
    fn note_authenticated(&mut self);
}
