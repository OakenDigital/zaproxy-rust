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

//! PHASE-6 active scan wiring.
//!
//! The ascan API is answered before the core API. Scans use the default
//! HTTP sender. There is no forced user and no login.

use std::sync::Arc;

use zap_api::ApiService;
use zap_ascan::{ActiveScanService, DefaultSender};
use zap_proxy::EarlyOverride;
use zap_store::Session;

/// Active scan service on the default sender.
pub fn start(session: Arc<Session>) -> Result<Arc<ActiveScanService>, String> {
    let sender = DefaultSender::from_current()?;
    Ok(Arc::new(ActiveScanService::new(session, Arc::new(sender))))
}

/// Answer `ascan` routes, then the core and alert API.
pub fn early_override(api: Arc<ApiService>, ascan: Arc<ActiveScanService>) -> EarlyOverride {
    Arc::new(move |message| {
        if ascan.handle(message) {
            return true;
        }
        api.handle(message)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, Method, StatusCode};
    use zap_api::ApiService;
    use zap_ascan::ActiveScanService;
    use zap_core::{HttpMessage, HttpResponse};
    use zap_store::Session;

    use super::early_override;

    struct QuietSender;

    impl zap_ascan::ScanSender for QuietSender {
        fn send(&self, _msg: &mut HttpMessage) -> Result<HttpResponse, String> {
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"<html></html>"),
            })
        }
    }

    fn message(url: &str) -> HttpMessage {
        HttpMessage {
            method: Method::GET,
            uri: url.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            response: None,
        }
    }

    #[test]
    fn ascan_is_answered_before_the_core_api() {
        let mut path = std::env::temp_dir();
        path.push(format!("zap-phase6-{}-api", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let session = Arc::new(Session::open(path.join("session.sqlite")).unwrap());
        let api = Arc::new(ApiService::new(
            Arc::clone(&session),
            "0.1.0",
            Arc::new(|| {}),
        ));
        let ascan = Arc::new(ActiveScanService::new(
            Arc::clone(&session),
            Arc::new(QuietSender),
        ));
        let handle = early_override(api, Arc::clone(&ascan));

        let mut version = message("http://zap/JSON/core/view/version/");
        assert!(handle(&mut version));
        let body = version.response.unwrap().body;
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["version"], "0.1.0");

        let mut scan = message(
            "http://zap/JSON/ascan/action/scan/?url=http://fixture.test/shouldFindCrLfInjection.php%3Fyears%3D1",
        );
        assert!(handle(&mut scan));
        let started: serde_json::Value =
            serde_json::from_slice(&scan.response.unwrap().body).unwrap();
        assert_eq!(started["scan"], "0");
        let id = 0;
        assert!(ascan.wait(id, Duration::from_secs(5)));

        let _ = std::fs::remove_dir_all(path);
    }
}
