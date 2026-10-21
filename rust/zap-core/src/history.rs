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

//! Process-local history. One row per recorded exchange. Nothing is written to disk.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::HeaderMap;

use crate::HttpMessage;

/// One stored exchange.
#[derive(Clone, Debug)]
pub struct HistoryRow {
    pub id: u64,
    pub url: String,
    pub method: String,
    pub status: u16,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Bytes,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Bytes,
    pub recorded_at_ms: u64,
}

#[derive(Debug)]
struct Inner {
    next_id: u64,
    rows: Vec<HistoryRow>,
}

/// In-memory table of proxied exchanges.
#[derive(Debug)]
pub struct InMemoryHistory {
    inner: Mutex<Inner>,
}

impl Default for InMemoryHistory {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_id: 1,
                rows: Vec::new(),
            }),
        }
    }
}

impl InMemoryHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `msg` when it has a response. Returns the new row id.
    pub fn record(&self, msg: &HttpMessage) -> Option<u64> {
        let response = msg.response.as_ref()?;
        let row = HistoryRow {
            id: 0,
            url: msg.url(),
            method: msg.method.to_string(),
            status: response.status.as_u16(),
            request_headers: header_pairs(&msg.headers),
            request_body: msg.body.clone(),
            response_headers: header_pairs(&response.headers),
            response_body: response.body.clone(),
            recorded_at_ms: unix_millis(),
        };
        let mut inner = lock(&self.inner);
        let id = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        let mut row = row;
        row.id = id;
        inner.rows.push(row);
        Some(id)
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn rows(&self) -> Vec<HistoryRow> {
        lock(&self.inner).rows.clone()
    }

    pub fn urls(&self) -> Vec<String> {
        lock(&self.inner)
            .rows
            .iter()
            .map(|row| row.url.clone())
            .collect()
    }

    /// Replace the table with `rows`. The next `record` id is one past the
    /// largest restored id, so a reloaded session keeps assigning the same
    /// ids SQLite will assign.
    pub fn restore(&self, rows: Vec<HistoryRow>) {
        let next_id = rows
            .iter()
            .map(|row| row.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1);
        let mut inner = lock(&self.inner);
        inner.rows = rows;
        inner.next_id = next_id;
    }
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpResponse;
    use bytes::Bytes;
    use http::{Method, StatusCode};

    fn message(url: &str, with_response: bool) -> HttpMessage {
        HttpMessage {
            method: Method::GET,
            uri: url.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"req"),
            response: with_response.then(|| HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"resp"),
            }),
        }
    }

    #[test]
    fn one_row_per_exchange_with_a_response() {
        let history = InMemoryHistory::new();
        assert!(history
            .record(&message("http://example.test/no", false))
            .is_none());
        assert!(history.is_empty());

        let id = history
            .record(&message("http://example.test/yes", true))
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(history.len(), 1);
        let row = &history.rows()[0];
        assert_eq!(row.url, "http://example.test/yes");
        assert_eq!(row.method, "GET");
        assert_eq!(row.status, 200);
        assert_eq!(row.request_body.as_ref(), b"req");
        assert_eq!(row.response_body.as_ref(), b"resp");
    }

    #[test]
    fn restore_replaces_rows_and_continues_ids() {
        let history = InMemoryHistory::new();
        history.restore(vec![HistoryRow {
            id: 7,
            url: "http://example.test/old".into(),
            method: "GET".into(),
            status: 200,
            request_headers: Vec::new(),
            request_body: Bytes::new(),
            response_headers: Vec::new(),
            response_body: Bytes::from_static(b"old"),
            recorded_at_ms: 1,
        }]);
        assert_eq!(history.len(), 1);
        let id = history
            .record(&message("http://example.test/new", true))
            .unwrap();
        assert_eq!(id, 8);
        let rows = history.rows();
        assert_eq!(rows[0].url, "http://example.test/old");
        assert_eq!(rows[0].response_body.as_ref(), b"old");
        assert_eq!(rows[1].url, "http://example.test/new");
        assert_eq!(rows[1].id, 8);
    }
}
