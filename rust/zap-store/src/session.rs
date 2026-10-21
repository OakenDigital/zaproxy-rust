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
// official OWASP ZAP build. The tables follow the Paros history, site,
// and alert model carried in the ZAP core.

//! Open a session file and read or write its rows.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, Uri};
use rusqlite::{params, Connection, OptionalExtension};
use zap_core::{HistoryRow, HttpMessage};

use crate::{AlertRow, NewAlert};

const SCHEMA_VERSION: i32 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER NOT NULL,
    request_headers TEXT NOT NULL,
    request_body BLOB NOT NULL,
    response_headers TEXT NOT NULL,
    response_body BLOB NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS site_node (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL DEFAULT 0,
    segment TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT,
    history_id INTEGER,
    UNIQUE(parent_id, segment)
);
CREATE TABLE IF NOT EXISTS alert (
    id INTEGER PRIMARY KEY,
    plugin_id INTEGER NOT NULL,
    risk INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    cwe_id INTEGER NOT NULL,
    wasc_id INTEGER NOT NULL,
    param TEXT NOT NULL,
    url TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR REPLACE INTO session_meta (key, value) VALUES ('schema', '1');
";

/// Failure opening a session or reading a stored row.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("session schema version {found} is not supported")]
    Schema { found: i32 },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stored row: {0}")]
    Row(String),
    #[error("session path: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// One node in the site tree. `parent_id` is `None` for a host node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteNode {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub segment: String,
    pub url: String,
    pub method: Option<String>,
    pub history_id: Option<i64>,
}

/// SQLite session. The connection is mutex-guarded so the proxy can share it.
pub struct Session {
    conn: Mutex<Connection>,
}

impl Session {
    /// Open or create `path` and apply the schema when the file is new.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// `user_version` of the open database. New files are version 1.
    pub fn schema_version(&self) -> Result<i32> {
        let conn = lock(&self.conn);
        Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Insert `msg` when it has a response, and upsert its site nodes.
    ///
    /// Returns the new history id. A message with no response is ignored.
    pub fn record_exchange(&self, msg: &HttpMessage) -> Result<Option<i64>> {
        let Some(response) = msg.response.as_ref() else {
            return Ok(None);
        };
        let request_headers = headers_json(&msg.headers)?;
        let response_headers = headers_json(&response.headers)?;
        let recorded_at_ms = i64::try_from(unix_millis())
            .map_err(|_| Error::Row("timestamp does not fit in sqlite".into()))?;
        let conn = lock(&self.conn);
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO history (
                method, url, status, request_headers, request_body,
                response_headers, response_body, recorded_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                msg.method.to_string(),
                msg.url(),
                i64::from(response.status.as_u16()),
                request_headers,
                msg.body.as_ref(),
                response_headers,
                response.body.as_ref(),
                recorded_at_ms,
            ],
        )?;
        let history_id = tx.last_insert_rowid();
        upsert_site(&tx, msg, history_id)?;
        tx.commit()?;
        Ok(Some(history_id))
    }

    pub fn history_rows(&self) -> Result<Vec<HistoryRow>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, method, url, status, request_headers, request_body,
                    response_headers, response_body, recorded_at_ms
             FROM history ORDER BY id",
        )?;
        let raw = stmt.query_map([], |row| {
            Ok(RawHistory {
                id: row.get(0)?,
                method: row.get(1)?,
                url: row.get(2)?,
                status: row.get(3)?,
                request_headers: row.get(4)?,
                request_body: row.get(5)?,
                response_headers: row.get(6)?,
                response_body: row.get(7)?,
                recorded_at_ms: row.get(8)?,
            })
        })?;
        let mut rows = Vec::new();
        for row in raw {
            rows.push(row?.into_history()?);
        }
        Ok(rows)
    }

    pub fn site_nodes(&self) -> Result<Vec<SiteNode>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, parent_id, segment, url, method, history_id
             FROM site_node ORDER BY id",
        )?;
        let mapped = stmt.query_map([], |row| {
            let parent: i64 = row.get(1)?;
            Ok(SiteNode {
                id: row.get(0)?,
                parent_id: (parent != 0).then_some(parent),
                segment: row.get(2)?,
                url: row.get(3)?,
                method: row.get(4)?,
                history_id: row.get(5)?,
            })
        })?;
        let mut nodes = Vec::new();
        for node in mapped {
            nodes.push(node?);
        }
        Ok(nodes)
    }

    /// Insert an alert. The id is the SQLite row id.
    pub fn insert_alert(&self, alert: &NewAlert) -> Result<i64> {
        let conn = lock(&self.conn);
        conn.execute(
            "INSERT INTO alert (
                plugin_id, risk, confidence, cwe_id, wasc_id, param, url
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                alert.plugin_id,
                alert.risk,
                alert.confidence,
                alert.cwe_id,
                alert.wasc_id,
                alert.param,
                alert.url,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn alert(&self, id: i64) -> Result<Option<AlertRow>> {
        let conn = lock(&self.conn);
        let row = conn
            .query_row(
                "SELECT id, plugin_id, risk, confidence, cwe_id, wasc_id, param, url
                 FROM alert WHERE id = ?1",
                [id],
                map_alert,
            )
            .optional()?;
        Ok(row)
    }

    pub fn alerts(&self) -> Result<Vec<AlertRow>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, plugin_id, risk, confidence, cwe_id, wasc_id, param, url
             FROM alert ORDER BY id",
        )?;
        let mapped = stmt.query_map([], map_alert)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }
}

struct RawHistory {
    id: i64,
    method: String,
    url: String,
    status: i64,
    request_headers: String,
    request_body: Vec<u8>,
    response_headers: String,
    response_body: Vec<u8>,
    recorded_at_ms: i64,
}

impl RawHistory {
    fn into_history(self) -> Result<HistoryRow> {
        Ok(HistoryRow {
            id: u64::try_from(self.id).map_err(|_| Error::Row(format!("id {}", self.id)))?,
            method: self.method,
            url: self.url,
            status: u16::try_from(self.status)
                .map_err(|_| Error::Row(format!("status {}", self.status)))?,
            request_headers: serde_json::from_str(&self.request_headers)?,
            request_body: Bytes::from(self.request_body),
            response_headers: serde_json::from_str(&self.response_headers)?,
            response_body: Bytes::from(self.response_body),
            recorded_at_ms: u64::try_from(self.recorded_at_ms)
                .map_err(|_| Error::Row(format!("timestamp {}", self.recorded_at_ms)))?,
        })
    }
}

fn map_alert(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
    Ok(AlertRow {
        id: row.get(0)?,
        plugin_id: row.get(1)?,
        risk: row.get(2)?,
        confidence: row.get(3)?,
        cwe_id: row.get(4)?,
        wasc_id: row.get(5)?,
        param: row.get(6)?,
        url: row.get(7)?,
    })
}

struct SitePiece {
    segment: String,
    url: String,
    leaf: bool,
}

fn site_pieces(uri: &Uri) -> Vec<SitePiece> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .unwrap_or("");
    let host = format!("{scheme}://{authority}");
    let parts: Vec<&str> = uri
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return vec![SitePiece {
            segment: host,
            url: uri.to_string(),
            leaf: true,
        }];
    }
    let mut pieces = Vec::with_capacity(parts.len() + 1);
    pieces.push(SitePiece {
        segment: host.clone(),
        url: host.clone(),
        leaf: false,
    });
    let mut accumulated = host;
    for (index, part) in parts.iter().enumerate() {
        accumulated.push('/');
        accumulated.push_str(part);
        let leaf = index + 1 == parts.len();
        pieces.push(SitePiece {
            segment: (*part).to_string(),
            url: if leaf {
                uri.to_string()
            } else {
                accumulated.clone()
            },
            leaf,
        });
    }
    pieces
}

fn upsert_site(tx: &rusqlite::Transaction<'_>, msg: &HttpMessage, history_id: i64) -> Result<()> {
    let mut parent_id = 0_i64;
    let method_name = msg.method.to_string();
    for piece in site_pieces(&msg.uri) {
        let method = piece.leaf.then(|| method_name.clone());
        let history = piece.leaf.then_some(history_id);
        parent_id = tx.query_row(
            "INSERT INTO site_node (parent_id, segment, url, method, history_id)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(parent_id, segment) DO UPDATE SET
               url = excluded.url,
               method = COALESCE(excluded.method, site_node.method),
               history_id = COALESCE(excluded.history_id, site_node.history_id)
             RETURNING id",
            params![parent_id, piece.segment, piece.url, method, history],
            |row| row.get(0),
        )?;
    }
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(Error::Schema { found: version });
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(SCHEMA)?;
    tx.commit()?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn headers_json(headers: &HeaderMap) -> Result<String> {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    Ok(serde_json::to_string(&pairs)?)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn lock(mutex: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
