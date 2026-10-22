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

//! Local page for the desktop. It is not the `http://zap/` API.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::breakpoint::Breakpoint;
use crate::view::{sites_text, snapshot, Snapshot};
use zap_store::Session;

/// Shared state the page reads.
pub struct UiState {
    pub session: Arc<Session>,
    pub breakpoint: Arc<Breakpoint>,
    pub proxy_addr: SocketAddr,
}

pub async fn serve(
    listener: TcpListener,
    state: Arc<UiState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = handle(stream, &state).await {
                        tracing::debug!(%err, "desktop ui connection closed");
                    }
                });
            }
        }
    }
}

async fn handle(mut stream: TcpStream, state: &UiState) -> Result<(), String> {
    let request = read_request(&mut stream).await?;
    let response = respond(&request, state);
    stream
        .write_all(&response)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

struct Incoming {
    method: String,
    path: String,
    query: String,
    body: String,
}

fn respond(request: &Incoming, state: &UiState) -> Vec<u8> {
    let selected = history_query(&request.query);
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => match page(state, selected) {
            Ok(html) => http_response(200, "text/html; charset=utf-8", html.into_bytes()),
            Err(response) => response,
        },
        ("GET", "/state.json") => snapshot(state.session.as_ref(), &state.breakpoint, selected)
            .map(|shot| {
                http_response(
                    200,
                    "application/json; charset=utf-8",
                    serde_json::to_vec(&state_json(&shot, state.proxy_addr)).unwrap_or_default(),
                )
            })
            .unwrap_or_else(|err| {
                http_response(
                    500,
                    "text/plain; charset=utf-8",
                    format!("session: {err}\n").into_bytes(),
                )
            }),
        ("POST", "/break/request") => toggle(state, true, &request.body),
        ("POST", "/break/response") => toggle(state, false, &request.body),
        ("POST", "/break/forward") => {
            let form = form_pairs(&request.body);
            let id = form
                .iter()
                .find(|(key, _)| key == "id")
                .and_then(|(_, value)| value.parse::<u64>().ok());
            let body = form
                .iter()
                .find(|(key, _)| key == "body")
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            match id {
                Some(id) if state.breakpoint.forward(id, body) => redirect("/"),
                _ => http_response(
                    409,
                    "text/plain; charset=utf-8",
                    b"no breakpoint\n".to_vec(),
                ),
            }
        }
        ("POST", "/break/drop") => {
            let id = form_pairs(&request.body)
                .into_iter()
                .find(|(key, _)| key == "id")
                .and_then(|(_, value)| value.parse::<u64>().ok());
            match id {
                Some(id) if state.breakpoint.drop_message(id) => redirect("/"),
                _ => http_response(
                    409,
                    "text/plain; charset=utf-8",
                    b"no breakpoint\n".to_vec(),
                ),
            }
        }
        _ => http_response(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
    }
}

fn toggle(state: &UiState, request_side: bool, body: &str) -> Vec<u8> {
    let enabled = form_pairs(body)
        .into_iter()
        .find(|(key, _)| key == "enabled")
        .is_none_or(|(_, value)| !value.eq_ignore_ascii_case("false"));
    if request_side {
        state.breakpoint.set_request_enabled(enabled);
    } else {
        state.breakpoint.set_response_enabled(enabled);
    }
    redirect("/")
}

fn page(state: &UiState, selected: Option<u64>) -> Result<String, Vec<u8>> {
    let shot = snapshot(state.session.as_ref(), &state.breakpoint, selected).map_err(|err| {
        http_response(
            500,
            "text/plain; charset=utf-8",
            format!("session: {err}\n").into_bytes(),
        )
    })?;
    Ok(render_page(&shot, state.proxy_addr, selected))
}

fn state_json(shot: &Snapshot, proxy: SocketAddr) -> Value {
    json!({
        "proxy": proxy.to_string(),
        "requestBreak": shot.request_break,
        "responseBreak": shot.response_break,
        "sites": sites_text(&shot.sites),
        "history": shot.history.iter().map(|row| json!({
            "id": row.id,
            "method": row.method,
            "url": row.url,
            "status": row.status,
        })).collect::<Vec<_>>(),
        "alerts": shot.alerts.iter().map(|alert| json!({
            "id": alert.id,
            "pluginId": alert.plugin_id,
            "risk": alert.risk,
            "confidence": alert.confidence,
            "param": alert.param,
            "url": alert.url,
        })).collect::<Vec<_>>(),
        "message": shot.message.as_ref().map(|message| json!({
            "id": message.id,
            "request": message.request,
            "response": message.response,
        })),
        "breakpoint": shot.breakpoint.as_ref().map(|waiting| json!({
            "id": waiting.id,
            "side": waiting.side.as_str(),
            "method": waiting.method,
            "url": waiting.url,
            "status": waiting.status,
            "body": waiting.body,
            "text": waiting.text,
        })),
    })
}

fn render_page(shot: &Snapshot, proxy: SocketAddr, selected: Option<u64>) -> String {
    let request = shot
        .message
        .as_ref()
        .map(|message| message.request.as_str())
        .unwrap_or("");
    let response = shot
        .message
        .as_ref()
        .map(|message| message.response.as_str())
        .unwrap_or("");
    let history = shot
        .history
        .iter()
        .map(|row| {
            let mark = if selected == Some(row.id) {
                " selected"
            } else {
                ""
            };
            format!(
                "<li class=\"row{mark}\"><a href=\"/?history={}\">{} {} {}</a></li>",
                row.id,
                escape(&row.method),
                escape(&row.url),
                row.status
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let alerts = if shot.alerts.is_empty() {
        "<li>No alerts.</li>".to_string()
    } else {
        shot.alerts
            .iter()
            .map(|alert| {
                format!(
                    "<li>plugin {} risk {} {} param {}</li>",
                    alert.plugin_id,
                    alert.risk,
                    escape(&alert.url),
                    escape(&alert.param)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let sites = escape(&sites_text(&shot.sites));
    let sites = if sites.is_empty() {
        "No sites yet.".to_string()
    } else {
        sites
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>zap desktop</title>
<style>
body {{ font: 15px/1.45 ui-sans-serif, sans-serif; margin: 0; color: #1c1917; background: #f6f3ee; }}
header {{ background: #292524; color: #faf7f2; padding: 16px 24px; }}
header p {{ margin: 4px 0; }}
main {{ display: grid; grid-template-columns: 280px 1fr; gap: 16px; padding: 16px; }}
section {{ background: #fff; border: 1px solid #e7e5e4; padding: 12px 14px; }}
h2 {{ margin: 0 0 8px; font-size: 15px; }}
pre, textarea {{ white-space: pre-wrap; word-break: break-word; background: #f5f5f4; padding: 8px; width: 100%; box-sizing: border-box; }}
textarea {{ min-height: 8rem; }}
.cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
button {{ margin-right: 8px; }}
a {{ color: #9a3412; }}
</style>
</head>
<body>
<header>
<h1>zap desktop</h1>
<p>Proxy <code>{proxy}</code>. Point a client at that address. This page is the UI.</p>
<p>Not an official OWASP ZAP build. zapd does not include this page.</p>
<p>
{break_forms}
<a href="/">Refresh</a>
</p>
</header>
<main>
<div>
<section>
<h2>Sites</h2>
<pre id="sites">{sites}</pre>
</section>
<section>
<h2>History</h2>
<ul id="history">{history}</ul>
</section>
<section>
<h2>Alerts</h2>
<ul id="alerts">{alerts}</ul>
</section>
</div>
<div>
<section>
<h2>Breakpoint</h2>
<div id="breakpoint" data-id="{breakpoint_id}">{breakpoint}</div>
</section>
<section class="cols">
<div>
<h2>Request</h2>
<pre id="request">{request}</pre>
</div>
<div>
<h2>Response</h2>
<pre id="response">{response}</pre>
</div>
</section>
</div>
</main>
{script}
</body>
</html>
"#,
        proxy = escape(&proxy.to_string()),
        break_forms = break_toggles(shot),
        sites = sites,
        history = if history.is_empty() {
            "<li>No history yet.</li>".to_string()
        } else {
            history
        },
        alerts = alerts,
        breakpoint = breakpoint_html(shot),
        breakpoint_id = shot
            .breakpoint
            .as_ref()
            .map(|waiting| waiting.id.to_string())
            .unwrap_or_default(),
        request = escape(request),
        response = escape(response),
        script = POLL_SCRIPT,
    )
}

/// Refreshes the views from `/state.json`. Rebuilds the breakpoint form only
/// when the held id changes, so a typed body is not wiped on each tick.
const POLL_SCRIPT: &str = r##"<script>
(function () {
  function text(id, value) {
    var node = document.getElementById(id);
    if (node && node.textContent !== value) node.textContent = value;
  }
  function historyQuery() {
    var params = new URLSearchParams(location.search);
    var history = params.get("history");
    return history ? "?history=" + encodeURIComponent(history) : "";
  }
  function fillHistory(rows) {
    var list = document.getElementById("history");
    if (!list) return;
    var selected = new URLSearchParams(location.search).get("history");
    list.replaceChildren();
    if (!rows || rows.length === 0) {
      var empty = document.createElement("li");
      empty.textContent = "No history yet.";
      list.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var item = document.createElement("li");
      if (String(row.id) === selected) item.className = "row selected";
      else item.className = "row";
      var link = document.createElement("a");
      link.href = "/?history=" + encodeURIComponent(row.id);
      link.textContent = row.method + " " + row.url + " " + row.status;
      item.appendChild(link);
      list.appendChild(item);
    });
  }
  function fillAlerts(rows) {
    var list = document.getElementById("alerts");
    if (!list) return;
    list.replaceChildren();
    if (!rows || rows.length === 0) {
      var empty = document.createElement("li");
      empty.textContent = "No alerts.";
      list.appendChild(empty);
      return;
    }
    rows.forEach(function (alert) {
      var item = document.createElement("li");
      item.textContent = "plugin " + alert.pluginId + " risk " + alert.risk + " " + alert.url + " param " + (alert.param || "");
      list.appendChild(item);
    });
  }
  function fillBreakpoint(waiting) {
    var box = document.getElementById("breakpoint");
    if (!box) return;
    var id = waiting ? String(waiting.id) : "";
    if (box.dataset.id === id) return;
    box.dataset.id = id;
    box.replaceChildren();
    if (!waiting) {
      box.textContent = "No breakpoint.";
      return;
    }
    var heading = document.createElement("p");
    heading.textContent = "Holding " + waiting.side + " " + waiting.method + " " + waiting.url;
    var preview = document.createElement("pre");
    preview.textContent = waiting.text || "";
    var forward = document.createElement("form");
    forward.method = "post";
    forward.action = "/break/forward";
    var hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = "id";
    hidden.value = id;
    var label = document.createElement("label");
    label.appendChild(document.createTextNode("Body"));
    var area = document.createElement("textarea");
    area.name = "body";
    area.value = waiting.body || "";
    label.appendChild(area);
    var submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Forward";
    forward.appendChild(hidden);
    forward.appendChild(label);
    forward.appendChild(submit);
    var drop = document.createElement("form");
    drop.method = "post";
    drop.action = "/break/drop";
    var dropId = document.createElement("input");
    dropId.type = "hidden";
    dropId.name = "id";
    dropId.value = id;
    var dropButton = document.createElement("button");
    dropButton.type = "submit";
    dropButton.textContent = "Drop";
    drop.appendChild(dropId);
    drop.appendChild(dropButton);
    box.appendChild(heading);
    box.appendChild(preview);
    box.appendChild(forward);
    box.appendChild(drop);
  }
  function tick() {
    fetch("/state.json" + historyQuery(), { cache: "no-store" })
      .then(function (response) { return response.json(); })
      .then(function (state) {
        text("sites", state.sites && state.sites.length ? state.sites : "No sites yet.");
        fillHistory(state.history);
        fillAlerts(state.alerts);
        var message = state.message || {};
        text("request", message.request || "");
        text("response", message.response || "");
        fillBreakpoint(state.breakpoint);
      })
      .catch(function () {});
  }
  setInterval(tick, 400);
})();
</script>"##;

fn break_toggles(shot: &Snapshot) -> String {
    let request = if shot.request_break {
        toggle_form("/break/request", "false", "Stop request break")
    } else {
        toggle_form("/break/request", "true", "Break on requests")
    };
    let response = if shot.response_break {
        toggle_form("/break/response", "false", "Stop response break")
    } else {
        toggle_form("/break/response", "true", "Break on responses")
    };
    format!("{request} {response}")
}

fn toggle_form(action: &str, enabled: &str, label: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{action}\" style=\"display:inline\"><input type=\"hidden\" name=\"enabled\" value=\"{enabled}\"><button type=\"submit\">{label}</button></form>"
    )
}

fn breakpoint_html(shot: &Snapshot) -> String {
    let Some(waiting) = &shot.breakpoint else {
        return "No breakpoint.".to_string();
    };
    format!(
        "<p>Holding {side} {method} {url}</p><pre>{text}</pre><form method=\"post\" action=\"/break/forward\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><label>Body<textarea name=\"body\">{body}</textarea></label><button type=\"submit\">Forward</button></form><form method=\"post\" action=\"/break/drop\"><input type=\"hidden\" name=\"id\" value=\"{id}\"><button type=\"submit\">Drop</button></form>",
        side = waiting.side.as_str(),
        method = escape(&waiting.method),
        url = escape(&waiting.url),
        text = escape(&waiting.text),
        id = waiting.id,
        body = escape(&waiting.body),
    )
}

fn redirect(location: &str) -> Vec<u8> {
    let body = b"See Other\n";
    format!(
        "HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn http_response(status: u16, content_type: &str, body: Vec<u8>) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        303 => "See Other",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    head.into_bytes().into_iter().chain(body).collect()
}

fn history_query(query: &str) -> Option<u64> {
    form_pairs(query)
        .into_iter()
        .find(|(key, _)| key == "history")
        .and_then(|(_, value)| value.parse().ok())
}

fn form_pairs(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let name = form_decode(parts.next().unwrap_or(""));
            let value = form_decode(parts.next().unwrap_or(""));
            (name, value)
        })
        .collect()
}

fn form_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (from_hex(bytes[index + 1]), from_hex(bytes[index + 2]))
                {
                    out.push((high << 4) | low);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn read_request(stream: &mut TcpStream) -> Result<Incoming, String> {
    let header = read_until(stream, b"\r\n\r\n", 64 * 1024).await?;
    let text = String::from_utf8_lossy(&header);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut length = 0usize;
    for line in lines {
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            length = value.parse().unwrap_or(0);
        }
    }
    if length > 1024 * 1024 {
        return Err("ui body too large".to_string());
    }
    let mut body = vec![0; length];
    if length > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(Incoming {
        method,
        path: path.to_string(),
        query: query.to_string(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

async fn read_until(
    stream: &mut TcpStream,
    marker: &[u8],
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| err.to_string())?;
        buf.push(byte[0]);
        if buf.ends_with(marker) {
            return Ok(buf);
        }
        if buf.len() > limit {
            return Err("ui header too large".to_string());
        }
    }
}
