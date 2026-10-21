# zapd

Rust intercepting proxy. **Not an official OWASP ZAP build.**

`zapd` forwards HTTP/1.1, tunnels `CONNECT`, and terminates HTTPS with a
certificate authority it writes to disk. Each completed exchange is one row in
memory and in a SQLite session. An exclude regex skips that row. Listeners run
in order and may mutate a message, supply a response (the origin is not
contacted), or stop later listeners. After history is recorded, a passive-scan
queue runs one header rule: X-Content-Type-Options (plugin id 10021). A
JavaScript host runs `proxy` and `httpsender` scripts. Form and JSON logins
send a follow-up request as a user. There is no active scan.

The Java tree in the repository root is unchanged and remains the behavioral
spec.

## Run

```text
cargo run -p zapd -- --port 8080
cargo run -p zapd -- --version
```

Single-dash forms `-port`, `-host`, `-exclude`, `-ca-dir`, `-session`, and
`-version` are accepted. The CA is written to `zapd-ca/ca.crt` and
`zapd-ca/ca.key` (override with `--ca-dir`). Point a client at the printed
address and trust `ca.crt` for HTTPS.

## Session

`--session` selects the SQLite file. The default is `zapd-session.sqlite` in
the working directory. Startup reloads history rows from that file into the
proxy. Each stored exchange also upserts site nodes (host, then path
segments). Alert rows are in the same file — plugin id, risk, confidence,
CWE, WASC, param, and URL. The passive-scan queue inserts a row when the
X-Content-Type-Options rule matches.

`--version` prints the version and does not open the session file.

## API

Requests whose host is `zap` are answered by the proxy and are not forwarded
or stored. JSON only. These routes use the same keys as the ZAP daemon for
this subset:

| Route | Body |
| --- | --- |
| `GET http://zap/JSON/core/view/version/` | `{"version":"<zapd version>"}` |
| `GET http://zap/JSON/core/view/hosts/` | `{"hosts":["example.com", ...]}` |
| `GET http://zap/JSON/core/view/messages/` | `{"messages":["<message json>", ...]}` |
| `GET http://zap/JSON/core/action/shutdown/` | `{"Result":"OK"}`, then the process exits |
| `GET http://zap/JSON/alert/view/alerts/` | `{"alerts":["<alert json>", ...]}` |
| `GET http://zap/JSON/alert/view/alert/?id=1` | `{"alert":"<alert json>"}` |

`messages` accepts `baseurl`, `start`, and `count`. `alerts` also accepts
`riskId` and `falsePositive`. `alert` requires `id`. Message and alert
objects are JSON strings inside the array, matching the ZAP API. No API key
is required. `core/action/shutdown` returns, then ends the process.
`http://zap/` is answered before listeners run, so those calls are not scanned.

## Passive scan

The queue is a proxy listener at order 5001, one after history. It runs on the
response the client is about to receive. The rule is X-Content-Type-Options
from pscanrules v70 (plugin id 10021). The Java add-on is not vendored. A
response with a non-empty body and no header value containing `nosniff` raises
one alert: risk low (1), confidence medium (2), CWE 693, WASC 15, param
`x-content-type-options`, and the request URL. At the default threshold
(medium), client errors, server errors, and redirects are skipped. Threshold
OFF disables the rule and raises nothing.

## Scripts

The engine is Boa. Script types are `proxy` and `httpsender`, with the ZAP
hook names `proxyRequest`, `proxyResponse`, `sendingRequest`, and
`responseReceived`. A sample in `zap-script/scripts/rewrite-headers.js` sets
`X-Script-Request` on the way out and `X-Script-Response` on the way back
(`httpsender` uses `X-Sender-Request` and `X-Sender-Response`). The message
object is `url`, `method`, `requestHeader`, `setRequestHeader`,
`responseHeader`, `setResponseHeader`, `responseStatus`, `requestBody`,
`responseBody`, and `setResponse`.

`AlertOnHttpResponseCodeErrors.js` (the Docker packaged-scan httpsender
script) does not run. Boa has no Nashorn/Graal `Java.type`, so the script
fails while evaluating `Java.type("java.lang.Integer")`,
`Java.type("java.util.regex.Pattern")`,
`Java.type("org.parosproxy.paros.core.scanner.Alert")`,
`Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert")`, and
`Java.type("org.parosproxy.paros.model.HistoryReference")`. It also reads
`control` and `model`. The hooks exist; that script never reaches them.

## Authentication

Context include and exclude regexes use the same full-string, ASCII
case-insensitive match as ZAP, after the query string is removed. A ZAP
context file (`<incregexes>` and `<excregexes>`) loads that config. Form login
posts `application/x-www-form-urlencoded` and JSON login posts
`application/json`, replacing `{%username%}` and `{%password%}`. Cookie session
management keeps `Set-Cookie` from the login response. `send-as-user` on the
HTTP client logs in once, then sends the follow-up request with those cookies.

## Listeners

Lower `order` runs first. Equal orders keep registration order. The history
listener uses order `5000` and records the message it sees. Listeners ordered
after that still run, and their later edits are what the client receives.

Returning `false` from a request listener stops later request listeners and
does not contact the origin. Returning `false` from a response listener stops
later response listeners. Setting `HttpMessage::response` during the request
phase, then returning `true`, skips the origin and still notifies response
listeners.

Excluded URLs (case-insensitive, entire URL, same rule as Java
`Matcher.matches`) are forwarded and are not stored. Listeners are not called
for them.

## Headers to ignore in a diff

Upstream requests carry one injected header:

| Name | Value |
| --- | --- |
| `via` | `1.1 zapd` (appended if `Via` was already present) |

Compare origin **status** and **body** directly. Hop-by-hop and framing
headers (`connection`, `proxy-connection`, `keep-alive`, `transfer-encoding`,
`te`, `trailer`, `upgrade`, `proxy-authorization`, `proxy-authenticate`, and
names listed in `Connection`) are removed when a buffered message is
forwarded. `content-length` is set from the buffered body.

The same names are `zap_http::INJECTED_HEADER_NAMES` and
`zap_core::HOP_BY_HOP_HEADERS`.

## Tests

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
