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

//! `zapd` daemon. Not an official OWASP ZAP build.

#![forbid(unsafe_code)]

mod phase11;
mod phase5;
mod phase6;
mod phase8;
mod phase9;
mod scripts;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::watch;
use zap_api::ApiService;
use zap_core::InMemoryHistory;
use zap_proxy::{LoggingListener, Proxy, ProxyConfig, ProxyListener};
use zap_store::{Session, SessionHistoryListener};

#[derive(Parser, Debug)]
#[command(
    name = "zapd",
    disable_version_flag = true,
    about = "Intercepting HTTP/HTTPS proxy. Not an official OWASP ZAP build."
)]
struct Cli {
    /// Print the version and exit. Also accepted as -version.
    #[arg(long = "version")]
    version: bool,

    /// Listen address. Also accepted as -host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Listen port. Also accepted as -port.
    #[arg(long, short = 'p', default_value_t = 8080)]
    port: u16,

    /// Case-insensitive regex matched against the entire URL. Repeat to add
    /// another pattern. Also accepted as -exclude.
    #[arg(long = "exclude")]
    exclude: Vec<String>,

    /// Directory for ca.crt and ca.key. Also accepted as -ca-dir.
    #[arg(long = "ca-dir", default_value = "zapd-ca")]
    ca_dir: PathBuf,

    /// SQLite session. History and site nodes reload from it on startup.
    /// Also accepted as -session.
    #[arg(long = "session", default_value = "zapd-session.sqlite")]
    session: PathBuf,

    /// Directory of add-on manifests. Also accepted as -addon-dir.
    #[arg(long = "addon-dir", default_value = "zapd-addons")]
    addon_dir: PathBuf,
}

fn normalize_args<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    args.into_iter()
        .map(|arg| match arg.as_str() {
            "-version" => "--version".to_string(),
            "-port" => "--port".to_string(),
            "-host" => "--host".to_string(),
            "-exclude" => "--exclude".to_string(),
            "-ca-dir" => "--ca-dir".to_string(),
            "-session" => "--session".to_string(),
            "-addon-dir" => "--addon-dir".to_string(),
            other => other.to_string(),
        })
        .collect()
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_args(std::env::args()));
    if cli.version {
        println!("zapd {}", env!("CARGO_PKG_VERSION"));
        println!("Not an official OWASP ZAP build.");
        return ExitCode::SUCCESS;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let Ok(ip) = cli.host.parse::<IpAddr>() else {
        eprintln!("zapd: invalid host {}", cli.host);
        return ExitCode::from(2);
    };
    let session = match Session::open(&cli.session) {
        Ok(session) => Arc::new(session),
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let history = Arc::new(InMemoryHistory::new());
    match session.history_rows() {
        Ok(rows) => history.restore(rows),
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    // PHASE-11: one passive listener for the proxy and for packaged-scan
    // fetches. Baseline counts cover plugin 10021 only.
    let (packaged, pscan) = match phase11::start(Arc::clone(&session)) {
        Ok(started) => started,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let listeners: Vec<Arc<dyn ProxyListener>> = vec![
        Arc::new(LoggingListener::new(0)),
        Arc::new(SessionHistoryListener::new(Arc::clone(&session))),
        Arc::clone(&pscan) as Arc<dyn ProxyListener>,
    ];
    // PHASE-7: Boa script host. Types `proxy` and `httpsender`.
    // Hooks: proxyRequest, proxyResponse, sendingRequest, responseReceived.
    // AlertOnHttpResponseCodeErrors.js does not run (`Java.type` needs a JVM).
    let listeners = scripts::register(listeners);
    // PHASE-8: add-ons from the directory. A copied manifest loads on restart.
    // This file does not name add-on rules. Java .zap files are not loaded.
    let addons = match phase8::load(&cli.addon_dir) {
        Ok(addons) => Arc::new(addons),
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let listeners = phase8::register(listeners, Arc::clone(&addons), Arc::clone(&session));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let on_shutdown = {
        let shutdown_tx = shutdown_tx.clone();
        Arc::new(move || {
            let shutdown_tx = shutdown_tx.clone();
            std::thread::spawn(move || {
                // Let the JSON response leave before the process ends.
                std::thread::sleep(Duration::from_millis(250));
                let _ = shutdown_tx.send(true);
            });
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let api = Arc::new(ApiService::new(
        Arc::clone(&session),
        env!("CARGO_PKG_VERSION"),
        on_shutdown,
    ));
    // PHASE-6: active scan on the default sender. Routes live in phase6.rs.
    // No forced user and no login. Do not fold this into the core API crate.
    let ascan = match phase6::start(Arc::clone(&session)) {
        Ok(ascan) => ascan,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    // PHASE-9: traditional spider on the default sender. No seed is crawled
    // at startup. The AJAX spider is not included.
    let spider = match phase9::start() {
        Ok(spider) => spider,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let config = ProxyConfig {
        listen: SocketAddr::new(ip, cli.port),
        ca_dir: cli.ca_dir.clone(),
        exclude: cli.exclude,
        listeners,
        extra_root_pems: Vec::new(),
        history: Some(history),
        early_override: Some(phase8::chain(
            phase11::chain(phase6::early_override(api, ascan), packaged),
            Arc::clone(&addons),
        )),
    };

    let proxy = match Proxy::start(config).await {
        Ok(proxy) => proxy,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };

    println!(
        "zapd {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        proxy.local_addr()
    );
    println!("CA certificate: {}", cli.ca_dir.join("ca.crt").display());
    println!(
        "Session: {} ({} history rows)",
        cli.session.display(),
        proxy.history().len()
    );
    println!("API: http://zap/JSON/ via this proxy");
    println!("Passive scan: X-Content-Type-Options (plugin 10021)");
    scripts::log_startup();
    // PHASE-5: context include/exclude regexes, form and JSON authentication,
    // cookie session management, and send-as-user. The line is printed from
    // `phase5` so this function stays the proxy startup path.
    println!("{}", phase5::startup_line());
    // PHASE-6
    println!("Active scan: CRLF Injection (40003), XPath Injection (90021)");
    // PHASE-8
    println!("{}", phase8::startup_line(&addons));
    // PHASE-9
    println!("{}", phase9::startup_line(&spider));
    // PHASE-11
    println!("{}", phase11::startup_line());
    println!("Not an official OWASP ZAP build.");

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if result.is_err() {
                eprintln!("zapd: failed to wait for interrupt");
            }
        }
        changed = shutdown_rx.changed() => {
            if changed.is_err() || !*shutdown_rx.borrow() {
                eprintln!("zapd: shutdown watch closed");
            }
        }
    }
    proxy.shutdown().await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{normalize_args, Cli};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn single_dash_flags_become_long_flags() {
        let args = normalize_args([
            "zapd".to_string(),
            "-version".to_string(),
            "-port".to_string(),
            "8081".to_string(),
            "-host".to_string(),
            "127.0.0.1".to_string(),
            "-exclude".to_string(),
            ".*".to_string(),
            "-ca-dir".to_string(),
            "certs".to_string(),
            "-session".to_string(),
            "mine.sqlite".to_string(),
            "-addon-dir".to_string(),
            "addons".to_string(),
        ]);
        assert_eq!(
            args,
            vec![
                "zapd",
                "--version",
                "--port",
                "8081",
                "--host",
                "127.0.0.1",
                "--exclude",
                ".*",
                "--ca-dir",
                "certs",
                "--session",
                "mine.sqlite",
                "--addon-dir",
                "addons",
            ]
        );
    }

    #[test]
    fn session_flag_sets_the_sqlite_path() {
        let cli = Cli::parse_from(normalize_args([
            "zapd".to_string(),
            "-session".to_string(),
            "mine.sqlite".to_string(),
        ]));
        assert_eq!(cli.session, PathBuf::from("mine.sqlite"));
        assert!(!cli.version);
    }

    #[test]
    fn default_session_path_is_in_the_working_directory() {
        let cli = Cli::parse_from(["zapd"]);
        assert_eq!(cli.session, PathBuf::from("zapd-session.sqlite"));
        assert_eq!(cli.addon_dir, PathBuf::from("zapd-addons"));
    }
}
