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

mod controls;
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
use zap_ajax::AjaxSpider;
use zap_api::ApiService;
use zap_core::InMemoryHistory;
use zap_openapi::spider_seeds;
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

    /// Traditional spider seed URL. Repeat to crawl another seed.
    /// Also accepted as -spider. Out-of-context URLs are not fetched.
    /// The AJAX spider is not included.
    #[arg(long = "spider")]
    spider_seed: Vec<String>,

    /// AJAX spider seed URL. Repeat to crawl another seed.
    /// Also accepted as -ajaxspider. HTML links and inline script string
    /// literals are followed. A browser runtime is not included.
    #[arg(long = "ajaxspider")]
    ajax_spider_seed: Vec<String>,

    /// JavaScript file for the Boa proxy and httpsender host.
    /// Repeat to load another file. Also accepted as -script.
    #[arg(long = "script")]
    script: Vec<PathBuf>,

    /// ZAP context file. Also accepted as -context.
    #[arg(long = "context")]
    context: Option<PathBuf>,

    /// Display name for send-as-user. Also accepted as -auth-user.
    #[arg(long = "auth-user", default_value = "user")]
    auth_user: String,

    /// Login username from the context file. Also accepted as -auth-username.
    #[arg(long = "auth-username")]
    auth_username: Option<String>,

    /// Login password from the context file. Also accepted as -auth-password.
    #[arg(long = "auth-password")]
    auth_password: Option<String>,

    /// URL to fetch with form or JSON login plus send-as-user.
    /// Repeat to send another follow-up. Also accepted as -send-as-user.
    #[arg(long = "send-as-user")]
    send_as_user: Vec<String>,

    /// OpenAPI 2 or 3 JSON or YAML file. Each operation URL is added to the
    /// traditional spider seed list. The method, URL, and body are the
    /// active-scan seed (`method`, `url`, `postData`). Repeat to import
    /// another file. Also accepted as -openapi. The file is read locally
    /// and is not downloaded.
    #[arg(long = "openapi")]
    openapi: Vec<PathBuf>,

    /// Base URL for -openapi. When set, it replaces servers in the file.
    /// Also accepted as -openapi-target. This URL is not fetched.
    #[arg(long = "openapi-target")]
    openapi_target: Option<String>,

    /// YAML automation plan to run, then exit. Also accepted as -autorun.
    /// Jobs include requestor, spider, passiveScan-wait, activeScan, and
    /// report. No JDK and no browser.
    #[arg(long = "autorun")]
    autorun: Option<PathBuf>,
}

fn openapi_spider_seeds(paths: &[PathBuf], target: Option<&str>) -> Result<Vec<String>, String> {
    let mut seeds = Vec::new();
    for path in paths {
        let requests = zap_openapi::import_path(path, target).map_err(|err| err.to_string())?;
        for request in &requests {
            println!("openapi {} {}", request.method, request.url);
        }
        for seed in spider_seeds(&requests) {
            if !seeds.contains(&seed) {
                seeds.push(seed);
            }
        }
    }
    Ok(seeds)
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
            "-spider" => "--spider".to_string(),
            "-ajaxspider" => "--ajaxspider".to_string(),
            "-script" => "--script".to_string(),
            "-context" => "--context".to_string(),
            "-auth-user" => "--auth-user".to_string(),
            "-auth-username" => "--auth-username".to_string(),
            "-auth-password" => "--auth-password".to_string(),
            "-send-as-user" => "--send-as-user".to_string(),
            "-openapi" => "--openapi".to_string(),
            "-openapi-target" => "--openapi-target".to_string(),
            "-autorun" => "--autorun".to_string(),
            other => other.to_string(),
        })
        .collect()
}

fn start_ajax_spiders(seeds: &[String], context: Option<zap_auth::Context>) -> Result<(), String> {
    if seeds.is_empty() {
        return Ok(());
    }
    let mut normalized = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let seed = seed.trim();
        if seed.is_empty() {
            return Err("ajax spider seed is empty".to_string());
        }
        normalized.push(AjaxSpider::normalize_seed(seed)?);
    }
    let sender = Arc::new(zap_ajax::DefaultSender::from_current()?);
    for seed in normalized {
        let sender = Arc::clone(&sender);
        let context = context.clone();
        std::thread::spawn(move || {
            let spider = AjaxSpider::new(sender);
            match spider.crawl(&seed, context.as_ref()) {
                Ok(urls) => {
                    let count = urls.len();
                    println!("ajax spider {seed} recorded {count} url(s)");
                    for url in &urls {
                        println!("ajax spider url {url}");
                    }
                }
                Err(err) => eprintln!("zapd: ajax spider {seed}: {err}"),
            }
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_args(std::env::args()));
    if cli.version {
        println!("zapd {}", env!("CARGO_PKG_VERSION"));
        println!("Not an official OWASP ZAP build.");
        return ExitCode::SUCCESS;
    }

    let openapi_seeds = match openapi_spider_seeds(&cli.openapi, cli.openapi_target.as_deref()) {
        Ok(seeds) => seeds,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if let Some(path) = &cli.autorun {
        // The default senders block on the runtime handle, so the plan runs
        // off this thread. The runtime stays alive until the worker joins.
        return run_autorun(path, &cli.session);
    }

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
    // PHASE-8 first so packaged scan and active scan can use add-on rules
    // without this file naming them.
    let addons = match phase8::load(&cli.addon_dir) {
        Ok(addons) => Arc::new(addons),
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    // PHASE-11: one passive listener for the proxy and for packaged-scan
    // fetches. Baseline counts cover plugin 10021 and installed add-on rules.
    let (packaged, pscan) = match phase11::start(Arc::clone(&session), addons.passive_rules()) {
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
    let (listeners, script_host) = scripts::register(listeners);
    // PHASE-8: add-ons from the directory. A copied manifest loads on restart.
    // This file does not name add-on rules. Java .zap files are not loaded.
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
    let ascan = match phase6::start(Arc::clone(&session), addons.active_plugins()) {
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
    let controls = controls::EngineControls::new(script_host, Arc::clone(&packaged));
    if let Some(path) = &cli.context {
        if let Err(err) = controls.import_context_file(path) {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    }
    if cli.auth_username.is_some() || cli.auth_password.is_some() {
        controls.set_user(
            &cli.auth_user,
            cli.auth_username.as_deref().unwrap_or(""),
            cli.auth_password.as_deref().unwrap_or(""),
        );
    }
    for path in &cli.script {
        if let Err(err) = controls.load_script_file(path, None) {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    }
    let config = ProxyConfig {
        listen: SocketAddr::new(ip, cli.port),
        ca_dir: cli.ca_dir.clone(),
        exclude: cli.exclude,
        listeners,
        extra_root_pems: Vec::new(),
        history: Some(history),
        // META-API: pscan, ascan scanners, context, users, and script JSON
        // that phase 6 and phase 11 do not answer is served by `api`.
        // ascan scan/status/stop and spider scan/status stay in front of it.
        early_override: Some(phase8::chain(
            controls::chain(
                phase11::chain(phase6::early_override(api, ascan), packaged),
                Arc::clone(&controls),
            ),
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
    // AJAX spider. A browser runtime is not included.
    println!("AJAX spider: {}", zap_ajax::SUMMARY);
    // PHASE-11
    println!("{}", phase11::startup_line());
    // META-ENGINE
    println!("{}", controls::startup_line());
    println!("Not an official OWASP ZAP build.");

    let mut seeds = cli.spider_seed.clone();
    for seed in openapi_seeds {
        if !seeds.contains(&seed) {
            seeds.push(seed);
        }
    }
    for seed in &seeds {
        if let Err(err) = controls.start_spider(seed) {
            eprintln!("zapd: {err}");
            proxy.shutdown().await;
            return ExitCode::from(1);
        }
    }
    if let Err(err) = start_ajax_spiders(&cli.ajax_spider_seed, controls.context()) {
        eprintln!("zapd: {err}");
        proxy.shutdown().await;
        return ExitCode::from(1);
    }
    for url in &cli.send_as_user {
        match controls.send_follow_up(url).await {
            Ok(response) => {
                println!("send-as-user {} {}", response.status.as_u16(), url);
            }
            Err(err) => {
                eprintln!("zapd: {err}");
                proxy.shutdown().await;
                return ExitCode::from(1);
            }
        }
    }

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

fn run_autorun(path: &std::path::Path, session_path: &std::path::Path) -> ExitCode {
    let session = match Session::open(session_path) {
        Ok(session) => Arc::new(session),
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let hosts = match zap_automation::Hosts::with_defaults(session) {
        Ok(hosts) => hosts,
        Err(err) => {
            eprintln!("zapd: {err}");
            return ExitCode::from(1);
        }
    };
    let path = path.to_path_buf();
    let joined = std::thread::spawn(move || zap_automation::run_file(&path, &hosts)).join();
    match joined {
        Ok(Ok(result)) => {
            println!("automation plan finished ({} jobs)", result.jobs.len());
            println!("Not an official OWASP ZAP build.");
            ExitCode::SUCCESS
        }
        Ok(Err(err)) => {
            eprintln!("zapd: {err}");
            ExitCode::from(1)
        }
        Err(_) => {
            eprintln!("zapd: automation plan panicked");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_args, start_ajax_spiders, Cli};
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
    fn engine_control_flags_set_spider_script_and_context() {
        let cli = Cli::parse_from(normalize_args([
            "zapd".to_string(),
            "-spider".to_string(),
            "http://127.0.0.1/app/".to_string(),
            "-script".to_string(),
            "rewrite-headers.js".to_string(),
            "-context".to_string(),
            "app.context".to_string(),
            "-auth-username".to_string(),
            "alice".to_string(),
            "-auth-password".to_string(),
            "secret".to_string(),
            "-send-as-user".to_string(),
            "http://127.0.0.1/private".to_string(),
        ]));
        assert_eq!(cli.spider_seed, ["http://127.0.0.1/app/"]);
        assert_eq!(cli.script, [PathBuf::from("rewrite-headers.js")]);
        assert_eq!(cli.context, Some(PathBuf::from("app.context")));
        assert_eq!(cli.auth_username.as_deref(), Some("alice"));
        assert_eq!(cli.auth_password.as_deref(), Some("secret"));
        assert_eq!(cli.send_as_user, ["http://127.0.0.1/private"]);
    }

    #[test]
    fn openapi_flag_points_at_a_local_file() {
        let cli = Cli::parse_from(normalize_args([
            "zapd".to_string(),
            "-openapi".to_string(),
            "petstore.yaml".to_string(),
            "-openapi-target".to_string(),
            "http://127.0.0.1:8080/api".to_string(),
        ]));
        assert_eq!(cli.openapi, [PathBuf::from("petstore.yaml")]);
        assert_eq!(
            cli.openapi_target.as_deref(),
            Some("http://127.0.0.1:8080/api")
        );
        assert!(cli.spider_seed.is_empty());
    }

    #[test]
    fn autorun_flag_sets_the_plan_path() {
        let cli = Cli::parse_from(normalize_args([
            "zapd".to_string(),
            "-autorun".to_string(),
            "plan.yaml".to_string(),
        ]));
        assert_eq!(cli.autorun, Some(PathBuf::from("plan.yaml")));
    }

    #[test]
    fn ajaxspider_flag_sets_the_seed() {
        let cli = Cli::parse_from(normalize_args([
            "zapd".to_string(),
            "-ajaxspider".to_string(),
            "http://127.0.0.1/app/".to_string(),
        ]));
        assert_eq!(cli.ajax_spider_seed, ["http://127.0.0.1/app/"]);
    }

    #[test]
    fn empty_ajaxspider_seed_is_rejected() {
        let err = start_ajax_spiders(&[String::new()], None).unwrap_err();
        assert_eq!(err, "ajax spider seed is empty");
    }

    #[test]
    fn default_session_path_is_in_the_working_directory() {
        let cli = Cli::parse_from(["zapd"]);
        assert_eq!(cli.session, PathBuf::from("zapd-session.sqlite"));
        assert_eq!(cli.addon_dir, PathBuf::from("zapd-addons"));
    }
}
