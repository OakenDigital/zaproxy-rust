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

//! `zap-desktop` binary. Not an official OWASP ZAP build.
//!
//! This process is separate from `zapd`. The daemon does not link this crate.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use zap_desktop::{launch, DesktopConfig};

#[derive(Parser, Debug)]
#[command(
    name = "zap-desktop",
    about = "Sites, history, messages, alerts, break, spider, and active scan. Not an official OWASP ZAP build."
)]
struct Cli {
    /// Print the version and exit.
    #[arg(long)]
    version: bool,

    /// Address for the proxy and the UI.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Proxy listen port.
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// UI listen port.
    #[arg(long, default_value_t = 8090)]
    ui_port: u16,

    /// SQLite session shared by history, sites, and alerts.
    #[arg(long, default_value = "zapd-session.sqlite")]
    session: PathBuf,

    /// Directory for ca.crt and ca.key.
    #[arg(long, default_value = "zapd-ca")]
    ca_dir: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.version {
        println!("zap-desktop {}", env!("CARGO_PKG_VERSION"));
        println!("Not an official OWASP ZAP build.");
        return ExitCode::SUCCESS;
    }
    let Ok(ip) = cli.host.parse::<IpAddr>() else {
        eprintln!("zap-desktop: invalid host {}", cli.host);
        return ExitCode::from(2);
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let desktop = match launch(DesktopConfig {
        ui: SocketAddr::new(ip, cli.ui_port),
        proxy: SocketAddr::new(ip, cli.port),
        session_path: cli.session,
        ca_dir: cli.ca_dir,
    })
    .await
    {
        Ok(desktop) => desktop,
        Err(err) => {
            eprintln!("zap-desktop: {err}");
            return ExitCode::from(1);
        }
    };
    println!(
        "zap-desktop {} proxy {} ui http://{}",
        env!("CARGO_PKG_VERSION"),
        desktop.proxy_addr(),
        desktop.ui_addr()
    );
    println!("Break is off until you turn it on in the UI.");
    println!("Start a traditional spider or an active scan from the page. The AJAX spider is not included.");
    println!("Not an official OWASP ZAP build. zapd does not include this UI.");
    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("zap-desktop: failed to wait for interrupt");
    }
    desktop.shutdown().await;
    ExitCode::SUCCESS
}
