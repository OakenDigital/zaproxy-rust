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

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use zap_proxy::{LoggingListener, Proxy, ProxyConfig};

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
    let config = ProxyConfig {
        listen: SocketAddr::new(ip, cli.port),
        ca_dir: cli.ca_dir.clone(),
        exclude: cli.exclude,
        listeners: vec![Arc::new(LoggingListener::new(0))],
        extra_root_pems: Vec::new(),
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
    println!("Not an official OWASP ZAP build.");

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("zapd: failed to wait for interrupt");
    }
    proxy.shutdown().await;
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::normalize_args;

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
            ]
        );
    }
}
