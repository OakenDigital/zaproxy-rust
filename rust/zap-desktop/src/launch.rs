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

//! Start the proxy and the desktop page together.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;
use zap_proxy::{Proxy, ProxyConfig, ProxyListener, RunningProxy};
use zap_pscan::PassiveScanListener;
use zap_store::{Session, SessionHistoryListener};

use crate::breakpoint::{BreakListener, Breakpoint};
use crate::scans::ScanControls;
use crate::ui::{serve, UiState};

/// Addresses and files for one desktop process.
pub struct DesktopConfig {
    pub ui: SocketAddr,
    pub proxy: SocketAddr,
    pub session_path: PathBuf,
    pub ca_dir: PathBuf,
}

/// A running proxy plus the local UI. `zapd` is not part of this process.
pub struct RunningDesktop {
    proxy: RunningProxy,
    ui_shutdown: watch::Sender<bool>,
    ui_task: tokio::task::JoinHandle<()>,
    ui_addr: SocketAddr,
    session: Arc<Session>,
    breakpoint: Arc<Breakpoint>,
}

impl RunningDesktop {
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    pub fn ui_addr(&self) -> SocketAddr {
        self.ui_addr
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn breakpoint(&self) -> &Breakpoint {
        &self.breakpoint
    }

    pub async fn shutdown(mut self) {
        let _ = self.ui_shutdown.send(true);
        let _ = (&mut self.ui_task).await;
        self.proxy.shutdown().await;
    }
}

/// Open the session, bind the UI, and start the proxy with break enabled in code
/// but off until the page turns it on.
pub async fn launch(config: DesktopConfig) -> Result<RunningDesktop, String> {
    let session = Arc::new(Session::open(&config.session_path).map_err(|err| err.to_string())?);
    let breakpoint = Arc::new(Breakpoint::new());
    let pscan = Arc::new(PassiveScanListener::new(Arc::clone(&session)));
    let scans = Arc::new(ScanControls::start(
        Arc::clone(&session),
        Arc::clone(&pscan),
    )?);
    let listeners: Vec<Arc<dyn ProxyListener>> = vec![
        Arc::new(BreakListener::new(Arc::clone(&breakpoint))),
        Arc::new(SessionHistoryListener::new(Arc::clone(&session))),
        pscan,
    ];
    let proxy = Proxy::start(ProxyConfig {
        listen: config.proxy,
        ca_dir: config.ca_dir,
        exclude: Vec::new(),
        listeners,
        extra_root_pems: Vec::new(),
        history: None,
        early_override: None,
    })
    .await
    .map_err(|err| err.to_string())?;
    let listener = TcpListener::bind(config.ui)
        .await
        .map_err(|err| err.to_string())?;
    let ui_addr = listener.local_addr().map_err(|err| err.to_string())?;
    let state = Arc::new(UiState {
        session: Arc::clone(&session),
        breakpoint: Arc::clone(&breakpoint),
        proxy_addr: proxy.local_addr(),
        scans,
    });
    let (ui_shutdown, shutdown_rx) = watch::channel(false);
    let ui_task = tokio::spawn(async move {
        serve(listener, state, shutdown_rx).await;
    });
    Ok(RunningDesktop {
        proxy,
        ui_shutdown,
        ui_task,
        ui_addr,
        session,
        breakpoint,
    })
}
