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

//! `core/action/shutdown` ends the zapd process.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn temp_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zapd-api-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn shutdown_action_stops_the_process() {
    let dir = temp_dir();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zapd"))
        .arg("--port")
        .arg("0")
        .arg("--session")
        .arg(dir.join("session.sqlite"))
        .arg("--ca-dir")
        .arg(dir.join("ca"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zapd");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut guard = KillOnDrop(Some(child));
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut BufReader::new(stderr), &mut std::io::sink());
    });
    let (addr_tx, addr_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(addr) = line.split("listening on ").nth(1) {
                let _ = addr_tx.send(addr.trim().to_string());
            }
        }
    });
    let addr = addr_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("zapd did not print a listen address");

    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            b"GET http://zap/JSON/core/action/shutdown/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("\"Result\":\"OK\""),
        "shutdown response: {text:?}"
    );

    let child = guard.0.as_mut().unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            panic!("zapd did not exit after core/action/shutdown");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    guard.0.take();
    assert!(status.success(), "zapd exit {status}");
    let _ = std::fs::remove_dir_all(dir);
}
