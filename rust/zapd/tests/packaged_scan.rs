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

//! Phase 11 image contents and baseline counts.
//!
//! The image file is checked for a JDK. `zap-baseline.py --autooff` counts
//! plugin 10021 and the bundled add-on passive rules. Rules that were not
//! ported are not listed, so they are not passes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "zapd-phase11-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn final_stage(dockerfile: &str) -> &str {
    dockerfile
        .rsplit_once("\nFROM ")
        .map(|(_, stage)| stage)
        .unwrap_or(dockerfile)
}

#[test]
fn dockerfile_has_no_jdk_and_starts_zapd() {
    let path = repo_root().join("docker/Dockerfile-zapd");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {path:?}: {err}"));
    let stage = final_stage(&text).to_ascii_lowercase();
    for banned in ["openjdk", "default-jre", "jdk", "xvfb", "webswing"] {
        assert!(
            !stage.contains(banned),
            "final stage contains {banned}:\n{stage}"
        );
    }
    assert!(
        stage.contains("zapd"),
        "final stage does not copy zapd:\n{stage}"
    );
    assert!(
        stage.contains("zap-x.sh"),
        "final stage does not install the zapd entrypoint:\n{stage}"
    );
    assert!(
        stage.contains("entrypoint") && stage.contains("zap-x.sh"),
        "entrypoint is not the shim:\n{stage}"
    );
    let shim = std::fs::read_to_string(repo_root().join("docker/zapd-entry.sh")).unwrap();
    assert!(shim.contains("automation framework"));
    assert!(shim.contains("ZAPD_BIN"));
}

struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn shim_starts_zapd_and_rejects_autorun() {
    let shim = repo_root().join("docker/zapd-entry.sh");
    let rejected = Command::new(&shim)
        .arg("-autorun")
        .arg("plan.yaml")
        .output()
        .expect("run shim");
    assert_eq!(rejected.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("automation framework"),
        "stderr was {stderr:?}"
    );

    let dir = temp_dir("shim");
    let mut child = Command::new(&shim)
        .args([
            "-daemon",
            "-host",
            "127.0.0.1",
            "-port",
            "0",
            "-config",
            "api.disablekey=true",
            "-addonupdate",
            "-addoninstall",
            "pscanrulesBeta",
        ])
        .env("ZAPD_BIN", env!("CARGO_BIN_EXE_zapd"))
        .env("ZAP_SESSION", dir.join("session.sqlite"))
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shim");
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
        .recv_timeout(Duration::from_secs(15))
        .expect("zapd did not print a listen address");

    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            b"GET http://zap/JSON/core/view/version/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("\"version\""), "version response: {text:?}");

    let mut shutdown = TcpStream::connect(&addr).expect("connect shutdown");
    shutdown
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    shutdown
        .write_all(
            b"GET http://zap/JSON/core/action/shutdown/ HTTP/1.1\r\nHost: zap\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut buf = Vec::new();
    let _ = shutdown.read_to_end(&mut buf);

    let child = guard.0.as_mut().unwrap();
    let started = std::time::Instant::now();
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

#[test]
fn baseline_counts_match_for_plugin_10021() {
    ensure_python_client();
    let missing = run_baseline(false, None);
    assert_eq!(missing.code, Some(2), "{}", missing.detail());
    missing.assert_counts(0, 1, 8);

    let passed = run_baseline(true, None);
    assert_eq!(passed.code, Some(0), "{}", passed.detail());
    passed.assert_counts(0, 0, 9);

    let failed = run_baseline(
        false,
        Some("10021\tFAIL\t(X-Content-Type-Options Header Missing)\n"),
    );
    assert_eq!(failed.code, Some(1), "{}", failed.detail());
    failed.assert_counts(1, 0, 8);
}

struct Baseline {
    code: Option<i32>,
    output: Output,
    work: PathBuf,
}

impl Baseline {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn detail(&self) -> String {
        let zap_out = std::fs::read_to_string(self.work.join("zap.out")).unwrap_or_default();
        format!(
            "exit {:?}\nstdout:\n{}\nstderr:\n{}\nzap.out:\n{zap_out}",
            self.code,
            self.stdout(),
            String::from_utf8_lossy(&self.output.stderr),
        )
    }

    fn assert_counts(&self, fail: i32, warn: i32, pass: i32) {
        let stdout = self.stdout();
        let line = stdout
            .lines()
            .find(|line| line.contains("\tPASS:"))
            .unwrap_or_else(|| panic!("no summary line\n{}", self.detail()));
        let expected = format!(
            "FAIL-NEW: {fail}\tFAIL-INPROG: 0\tWARN-NEW: {warn}\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: {pass}"
        );
        assert_eq!(line, expected, "{}", self.detail());
    }
}

fn ensure_python_client() {
    let check = Command::new("python3")
        .args(["-c", "import yaml, zapv2"])
        .status();
    if check.map(|status| status.success()).unwrap_or(false) {
        return;
    }
    let status = Command::new("python3")
        .args(["-m", "pip", "install", "--user", "zaproxy", "pyyaml"])
        .status()
        .expect("pip");
    assert!(status.success(), "pip install zaproxy pyyaml");
}

fn run_baseline(nosniff: bool, config: Option<&str>) -> Baseline {
    let work = temp_dir(if nosniff { "pass" } else { "warn" });
    if let Some(config) = config {
        std::fs::write(work.join("rules.conf"), config).unwrap();
    }
    let origin = serve(nosniff);
    let port = free_port();
    let target = format!("http://127.0.0.1:{origin}/");
    let mut command = Command::new("python3");
    command
        .arg(repo_root().join("docker/zap-baseline.py"))
        .arg("--autooff")
        .arg("-s")
        .arg("-T")
        .arg("1")
        .arg("-t")
        .arg(&target)
        .arg("-P")
        .arg(port.to_string());
    if config.is_some() {
        command.arg("-c").arg("rules.conf");
    }
    let wrk = format!("{}/", work.display());
    let output = command
        .current_dir(&work)
        .env("IS_CONTAINERIZED", "true")
        .env("ZAP_DAEMON", repo_root().join("docker/zapd-entry.sh"))
        .env("ZAPD_BIN", env!("CARGO_BIN_EXE_zapd"))
        .env("ZAP_WRK", &wrk)
        .output()
        .expect("run zap-baseline.py");
    Baseline {
        code: output.status.code(),
        output,
        work,
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn serve(nosniff: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = answer(stream, nosniff);
        }
    });
    port
}

fn answer(mut stream: TcpStream, nosniff: bool) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let path = request_path(&req);
    let (status, reason, body) = match path {
        "/robots.txt" => (200, "OK", "User-agent: *\n"),
        "/sitemap.xml" => (404, "Not Found", ""),
        _ => (
            200,
            "OK",
            "<html><body><a href=\"/page\">page</a></body></html>",
        ),
    };
    let header = if nosniff && status == 200 {
        "X-Content-Type-Options: nosniff\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n{header}\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn request_path(req: &str) -> &str {
    let target = req.split_whitespace().nth(1).unwrap_or("/");
    let path = if let Some(index) = target.find("://") {
        let after = &target[index + 3..];
        after.find('/').map(|index| &after[index..]).unwrap_or("/")
    } else {
        target
    };
    path.split('?').next().unwrap_or("/")
}
