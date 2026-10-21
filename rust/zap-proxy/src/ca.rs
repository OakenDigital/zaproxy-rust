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
// official OWASP ZAP build. Per-host certificates follow the dynamic CA
// behavior of the ZAP core (Paros `SSLConnector` / dynssl).

//! Certificate authority persisted as `ca.crt` and `ca.key`.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use crate::Error;

const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key";

/// Root CA used to mint per-host certificates for HTTPS interception.
pub struct CertificateAuthority {
    dir: PathBuf,
    cert_pem: String,
    issuer: Mutex<Issuer<'static, KeyPair>>,
    serial: AtomicU64,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// Load `ca.crt` and `ca.key` from `dir`, or create them.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|err| Error::Certificate(err.to_string()))?;
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let (cert_pem, key_pem) = match (cert_path.is_file(), key_path.is_file()) {
            (true, true) => (
                fs::read_to_string(&cert_path)
                    .map_err(|err| Error::Certificate(err.to_string()))?,
                fs::read_to_string(&key_path).map_err(|err| Error::Certificate(err.to_string()))?,
            ),
            (false, false) => generate_ca(&cert_path, &key_path)?,
            _ => {
                return Err(Error::Certificate(format!(
                    "{} is incomplete; expected both {CERT_FILE} and {KEY_FILE}",
                    dir.display()
                )));
            }
        };
        let key = KeyPair::from_pem(&key_pem).map_err(|err| Error::Certificate(err.to_string()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
            .map_err(|err| Error::Certificate(err.to_string()))?;
        Ok(Self {
            dir,
            cert_pem,
            issuer: Mutex::new(issuer),
            serial: AtomicU64::new(1),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// TLS server config whose leaf is signed by this CA and names `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, Error> {
        if let Some(cached) = lock(&self.cache).get(host).cloned() {
            return Ok(cached);
        }
        let config = Arc::new(self.mint(host)?);
        lock(&self.cache).insert(host.to_string(), Arc::clone(&config));
        Ok(config)
    }

    fn mint(&self, host: &str) -> Result<ServerConfig, Error> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san_for_host(host)?];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        name.push(DnType::OrganizationName, "zapd");
        params.distinguished_name = name;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        let mut serial_bytes = [0u8; 16];
        serial_bytes[0] = 0x01;
        serial_bytes[8..].copy_from_slice(&serial.to_be_bytes());
        params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));

        let leaf_key = KeyPair::generate().map_err(|err| Error::Certificate(err.to_string()))?;
        let issuer = lock(&self.issuer);
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|err| Error::Certificate(err.to_string()))?;
        drop(issuer);

        let leaf_der = leaf.der().clone();
        let mut reader = io::Cursor::new(self.cert_pem.as_bytes());
        let ca_der = rustls_pemfile::certs(&mut reader)
            .next()
            .ok_or_else(|| Error::Certificate("CA pem is empty".into()))?
            .map_err(|err| Error::Certificate(err.to_string()))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der, ca_der], key)
            .map_err(|err| Error::Certificate(err.to_string()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn san_for_host(host: &str) -> Result<SanType, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    let dns = rcgen::string::Ia5String::try_from(host)
        .map_err(|err| Error::Certificate(format!("invalid DNS name `{host}`: {err}")))?;
    Ok(SanType::DnsName(dns))
}

fn generate_ca(cert_path: &Path, key_path: &Path) -> Result<(String, String), Error> {
    let key = KeyPair::generate().map_err(|err| Error::Certificate(err.to_string()))?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "zapd Root CA");
    name.push(DnType::OrganizationName, "zapd");
    params.distinguished_name = name;
    let cert = params
        .self_signed(&key)
        .map_err(|err| Error::Certificate(err.to_string()))?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    write_public(cert_path, &cert_pem)?;
    write_secret(key_path, &key_pem)?;
    Ok((cert_pem, key_pem))
}

fn write_public(path: &Path, data: &str) -> Result<(), Error> {
    fs::write(path, data).map_err(|err| Error::Certificate(err.to_string()))
}

fn write_secret(path: &Path, data: &str) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| Error::Certificate(err.to_string()))?;
    file.write_all(data.as_bytes())
        .map_err(|err| Error::Certificate(err.to_string()))?;
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
