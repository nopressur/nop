// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{TlsMode, ValidatedConfig};
use crate::runtime_paths::RuntimePaths;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::fs;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration as StdDuration;
use std::time::SystemTime;
use time::OffsetDateTime;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

const RELOAD_DEBOUNCE: StdDuration = StdDuration::from_secs(1);
pub fn load_rustls_config(
    runtime_paths: &RuntimePaths,
    config: &ValidatedConfig,
) -> io::Result<rustls::ServerConfig> {
    let tls_config = config
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config missing"))?;
    let tls_dir = runtime_paths.state_sys_dir.join("tls");
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    match tls_config.mode {
        TlsMode::SelfSigned => ensure_self_signed(&tls_dir, &cert_path, &key_path, tls_config)?,
        TlsMode::UserProvided => ensure_manual(&cert_path, &key_path)?,
        TlsMode::Acme => ensure_manual(&cert_path, &key_path)?,
    }

    let resolver = FileReloadingResolver::new(cert_path, key_path)?;

    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver)))
}

fn load_cert_chain(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = CertificateDer::pem_reader_iter(reader).collect();
    let certs =
        certs.map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("No certificates found in {}", path.display()),
        ));
    }

    Ok(certs)
}

fn load_private_key(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let keys: Result<Vec<_>, _> = PrivateKeyDer::pem_reader_iter(reader).collect();
    let keys = keys.map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

    keys.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("No private keys found in {}", path.display()),
        )
    })
}

fn ensure_self_signed(
    tls_dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    tls_config: &crate::config::TlsConfig,
) -> io::Result<()> {
    let needs_generation = if !cert_path.exists() || !key_path.exists() {
        true
    } else {
        cert_is_expired(cert_path).unwrap_or(true)
    };

    if !needs_generation {
        return Ok(());
    }

    if tls_config.domains.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Self-signed TLS requires at least one domain",
        ));
    }

    let mut params = CertificateParams::new(tls_config.domains.clone())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let mut dn = DistinguishedName::new();
    if let Some(primary) = tls_config.domains.first() {
        dn.push(DnType::CommonName, primary.as_str());
    }
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(60);
    params.not_after = now + time::Duration::days(90);
    let key_pair =
        KeyPair::generate().map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::create_dir_all(tls_dir)?;
    fs::write(cert_path, cert_pem)?;
    fs::write(key_path, key_pem)?;

    Ok(())
}

fn ensure_manual(cert_path: &Path, key_path: &Path) -> io::Result<()> {
    if !cert_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("TLS certificate not found: {}", cert_path.display()),
        ));
    }
    if !key_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("TLS private key not found: {}", key_path.display()),
        ));
    }

    if cert_is_expired(cert_path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TLS certificate expired: {}", cert_path.display()),
        ));
    }

    // Validate key readability by parsing it once.
    let _ = load_private_key(key_path)?;
    Ok(())
}

pub(crate) fn cert_not_after(path: &Path) -> io::Result<OffsetDateTime> {
    let bytes = fs::read(path)?;
    let (_, pem) = parse_x509_pem(&bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let (_, cert) = X509Certificate::from_der(pem.contents.as_slice())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(cert.validity().not_after.to_datetime())
}

fn cert_is_expired(path: &Path) -> io::Result<bool> {
    let not_after = cert_not_after(path)?;
    let now = OffsetDateTime::now_utc();
    Ok(now >= not_after)
}

#[derive(Debug)]
struct FileReloadingResolver {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    state: RwLock<ReloadState>,
}

#[derive(Debug)]
struct ReloadState {
    certified_key: Arc<CertifiedKey>,
    last_modified: SystemTime,
    last_checked: SystemTime,
}

impl FileReloadingResolver {
    fn new(cert_path: std::path::PathBuf, key_path: std::path::PathBuf) -> io::Result<Self> {
        let certified_key = load_certified_key(&cert_path, &key_path)?;
        let last_modified = latest_modified(&cert_path, &key_path)?;
        Ok(Self {
            cert_path,
            key_path,
            state: RwLock::new(ReloadState {
                certified_key,
                last_modified,
                last_checked: SystemTime::UNIX_EPOCH,
            }),
        })
    }

    fn maybe_reload(&self) -> io::Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| io::Error::other("TLS resolver lock poisoned"))?;

        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(state.last_checked)
            && elapsed < RELOAD_DEBOUNCE
        {
            return Ok(());
        }
        state.last_checked = now;

        let latest = latest_modified(&self.cert_path, &self.key_path)?;
        if latest <= state.last_modified {
            return Ok(());
        }

        let certified_key = load_certified_key(&self.cert_path, &self.key_path)?;
        state.certified_key = certified_key;
        state.last_modified = latest;
        Ok(())
    }
}

impl ResolvesServerCert for FileReloadingResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Err(err) = self.maybe_reload() {
            log::warn!("TLS reload failed: {}", err);
        }
        self.state
            .read()
            .ok()
            .map(|state| Arc::clone(&state.certified_key))
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> io::Result<Arc<CertifiedKey>> {
    let cert_chain = load_cert_chain(cert_path)?;
    let private_key = load_private_key(key_path)?;
    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(cert_chain, private_key, &provider)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(Arc::new(certified_key))
}

fn latest_modified(cert_path: &Path, key_path: &Path) -> io::Result<SystemTime> {
    let cert_meta = fs::metadata(cert_path)?;
    let key_meta = fs::metadata(key_path)?;
    let cert_modified = cert_meta.modified()?;
    let key_modified = key_meta.modified()?;
    Ok(std::cmp::max(cert_modified, key_modified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, TlsConfig,
        UploadConfig, ValidatedConfig, test_local_users_config,
    };
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::time::Duration as StdDuration;

    fn build_test_config(
        servers: Vec<crate::config::ServerListenerConfig>,
        tls: TlsConfig,
    ) -> ValidatedConfig {
        ValidatedConfig {
            servers,
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: test_local_users_config(),
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 2,
                cooldown_seconds: 30,
                use_forwarded_for: false,
                login_sessions: crate::config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: Some(tls),
            app: AppConfig {
                name: "Test App".to_string(),
                description: "Test Description".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["jpg".to_string()],
            },
            streaming: StreamingConfig { enabled: true },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    fn https_main_and_well_known() -> Vec<crate::config::ServerListenerConfig> {
        vec![
            crate::config::ServerListenerConfig {
                name: Some("main-https".to_string()),
                role: crate::config::ServerRole::Main,
                host: "127.0.0.1".to_string(),
                port: 8443,
                protocol: crate::config::ServerProtocol::Https,
            },
            crate::config::ServerListenerConfig {
                name: Some("well-known".to_string()),
                role: crate::config::ServerRole::WellKnown,
                host: "127.0.0.1".to_string(),
                port: 8080,
                protocol: crate::config::ServerProtocol::Http,
            },
        ]
    }

    fn self_signed_tls() -> TlsConfig {
        TlsConfig {
            mode: TlsMode::SelfSigned,
            domains: vec!["example.com".to_string()],
            redirect_base_url: None,
            acme: None,
        }
    }

    fn user_provided_tls() -> TlsConfig {
        TlsConfig {
            mode: TlsMode::UserProvided,
            domains: Vec::new(),
            redirect_base_url: None,
            acme: None,
        }
    }

    #[test]
    fn self_signed_generates_missing_certificates() {
        let fixture = TestFixtureRoot::new_unique("tls-self-signed").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let config = build_test_config(https_main_and_well_known(), self_signed_tls());

        let result = load_rustls_config(&runtime_paths, &config);
        assert!(result.is_ok(), "expected self-signed TLS to generate");

        let tls_dir = runtime_paths.state_sys_dir.join("tls");
        assert!(tls_dir.join("cert.pem").exists());
        assert!(tls_dir.join("key.pem").exists());
    }

    #[test]
    fn user_provided_missing_certificates_fail() {
        let fixture = TestFixtureRoot::new_unique("tls-user-missing").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let config = build_test_config(https_main_and_well_known(), user_provided_tls());

        let result = load_rustls_config(&runtime_paths, &config);
        assert!(result.is_err(), "expected missing user cert to fail");
    }

    #[test]
    fn self_signed_regenerates_expired_certificates() {
        let fixture = TestFixtureRoot::new_unique("tls-self-expired").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let tls_dir = runtime_paths.state_sys_dir.join("tls");
        fs::create_dir_all(&tls_dir).unwrap();

        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(2);
        params.not_after = now - time::Duration::days(1);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        fs::write(tls_dir.join("cert.pem"), cert.pem()).unwrap();
        fs::write(tls_dir.join("key.pem"), key_pair.serialize_pem()).unwrap();

        let config = build_test_config(https_main_and_well_known(), self_signed_tls());
        let result = load_rustls_config(&runtime_paths, &config);
        assert!(result.is_ok(), "expected expired cert to regenerate");
        let expired = cert_is_expired(&tls_dir.join("cert.pem")).unwrap();
        assert!(!expired, "expected regenerated cert to be valid");
    }

    #[test]
    fn load_cert_chain_rejects_invalid_pem() {
        let fixture = TestFixtureRoot::new_unique("tls-invalid-cert").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let tls_dir = runtime_paths.state_sys_dir.join("tls");
        fs::create_dir_all(&tls_dir).unwrap();
        let cert_path = tls_dir.join("cert.pem");
        fs::write(&cert_path, "not a cert").unwrap();

        let result = load_cert_chain(&cert_path);
        assert!(result.is_err(), "expected invalid cert to fail");
    }

    #[test]
    fn load_private_key_rejects_invalid_pem() {
        let fixture = TestFixtureRoot::new_unique("tls-invalid-key").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let tls_dir = runtime_paths.state_sys_dir.join("tls");
        fs::create_dir_all(&tls_dir).unwrap();
        let key_path = tls_dir.join("key.pem");
        fs::write(&key_path, "not a key").unwrap();

        let result = load_private_key(&key_path);
        assert!(result.is_err(), "expected invalid key to fail");
    }

    #[test]
    fn file_reloading_resolver_updates_cert() {
        let fixture = TestFixtureRoot::new_unique("tls-reload").unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let tls_dir = runtime_paths.state_sys_dir.join("tls");
        fs::create_dir_all(&tls_dir).unwrap();
        let cert_path = tls_dir.join("cert.pem");
        let key_path = tls_dir.join("key.pem");

        write_self_signed_cert(&cert_path, &key_path, "example.com");
        let resolver = FileReloadingResolver::new(cert_path.clone(), key_path.clone()).unwrap();
        let initial = resolver
            .state
            .read()
            .unwrap()
            .certified_key
            .cert
            .first()
            .unwrap()
            .as_ref()
            .to_vec();

        std::thread::sleep(StdDuration::from_secs(1));
        write_self_signed_cert(&cert_path, &key_path, "example.org");

        resolver.maybe_reload().unwrap();
        let updated = resolver
            .state
            .read()
            .unwrap()
            .certified_key
            .cert
            .first()
            .unwrap()
            .as_ref()
            .to_vec();

        assert_ne!(initial, updated, "expected cert to reload");
    }

    fn write_self_signed_cert(cert_path: &Path, key_path: &Path, domain: &str) {
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        fs::write(cert_path, cert.pem()).unwrap();
        fs::write(key_path, key_pair.serialize_pem()).unwrap();
    }
}
