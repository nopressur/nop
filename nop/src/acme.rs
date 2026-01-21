// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{AcmeChallenge, AcmeConfig, AcmeEnvironment, TlsMode, ValidatedConfig};
use crate::runtime_paths::RuntimePaths;
use crate::tls::cert_not_after;
use async_trait::async_trait;
use lers::solver::dns::CloudflareDns01Solver;
use lers::{Directory, LETS_ENCRYPT_PRODUCTION_URL, LETS_ENCRYPT_STAGING_URL, Solver};
use log::{info, warn};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use time::{Duration, OffsetDateTime};
use tokio::process::Command;

const RENEWAL_WINDOW_DAYS: i64 = 30;
const RENEWAL_INTERVAL_HOURS: u64 = 12;
#[derive(Clone, Default)]
pub struct AcmeTokenStore {
    inner: Arc<RwLock<HashMap<String, AcmeTokenEntry>>>,
}

impl AcmeTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: String, key_authorization: String, domain: String) {
        let entry = AcmeTokenEntry {
            key_authorization,
            domain,
            created_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        };
        match self.inner.write() {
            Ok(mut guard) => {
                guard.insert(token, entry);
            }
            Err(_) => {
                warn!("ACME token store lock poisoned; insert skipped");
            }
        }
    }

    pub fn get_key_authorization(&self, token: &str) -> Option<String> {
        match self.inner.read() {
            Ok(guard) => guard
                .get(token)
                .map(|entry| entry.key_authorization.clone()),
            Err(_) => {
                warn!("ACME token store lock poisoned; lookup skipped");
                None
            }
        }
    }

    fn remove(&self, token: &str) -> Option<AcmeTokenEntry> {
        match self.inner.write() {
            Ok(mut guard) => guard.remove(token),
            Err(_) => {
                warn!("ACME token store lock poisoned; cleanup skipped");
                None
            }
        }
    }
}

#[derive(Clone)]
pub struct AcmeHttp01Solver {
    store: AcmeTokenStore,
}

impl AcmeHttp01Solver {
    pub fn new(store: AcmeTokenStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Solver for AcmeHttp01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.store.insert(token, key_authorization, domain);
        Ok(())
    }

    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        if let Some(entry) = self.store.remove(token) {
            log::debug!("ACME token cleaned for {}", entry.domain);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ExecDns01Solver {
    present_command: String,
    cleanup_command: String,
    tokens: ExecDnsTokenStore,
}

#[derive(Clone, Debug)]
struct ExecDnsTokenEntry {
    domain: String,
    key_authorization: String,
}

#[derive(Clone)]
struct ExecDnsTokenStore {
    sender: mpsc::Sender<ExecDnsTokenCommand>,
}

enum ExecDnsTokenCommand {
    Insert {
        token: String,
        entry: ExecDnsTokenEntry,
    },
    Take {
        token: String,
        reply: mpsc::Sender<Option<ExecDnsTokenEntry>>,
    },
}

impl ExecDns01Solver {
    fn new(present_command: String, cleanup_command: String) -> Self {
        Self {
            present_command,
            cleanup_command,
            tokens: ExecDnsTokenStore::new(),
        }
    }

    async fn run_command(
        &self,
        command: &str,
        domain: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("ACME_DOMAIN", domain)
            .env("ACME_TOKEN", token)
            .env("ACME_KEY_AUTHORIZATION", key_authorization)
            .env("ACME_DNS_VALUE", key_authorization)
            .output()
            .await?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Box::new(io::Error::other(format!(
                "DNS exec command failed ({}) stdout={} stderr={}",
                command, stdout, stderr
            ))));
        }

        Ok(())
    }
}

impl ExecDnsTokenStore {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::Builder::new().name("acme-exec-dns".to_string());
        if let Err(err) = thread.spawn(move || run_exec_dns_tokens(receiver)) {
            warn!("ACME exec DNS token worker failed to start: {}", err);
        }
        Self { sender }
    }

    fn insert(&self, token: String, entry: ExecDnsTokenEntry) {
        if self
            .sender
            .send(ExecDnsTokenCommand::Insert { token, entry })
            .is_err()
        {
            warn!("ACME exec DNS token store channel closed; cleanup may fail");
        }
    }

    fn take(&self, token: &str) -> Option<ExecDnsTokenEntry> {
        let (reply, receive) = mpsc::channel();
        if self
            .sender
            .send(ExecDnsTokenCommand::Take {
                token: token.to_string(),
                reply,
            })
            .is_err()
        {
            warn!("ACME exec DNS token store channel closed; cleanup skipped");
            return None;
        }
        receive.recv().ok().flatten()
    }
}

fn run_exec_dns_tokens(receiver: mpsc::Receiver<ExecDnsTokenCommand>) {
    let mut tokens: HashMap<String, ExecDnsTokenEntry> = HashMap::new();
    while let Ok(command) = receiver.recv() {
        match command {
            ExecDnsTokenCommand::Insert { token, entry } => {
                tokens.insert(token, entry);
            }
            ExecDnsTokenCommand::Take { token, reply } => {
                let entry = tokens.remove(&token);
                let _ = reply.send(entry);
            }
        }
    }
}

#[async_trait]
impl Solver for ExecDns01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.run_command(&self.present_command, &domain, &token, &key_authorization)
            .await?;

        self.tokens.insert(
            token,
            ExecDnsTokenEntry {
                domain,
                key_authorization,
            },
        );

        Ok(())
    }

    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let entry = self.tokens.take(token);

        if let Some(entry) = entry {
            self.run_command(
                &self.cleanup_command,
                &entry.domain,
                token,
                &entry.key_authorization,
            )
            .await?;
        }

        Ok(())
    }
}

// Reserved for ACME test harness overrides (HTTP-01 now, DNS-01 later).
pub enum AcmeSolverOverride {
    #[allow(dead_code)]
    Http01(Box<dyn Solver + Send + Sync>),
    #[allow(dead_code)]
    Dns01(Box<dyn Solver + Send + Sync>),
}

pub async fn ensure_acme_certificate(
    runtime_paths: &RuntimePaths,
    config: &ValidatedConfig,
    token_store: Option<AcmeTokenStore>,
    solver_override: Option<AcmeSolverOverride>,
) -> io::Result<bool> {
    let tls = config
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config missing"))?;

    if tls.mode != TlsMode::Acme {
        return Ok(false);
    }

    let acme = tls
        .acme
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ACME config missing"))?;

    let tls_dir = runtime_paths.state_sys_dir.join("tls");
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    let status = cert_status(&cert_path, &key_path)?;
    let must_issue = matches!(
        status,
        CertStatus::Missing | CertStatus::Expired | CertStatus::Invalid
    );
    let should_issue = matches!(status, CertStatus::ExpiringSoon);

    if !must_issue && !should_issue {
        return Ok(false);
    }

    let result = issue_certificate(runtime_paths, tls, acme, token_store, solver_override).await;

    match result {
        Ok(()) => Ok(true),
        Err(err) if must_issue => Err(err),
        Err(err) => {
            warn!("ACME renewal failed: {}", err);
            Ok(false)
        }
    }
}

pub fn spawn_renewal_loop(
    runtime_paths: RuntimePaths,
    config: Arc<ValidatedConfig>,
    token_store: Option<AcmeTokenStore>,
) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                warn!("ACME renewal loop disabled: {}", err);
                return;
            }
        };

        let interval = std::time::Duration::from_secs(RENEWAL_INTERVAL_HOURS * 60 * 60);
        loop {
            std::thread::sleep(interval);
            if let Err(err) = runtime.block_on(ensure_acme_certificate(
                &runtime_paths,
                &config,
                token_store.clone(),
                None,
            )) {
                warn!("ACME renewal loop failed: {}", err);
            }
        }
    });
}

async fn issue_certificate(
    runtime_paths: &RuntimePaths,
    tls: &crate::config::TlsConfig,
    acme: &AcmeConfig,
    token_store: Option<AcmeTokenStore>,
    solver_override: Option<AcmeSolverOverride>,
) -> io::Result<()> {
    let directory_url = resolve_directory_url(acme)?;
    let client = build_client(acme)?;
    let mut builder = Directory::builder(directory_url.clone()).client(client);

    match acme.challenge {
        AcmeChallenge::Http01 => {
            let solver: Box<dyn Solver + Send + Sync> = match solver_override {
                Some(AcmeSolverOverride::Http01(solver)) => solver,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ACME solver override does not match http-01 challenge",
                    ));
                }
                None => {
                    let store = token_store.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "ACME http-01 requires a token store",
                        )
                    })?;
                    Box::new(AcmeHttp01Solver::new(store))
                }
            };
            let solver: Box<dyn Solver> = solver;
            builder = builder.http01_solver(solver);
        }
        AcmeChallenge::Dns01 => {
            let solver: Box<dyn Solver + Send + Sync> = match solver_override {
                Some(AcmeSolverOverride::Dns01(solver)) => solver,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ACME solver override does not match dns-01 challenge",
                    ));
                }
                None => build_dns_solver(acme)?,
            };
            let solver: Box<dyn Solver> = solver;
            builder = builder.dns01_solver(solver);
        }
    }

    let directory = builder
        .build()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;

    let account_key_path = runtime_paths
        .state_sys_dir
        .join("tls")
        .join("acme-account.pem");
    let account_key = load_or_create_account_key(&account_key_path)?;

    let account = directory
        .account()
        .contacts(vec![format!("mailto:{}", acme.contact_email)])
        .terms_of_service_agreed(true)
        .private_key(account_key)
        .create_if_not_exists()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;

    write_acme_metadata(
        runtime_paths
            .state_sys_dir
            .join("tls")
            .join("acme-meta.json"),
        acme,
        &directory_url,
        None,
    )?;

    let mut cert_builder = account.certificate();
    for domain in &tls.domains {
        cert_builder = cert_builder.add_domain(domain);
    }

    let certificate = cert_builder
        .obtain()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;

    let tls_dir = runtime_paths.state_sys_dir.join("tls");
    fs::create_dir_all(&tls_dir)?;

    fs::write(
        tls_dir.join("cert.pem"),
        certificate
            .fullchain_to_pem()
            .map_err(|err| io::Error::other(err.to_string()))?,
    )?;
    fs::write(
        tls_dir.join("key.pem"),
        certificate
            .private_key_to_pem()
            .map_err(|err| io::Error::other(err.to_string()))?,
    )?;
    fs::write(
        tls_dir.join("last-renewed.txt"),
        OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
    )?;

    info!("ACME certificate issued for {}", tls.domains.join(", "));

    Ok(())
}

fn build_client(acme: &AcmeConfig) -> io::Result<Client> {
    let mut builder = Client::builder().user_agent("nopressure-acme");
    if acme.insecure_skip_verify {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    builder
        .build()
        .map_err(|err| io::Error::other(err.to_string()))
}

fn build_dns_solver(acme: &AcmeConfig) -> io::Result<Box<dyn Solver + Send + Sync>> {
    let dns = acme.dns.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME DNS-01 requires dns configuration",
        )
    })?;

    let provider = dns.provider.trim().to_lowercase();
    match provider.as_str() {
        "cloudflare" => {
            let token = dns
                .api_token
                .as_deref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ACME DNS-01 cloudflare requires api_token",
                    )
                })
                .and_then(resolve_secret)?;

            CloudflareDns01Solver::new_with_token(token)
                .build()
                .map(|solver| Box::new(solver) as Box<dyn Solver + Send + Sync>)
                .map_err(|err| io::Error::other(err.to_string()))
        }
        "exec" => {
            let exec = dns.exec.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME DNS-01 exec requires exec configuration",
                )
            })?;
            Ok(Box::new(ExecDns01Solver::new(
                exec.present_command.clone(),
                exec.cleanup_command.clone(),
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported DNS-01 provider: {}", dns.provider),
        )),
    }
}

fn resolve_directory_url(acme: &AcmeConfig) -> io::Result<String> {
    if let Some(url) = &acme.directory_url {
        return Ok(url.clone());
    }

    let url = match acme.environment {
        AcmeEnvironment::Production => LETS_ENCRYPT_PRODUCTION_URL,
        AcmeEnvironment::Staging => LETS_ENCRYPT_STAGING_URL,
    };
    Ok(url.to_string())
}

fn load_or_create_account_key(path: &Path) -> io::Result<PKey<Private>> {
    if path.exists() {
        let bytes = fs::read(path)?;
        return PKey::private_key_from_pem(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()));
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|err| io::Error::other(err.to_string()))?;
    let ec_key = EcKey::generate(&group).map_err(|err| io::Error::other(err.to_string()))?;
    let key = PKey::from_ec_key(ec_key).map_err(|err| io::Error::other(err.to_string()))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let pem = key
        .private_key_to_pem_pkcs8()
        .map_err(|err| io::Error::other(err.to_string()))?;
    fs::write(path, pem)?;

    Ok(key)
}

fn resolve_secret(secret: &str) -> io::Result<String> {
    if let Some(name) = secret.strip_prefix("env:") {
        let value = std::env::var(name.trim()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Missing environment variable: {}", name.trim()),
            )
        })?;
        return Ok(value);
    }

    Ok(secret.to_string())
}

fn write_acme_metadata(
    path: PathBuf,
    acme: &AcmeConfig,
    directory_url: &str,
    account_id: Option<String>,
) -> io::Result<()> {
    let metadata = AcmeMetadata {
        provider: acme.provider.clone(),
        directory_url: directory_url.to_string(),
        contact_email: acme.contact_email.clone(),
        account_id,
        created_at: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
    };
    let payload = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
    fs::write(path, payload)?;
    Ok(())
}

fn cert_status(cert_path: &Path, key_path: &Path) -> io::Result<CertStatus> {
    if !cert_path.exists() || !key_path.exists() {
        return Ok(CertStatus::Missing);
    }

    let not_after = match cert_not_after(cert_path) {
        Ok(value) => value,
        Err(_) => return Ok(CertStatus::Invalid),
    };

    let now = OffsetDateTime::now_utc();
    if now >= not_after {
        return Ok(CertStatus::Expired);
    }

    if now + Duration::days(RENEWAL_WINDOW_DAYS) >= not_after {
        return Ok(CertStatus::ExpiringSoon);
    }

    Ok(CertStatus::Valid)
}

#[derive(Debug)]
enum CertStatus {
    Missing,
    Invalid,
    Expired,
    ExpiringSoon,
    Valid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AcmeTokenEntry {
    key_authorization: String,
    domain: String,
    created_at_unix: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AcmeMetadata {
    provider: String,
    directory_url: String,
    contact_email: String,
    account_id: Option<String>,
    created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig,
    };
    use crate::util::test_fixtures::TestFixtureRoot;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fs;
    use std::future::Future;
    use std::net::TcpStream;
    use std::process::Command;
    use std::sync::{Arc, OnceLock, mpsc};
    use std::thread;
    use std::time::{Duration as StdDuration, Instant};
    use tokio::sync::Semaphore;
    use tokio::time::sleep;

    #[tokio::test]
    async fn http01_solver_stores_and_cleans() {
        let store = AcmeTokenStore::new();
        let solver = AcmeHttp01Solver::new(store.clone());

        solver
            .present(
                "example.com".to_string(),
                "token".to_string(),
                "authz".to_string(),
            )
            .await
            .expect("present should succeed");
        assert_eq!(
            store.get_key_authorization("token"),
            Some("authz".to_string())
        );

        solver
            .cleanup("token")
            .await
            .expect("cleanup should succeed");
        assert!(store.get_key_authorization("token").is_none());
    }

    #[test]
    fn token_store_round_trip() {
        let store = AcmeTokenStore::new();
        store.insert(
            "token".to_string(),
            "authz".to_string(),
            "example.com".to_string(),
        );
        assert_eq!(
            store.get_key_authorization("token"),
            Some("authz".to_string())
        );
        let _ = store.remove("token");
        assert!(store.get_key_authorization("token").is_none());
    }

    static PEBBLE_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

    async fn acquire_pebble_permit() -> tokio::sync::OwnedSemaphorePermit {
        let semaphore = PEBBLE_SEMAPHORE
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        semaphore
            .acquire_owned()
            .await
            .expect("pebble semaphore closed")
    }

    async fn with_pebble_harness<F, Fut>(label: &str, test: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        if !docker_available() {
            eprintln!("Skipping ACME test ({label}): Docker not available.");
            return;
        }

        let _permit = acquire_pebble_permit().await;

        let script = repo_root().join("scripts").join("acme-pebble.sh");
        if !script.exists() {
            panic!("ACME harness script missing: {}", script.display());
        }

        run_script(&script, "start").expect("failed to start Pebble harness");
        let _guard = PebbleGuard { script };

        let ready = wait_for_port("127.0.0.1:14000", StdDuration::from_secs(10));
        assert!(ready, "Pebble did not become ready on port 14000");
        let ready = wait_for_port("127.0.0.1:8055", StdDuration::from_secs(10));
        assert!(
            ready,
            "Pebble challenge server did not become ready on port 8055"
        );
        let ready =
            wait_for_acme_directory("https://localhost:14000/dir", StdDuration::from_secs(10))
                .await;
        assert!(ready, "Pebble ACME directory did not become ready");

        test().await;
    }

    async fn wait_for_acme_directory(url: &str, timeout: StdDuration) -> bool {
        let client = match Client::builder().danger_accept_invalid_certs(true).build() {
            Ok(client) => client,
            Err(_) => return false,
        };

        let start = Instant::now();
        while start.elapsed() < timeout {
            let response = client.get(url).send().await;
            if matches!(response, Ok(res) if res.status().is_success()) {
                return true;
            }
            sleep(StdDuration::from_millis(250)).await;
        }
        false
    }

    async fn ensure_acme_with_retry<F>(
        runtime_paths: &RuntimePaths,
        config: &ValidatedConfig,
        mut solver_override: F,
    ) -> bool
    where
        F: FnMut() -> AcmeSolverOverride,
    {
        let mut last_error = None;

        for attempt in 1..=3 {
            match ensure_acme_certificate(runtime_paths, config, None, Some(solver_override()))
                .await
            {
                Ok(result) => return result,
                Err(err) => {
                    last_error = Some(err);
                    if attempt < 3 {
                        sleep(StdDuration::from_secs(1)).await;
                    }
                }
            }
        }

        let err = last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        panic!("ACME issuance should succeed: {}", err);
    }

    #[tokio::test]
    async fn acme_issues_certificate_with_pebble() {
        with_pebble_harness("http-01", || async {
            let fixture = TestFixtureRoot::new_unique("acme-pebble-http01").unwrap();
            let runtime_paths = fixture.runtime_paths().unwrap();
            fs::create_dir_all(runtime_paths.state_sys_dir.join("tls")).unwrap();

            let config = build_acme_test_config(AcmeChallenge::Http01);
            let solver = PebbleHttp01Solver::new("http://127.0.0.1:8055");
            let issued = ensure_acme_with_retry(&runtime_paths, &config, || {
                AcmeSolverOverride::Http01(Box::new(solver.clone()))
            })
            .await;

            assert!(issued, "expected ACME to issue a certificate");
            assert!(
                runtime_paths
                    .state_sys_dir
                    .join("tls")
                    .join("cert.pem")
                    .exists()
            );
            assert!(
                runtime_paths
                    .state_sys_dir
                    .join("tls")
                    .join("key.pem")
                    .exists()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn acme_issues_certificate_with_pebble_dns01() {
        with_pebble_harness("dns-01", || async {
            let fixture = TestFixtureRoot::new_unique("acme-pebble-dns01").unwrap();
            let runtime_paths = fixture.runtime_paths().unwrap();
            fs::create_dir_all(runtime_paths.state_sys_dir.join("tls")).unwrap();

            let config = build_acme_test_config(AcmeChallenge::Dns01);
            let solver = PebbleDns01Solver::new("http://127.0.0.1:8055");
            let issued = ensure_acme_with_retry(&runtime_paths, &config, || {
                AcmeSolverOverride::Dns01(Box::new(solver.clone()))
            })
            .await;

            assert!(issued, "expected ACME to issue a certificate");
            assert!(
                runtime_paths
                    .state_sys_dir
                    .join("tls")
                    .join("cert.pem")
                    .exists()
            );
            assert!(
                runtime_paths
                    .state_sys_dir
                    .join("tls")
                    .join("key.pem")
                    .exists()
            );
        })
        .await;
    }

    fn build_acme_test_config(challenge: AcmeChallenge) -> ValidatedConfig {
        ValidatedConfig {
            servers: Vec::new(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: crate::config::ValidatedUsersConfig::Local(
                crate::config::ValidatedLocalAuthConfig {
                    jwt: crate::config::JwtConfig {
                        secret: "test-secret".to_string(),
                        issuer: "nopressure".to_string(),
                        audience: "nopressure-users".to_string(),
                        expiration_hours: 12,
                        cookie_name: "nop_auth".to_string(),
                        disable_refresh: false,
                        refresh_threshold_percentage: 10,
                        refresh_threshold_hours: 24,
                    },
                    password: crate::config::PasswordHashingParams::default(),
                },
            ),
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
            tls: Some(crate::config::TlsConfig {
                mode: crate::config::TlsMode::Acme,
                domains: vec!["example.com".to_string()],
                redirect_base_url: None,
                acme: Some(AcmeConfig {
                    provider: "lers".to_string(),
                    environment: AcmeEnvironment::Staging,
                    directory_url: Some("https://localhost:14000/dir".to_string()),
                    insecure_skip_verify: true,
                    contact_email: "admin@example.com".to_string(),
                    challenge,
                    dns: None,
                }),
            }),
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

    #[derive(Clone)]
    struct TestTokenStore {
        sender: mpsc::Sender<TestTokenCommand>,
    }

    enum TestTokenCommand {
        Insert {
            token: String,
            value: String,
        },
        Take {
            token: String,
            reply: mpsc::Sender<Option<String>>,
        },
    }

    impl TestTokenStore {
        fn new() -> Self {
            let (sender, receiver) = mpsc::channel();
            let thread = thread::Builder::new().name("acme-test-tokens".to_string());
            if let Err(err) = thread.spawn(move || run_test_token_store(receiver)) {
                eprintln!("ACME test token worker failed to start: {err}");
            }
            Self { sender }
        }

        fn insert(&self, token: String, value: String) {
            let _ = self.sender.send(TestTokenCommand::Insert { token, value });
        }

        fn take(&self, token: &str) -> Option<String> {
            let (reply, receive) = mpsc::channel();
            if self
                .sender
                .send(TestTokenCommand::Take {
                    token: token.to_string(),
                    reply,
                })
                .is_err()
            {
                return None;
            }
            receive.recv().ok().flatten()
        }
    }

    fn run_test_token_store(receiver: mpsc::Receiver<TestTokenCommand>) {
        let mut tokens: HashMap<String, String> = HashMap::new();
        while let Ok(command) = receiver.recv() {
            match command {
                TestTokenCommand::Insert { token, value } => {
                    tokens.insert(token, value);
                }
                TestTokenCommand::Take { token, reply } => {
                    let value = tokens.remove(&token);
                    let _ = reply.send(value);
                }
            }
        }
    }

    #[derive(Clone)]
    struct PebbleHttp01Solver {
        client: Client,
        api_base: String,
        tokens: TestTokenStore,
    }

    impl PebbleHttp01Solver {
        fn new(api_base: &str) -> Self {
            Self {
                client: Client::new(),
                api_base: api_base.to_string(),
                tokens: TestTokenStore::new(),
            }
        }
    }

    #[derive(Clone)]
    struct PebbleDns01Solver {
        client: Client,
        api_base: String,
        tokens: TestTokenStore,
    }

    impl PebbleDns01Solver {
        fn new(api_base: &str) -> Self {
            Self {
                client: Client::new(),
                api_base: api_base.to_string(),
                tokens: TestTokenStore::new(),
            }
        }
    }

    #[async_trait]
    impl Solver for PebbleHttp01Solver {
        async fn present(
            &self,
            domain: String,
            token: String,
            key_authorization: String,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let addresses = ["10.30.50.3"];
            post_json(
                &self.client,
                &format!("{}/add-a", self.api_base),
                &DnsRequest {
                    host: &domain,
                    addresses: Some(&addresses),
                },
            )
            .await?;

            post_json(
                &self.client,
                &format!("{}/add-http01", self.api_base),
                &Http01Request {
                    token: &token,
                    content: Some(&key_authorization),
                },
            )
            .await?;

            self.tokens.insert(token, domain);

            Ok(())
        }

        async fn cleanup(
            &self,
            token: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let domain = self.tokens.take(token);
            let domain = match domain {
                Some(domain) => domain,
                None => return Ok(()),
            };

            post_json(
                &self.client,
                &format!("{}/clear-a", self.api_base),
                &DnsRequest {
                    host: &domain,
                    addresses: None,
                },
            )
            .await?;

            post_json(
                &self.client,
                &format!("{}/del-http01", self.api_base),
                &Http01Request {
                    token,
                    content: None,
                },
            )
            .await?;

            Ok(())
        }
    }

    #[async_trait]
    impl Solver for PebbleDns01Solver {
        async fn present(
            &self,
            domain: String,
            token: String,
            key_authorization: String,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let host = format!("_acme-challenge.{domain}.");
            post_json(
                &self.client,
                &format!("{}/set-txt", self.api_base),
                &DnsTxtRequest {
                    host: &host,
                    value: &key_authorization,
                },
            )
            .await?;

            self.tokens.insert(token, host);

            Ok(())
        }

        async fn cleanup(
            &self,
            token: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            let host = self.tokens.take(token);
            let host = match host {
                Some(host) => host,
                None => return Ok(()),
            };

            post_json(
                &self.client,
                &format!("{}/clear-txt", self.api_base),
                &DnsTxtCleanupRequest { host: &host },
            )
            .await?;

            Ok(())
        }
    }

    #[derive(Serialize)]
    struct DnsRequest<'a> {
        host: &'a str,
        addresses: Option<&'a [&'a str]>,
    }

    #[derive(Serialize)]
    struct DnsTxtRequest<'a> {
        host: &'a str,
        value: &'a str,
    }

    #[derive(Serialize)]
    struct DnsTxtCleanupRequest<'a> {
        host: &'a str,
    }

    #[derive(Serialize)]
    struct Http01Request<'a> {
        token: &'a str,
        content: Option<&'a str>,
    }

    async fn post_json<T: Serialize>(
        client: &Client,
        url: &str,
        payload: &T,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        client
            .post(url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn docker_available() -> bool {
        Command::new("docker")
            .args(["info"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn run_script(script: &PathBuf, command: &str) -> Result<(), String> {
        let output = Command::new("bash")
            .arg(script)
            .arg(command)
            .output()
            .map_err(|err| format!("Failed to run script: {err}"))?;

        if output.status.success() {
            return Ok(());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Script failed ({command}): stdout={stdout} stderr={stderr}"
        ))
    }

    fn wait_for_port(address: &str, timeout: StdDuration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if TcpStream::connect(address).is_ok() {
                return true;
            }
            thread::sleep(StdDuration::from_millis(250));
        }
        false
    }

    fn repo_root() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.parent().expect("repo root").to_path_buf()
    }

    struct PebbleGuard {
        script: PathBuf,
    }

    impl Drop for PebbleGuard {
        fn drop(&mut self) {
            let _ = run_script(&self.script, "stop");
        }
    }
}
