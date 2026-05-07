// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::tls::{
    TlsAcmeState, build_tls_state, cert_covers_domains, cert_not_after, read_tls_state,
    tls_config_fingerprint, validate_private_key, write_tls_state,
};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use log::{info, warn};
use nop_config::{
    AcmeChallenge, AcmeConfig, AcmeDnsConfig, AcmeEnvironment, TlsMode, ValidatedConfig,
};
use nop_rt_paths::RuntimePaths;
use reqwest::Client;
use reqwest::StatusCode;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::result::Result as StdResult;
use std::sync::{Arc, RwLock};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::OnceCell;

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

#[derive(Clone, Copy, Debug, PartialEq)]
enum ChallengeType {
    Http01,
    Dns01,
}

#[async_trait]
pub trait Http01Provider: Send + Sync {
    async fn present(
        &self,
        domain: &str,
        token: &str,
        key_authorization: &str,
    ) -> StdResult<(), Box<dyn StdError>>;

    async fn cleanup(&self, token: &str) -> StdResult<(), Box<dyn StdError>>;
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn add_txt_record(&self, domain: &str, value: &str) -> StdResult<(), Box<dyn StdError>>;
    async fn remove_txt_record(
        &self,
        domain: &str,
        value: &str,
    ) -> StdResult<(), Box<dyn StdError>>;
}

#[derive(Clone)]
pub struct AcmeHttp01Provider {
    store: AcmeTokenStore,
}

impl AcmeHttp01Provider {
    pub fn new(store: AcmeTokenStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Http01Provider for AcmeHttp01Provider {
    async fn present(
        &self,
        domain: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.store.insert(
            token.to_string(),
            key_authorization.to_string(),
            domain.to_string(),
        );
        Ok(())
    }

    async fn cleanup(&self, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(entry) = self.store.remove(token) {
            log::debug!("ACME token cleaned for {}", entry.domain);
        }
        Ok(())
    }
}

#[async_trait]
trait DnsTxtResolver: Send + Sync {
    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>>;
}

fn parse_dns_resolver_addr(value: &str) -> io::Result<SocketAddr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME DNS resolver cannot be empty",
        ));
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Invalid DNS resolver address: {}", value),
    ))
}

fn build_name_servers(addrs: &[SocketAddr]) -> Vec<NameServerConfig> {
    let mut group = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let mut connection = ConnectionConfig::udp();
        connection.port = addr.port();
        group.push(NameServerConfig::new(addr.ip(), false, vec![connection]));
    }
    group
}

fn format_resolver_label(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn lookup_zone_for_name(resolver: &TokioResolver, name: &str) -> io::Result<String> {
    let mut current = name.trim_end_matches('.').to_string();
    loop {
        let query = format!("{current}.");
        if let Ok(lookup) = resolver.lookup(query.as_str(), RecordType::SOA).await
            && let Some(record) = lookup.answers().first()
        {
            return Ok(record.name.to_utf8());
        }
        if let Some((_, parent)) = current.split_once('.') {
            current = parent.to_string();
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Unable to discover SOA record for {}", name),
            ));
        }
    }
}

async fn lookup_authoritative_servers(
    resolver: &TokioResolver,
    zone: &str,
) -> io::Result<Vec<String>> {
    let query = if zone.ends_with('.') {
        zone.to_string()
    } else {
        format!("{zone}.")
    };
    let lookup = resolver
        .lookup(query.as_str(), RecordType::NS)
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut names = Vec::new();
    for record in lookup.answers() {
        if let RData::NS(ns) = &record.data {
            names.push(ns.to_utf8());
        }
    }
    if names.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No NS records found for {}", zone),
        ));
    }
    Ok(names)
}

async fn resolve_name_server_addresses(
    resolver: &TokioResolver,
    servers: &[String],
) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for server in servers {
        let lookup = resolver
            .lookup_ip(server.as_str())
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        for ip in lookup.iter() {
            addrs.push(SocketAddr::new(ip, 53));
        }
    }
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No IP addresses resolved for authoritative name servers",
        ));
    }
    Ok(addrs)
}

async fn build_authoritative_resolver(
    resolver: &TokioResolver,
    name: &str,
) -> io::Result<(TokioResolver, Vec<SocketAddr>, String)> {
    let zone = lookup_zone_for_name(resolver, name).await?;
    let servers = lookup_authoritative_servers(resolver, &zone).await?;
    let addrs = resolve_name_server_addresses(resolver, &servers).await?;
    let name_servers = build_name_servers(&addrs);
    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|err| io::Error::other(err.to_string()))?;
    Ok((resolver, addrs, zone))
}

struct ExplicitDnsResolver {
    resolver: TokioResolver,
}

impl ExplicitDnsResolver {
    fn new(dns: &AcmeDnsConfig) -> io::Result<Self> {
        let mut addrs = Vec::with_capacity(dns.resolver.len());
        for entry in &dns.resolver {
            addrs.push(parse_dns_resolver_addr(entry)?);
        }
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME DNS resolver override list is empty",
            ));
        }
        let name_servers = build_name_servers(&addrs);
        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|err| io::Error::other(err.to_string()))?;
        let label = format_resolver_label(&addrs);
        info!("ACME DNS-01 resolver set to {}", label);
        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsTxtResolver for ExplicitDnsResolver {
    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        let response = self
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let mut values = Vec::new();
        for record in response.answers() {
            if let RData::TXT(txt) = &record.data {
                for data in &txt.txt_data {
                    if let Ok(text) = std::str::from_utf8(data) {
                        values.push(text.trim_matches('"').to_string());
                    }
                }
            }
        }
        Ok(values)
    }
}

struct AuthoritativeDnsResolver {
    bootstrap: TokioResolver,
    resolver: OnceCell<TokioResolver>,
}

impl AuthoritativeDnsResolver {
    fn new() -> io::Result<Self> {
        let bootstrap = TokioResolver::builder_tokio()
            .map_err(|err| io::Error::other(err.to_string()))?
            .build()
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Self {
            bootstrap,
            resolver: OnceCell::new(),
        })
    }

    async fn resolver_for(&self, name: &str) -> io::Result<&TokioResolver> {
        self.resolver
            .get_or_try_init(|| async {
                let (resolver, addrs, zone) =
                    build_authoritative_resolver(&self.bootstrap, name).await?;
                info!(
                    "ACME DNS-01 resolver set to authoritative servers for {} ({})",
                    zone,
                    format_resolver_label(&addrs)
                );
                Ok(resolver)
            })
            .await
    }
}

#[async_trait]
impl DnsTxtResolver for AuthoritativeDnsResolver {
    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        let resolver = self.resolver_for(name).await?;
        let response = resolver
            .txt_lookup(name)
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let mut values = Vec::new();
        for record in response.answers() {
            if let RData::TXT(txt) = &record.data {
                for data in &txt.txt_data {
                    if let Ok(text) = std::str::from_utf8(data) {
                        values.push(text.trim_matches('"').to_string());
                    }
                }
            }
        }
        Ok(values)
    }
}

struct DnsPropagation {
    resolver: Arc<dyn DnsTxtResolver>,
    label: String,
    propagation_check: bool,
    propagation_delay: StdDuration,
}

impl DnsPropagation {
    fn new(
        resolver: Arc<dyn DnsTxtResolver>,
        label: String,
        propagation_check: bool,
        propagation_delay: StdDuration,
    ) -> Self {
        Self {
            resolver,
            label,
            propagation_check,
            propagation_delay,
        }
    }

    async fn wait_for_propagation(&self, name: &str, expected: &str) -> io::Result<()> {
        if !self.propagation_check {
            return Ok(());
        }

        let attempts = 12;
        let interval = StdDuration::from_secs(5);
        let started = std::time::Instant::now();
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        let mut last_records: Vec<String> = Vec::new();
        let mut last_error: Option<String> = None;
        for attempt in 0..attempts {
            match self.resolver.lookup_txt(&fqdn).await {
                Ok(records) => {
                    if attempt == 0 {
                        info!(
                            "ACME DNS-01 propagation check started (name={}, attempts={}, interval={:?}, solver={})",
                            fqdn, attempts, interval, self.label
                        );
                    }
                    if !records.is_empty() {
                        log::debug!(
                            "ACME DNS-01 lookup attempt {}/{} (name={}, records={:?})",
                            attempt + 1,
                            attempts,
                            fqdn,
                            records
                        );
                    } else {
                        log::debug!(
                            "ACME DNS-01 lookup attempt {}/{} (name={}, records=[])",
                            attempt + 1,
                            attempts,
                            fqdn
                        );
                    }
                    last_records = records;
                    if last_records.iter().any(|value| value == expected) {
                        info!(
                            "ACME DNS-01 propagation confirmed after {:?} (name={}, solver={})",
                            started.elapsed(),
                            fqdn,
                            self.label
                        );
                        return Ok(());
                    }
                }
                Err(err) => {
                    if attempt == 0 {
                        info!(
                            "ACME DNS-01 propagation check started (name={}, attempts={}, interval={:?}, solver={})",
                            fqdn, attempts, interval, self.label
                        );
                    }
                    last_error = Some(err.to_string());
                    log::debug!(
                        "ACME DNS-01 lookup attempt {}/{} failed (name={}, error={})",
                        attempt + 1,
                        attempts,
                        fqdn,
                        err
                    );
                }
            }

            if attempt + 1 < attempts {
                tokio::time::sleep(interval).await;
            }
        }

        if let Some(err) = last_error {
            warn!(
                "ACME DNS-01 propagation failed after {:?} (name={}, last_error={})",
                started.elapsed(),
                fqdn,
                err
            );
        } else {
            warn!(
                "ACME DNS-01 propagation failed after {:?} (name={}, last_records={:?})",
                started.elapsed(),
                fqdn,
                last_records
            );
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("DNS-01 TXT record not propagated: {}", fqdn),
        ))
    }
}

struct CloudflareDnsProvider {
    client: Client,
    api_token: String,
    propagation: DnsPropagation,
    zone_cache: RwLock<HashMap<String, String>>,
    record_cache: RwLock<HashMap<String, String>>,
}

impl CloudflareDnsProvider {
    fn new(client: Client, api_token: String, propagation: DnsPropagation) -> Self {
        Self {
            client,
            api_token,
            propagation,
            zone_cache: RwLock::new(HashMap::new()),
            record_cache: RwLock::new(HashMap::new()),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_token)
    }

    async fn resolve_zone_id(&self, name: &str) -> io::Result<String> {
        let trimmed = name.trim_end_matches('.').to_string();
        let labels: Vec<&str> = trimmed.split('.').collect();
        for start in 1..labels.len() {
            let candidate = labels[start..].join(".");
            if let Some(id) = self.get_cached_zone(&candidate) {
                return Ok(id);
            }
            if let Some(id) = self.fetch_zone_id(&candidate).await? {
                self.cache_zone(&candidate, &id);
                return Ok(id);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Cloudflare zone not found for {}", name),
        ))
    }

    fn cache_zone(&self, zone: &str, id: &str) {
        match self.zone_cache.write() {
            Ok(mut guard) => {
                guard.insert(zone.to_string(), id.to_string());
            }
            Err(_) => {
                warn!("ACME DNS cache lock poisoned; zone cache write skipped");
            }
        }
    }

    fn get_cached_zone(&self, zone: &str) -> Option<String> {
        match self.zone_cache.read() {
            Ok(guard) => guard.get(zone).cloned(),
            Err(_) => {
                warn!("ACME DNS cache lock poisoned; zone cache lookup skipped");
                None
            }
        }
    }

    async fn fetch_zone_id(&self, zone: &str) -> io::Result<Option<String>> {
        #[derive(serde::Deserialize)]
        struct Zone {
            id: String,
        }

        #[derive(serde::Deserialize)]
        struct ZoneResponse {
            success: bool,
            result: Vec<Zone>,
            errors: Vec<CloudflareError>,
        }

        let response = self
            .client
            .get("https://api.cloudflare.com/client/v4/zones")
            .header("Authorization", self.auth_header())
            .query(&[("name", zone)])
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let payload: ZoneResponse = response
            .json()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        if !payload.success {
            return Err(io::Error::other(format_cloudflare_errors(&payload.errors)));
        }
        Ok(payload.result.first().map(|zone| zone.id.clone()))
    }

    fn record_cache_key(zone_id: &str, name: &str, value: &str) -> String {
        format!("{zone_id}|{name}|{value}")
    }

    fn cache_record(&self, zone_id: &str, name: &str, value: &str, record_id: &str) {
        match self.record_cache.write() {
            Ok(mut guard) => {
                guard.insert(
                    Self::record_cache_key(zone_id, name, value),
                    record_id.to_string(),
                );
            }
            Err(_) => {
                warn!("ACME DNS cache lock poisoned; record cache write skipped");
            }
        }
    }

    fn take_cached_record(&self, zone_id: &str, name: &str, value: &str) -> Option<String> {
        match self.record_cache.write() {
            Ok(mut guard) => guard.remove(&Self::record_cache_key(zone_id, name, value)),
            Err(_) => {
                warn!("ACME DNS cache lock poisoned; record cache lookup skipped");
                None
            }
        }
    }

    async fn create_record(&self, zone_id: &str, name: &str, value: &str) -> io::Result<String> {
        #[derive(serde::Serialize)]
        struct CreateDnsRecord<'a> {
            #[serde(rename = "type")]
            record_type: &'a str,
            name: &'a str,
            content: &'a str,
            ttl: u32,
        }

        #[derive(serde::Deserialize)]
        struct RecordResult {
            id: String,
        }

        #[derive(serde::Deserialize)]
        struct RecordResponse {
            success: bool,
            result: RecordResult,
            errors: Vec<CloudflareError>,
        }

        let response = self
            .client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .header("Authorization", self.auth_header())
            .json(&CreateDnsRecord {
                record_type: "TXT",
                name,
                content: value,
                ttl: 120,
            })
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let payload: RecordResponse = response
            .json()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        if !payload.success {
            return Err(io::Error::other(format_cloudflare_errors(&payload.errors)));
        }
        Ok(payload.result.id)
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> io::Result<()> {
        #[derive(serde::Deserialize)]
        struct DeleteResponse {
            success: bool,
            errors: Vec<CloudflareError>,
        }

        let response = self
            .client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let payload: DeleteResponse = response
            .json()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        if !payload.success {
            return Err(io::Error::other(format_cloudflare_errors(&payload.errors)));
        }
        Ok(())
    }

    async fn delete_record_by_lookup(
        &self,
        zone_id: &str,
        name: &str,
        value: &str,
    ) -> io::Result<()> {
        #[derive(serde::Deserialize)]
        struct Record {
            id: String,
        }

        #[derive(serde::Deserialize)]
        struct RecordResponse {
            success: bool,
            result: Vec<Record>,
            errors: Vec<CloudflareError>,
        }

        let response = self
            .client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .header("Authorization", self.auth_header())
            .query(&[("type", "TXT"), ("name", name), ("content", value)])
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        let payload: RecordResponse = response
            .json()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        if !payload.success {
            return Err(io::Error::other(format_cloudflare_errors(&payload.errors)));
        }
        if let Some(record) = payload.result.first() {
            self.delete_record(zone_id, &record.id).await?;
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
struct CloudflareError {
    code: Option<i64>,
    message: Option<String>,
}

fn format_cloudflare_errors(errors: &[CloudflareError]) -> String {
    if errors.is_empty() {
        return "Cloudflare API error".to_string();
    }
    errors
        .iter()
        .map(|err| {
            let code = err
                .code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let message = err.message.as_deref().unwrap_or("unknown error");
            format!("{}: {}", code, message)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn add_txt_record(
        &self,
        domain: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let zone_id = self.resolve_zone_id(domain).await?;
        let record_id = self.create_record(&zone_id, domain, value).await?;
        self.cache_record(&zone_id, domain, value, &record_id);

        if self.propagation.propagation_delay.as_secs() > 0 {
            info!(
                "ACME DNS-01 propagation delay started (duration={:?}, domain={}, solver={})",
                self.propagation.propagation_delay, domain, self.propagation.label
            );
            tokio::time::sleep(self.propagation.propagation_delay).await;
        }
        if let Err(err) = self.propagation.wait_for_propagation(domain, value).await {
            let _ = self.delete_record(&zone_id, &record_id).await;
            return Err(Box::new(err));
        }

        Ok(())
    }

    async fn remove_txt_record(
        &self,
        domain: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let zone_id = self.resolve_zone_id(domain).await?;
        if let Some(record_id) = self.take_cached_record(&zone_id, domain, value) {
            self.delete_record(&zone_id, &record_id).await?;
        } else {
            self.delete_record_by_lookup(&zone_id, domain, value)
                .await?;
        }
        Ok(())
    }
}

// Reserved for ACME test harness overrides.
pub enum AcmeProviderOverride {
    #[allow(dead_code)]
    Http01(Box<dyn Http01Provider>),
    #[allow(dead_code)]
    Dns01(Box<dyn DnsProvider>),
}

#[derive(Deserialize)]
struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Serialize, Deserialize)]
struct AcmeAccountPayload {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

#[derive(Clone)]
struct AcmeAccount {
    id: String,
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct AcmeOrderPayload {
    identifiers: Vec<AcmeIdentifier>,
}

#[derive(Serialize, Deserialize)]
struct AcmeIdentifier {
    #[serde(rename = "type")]
    type_: String,
    value: String,
}

#[derive(Deserialize)]
struct AcmeOrder {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct AcmeAuthorization {
    status: String,
    identifier: AcmeIdentifier,
    challenges: Vec<AcmeChallengeRecord>,
}

#[derive(Deserialize, Clone)]
struct AcmeChallengeRecord {
    #[serde(rename = "type")]
    type_: String,
    url: String,
    token: String,
}

struct AcmeCertResult {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

struct AcmeProviderSet {
    http01: Option<Box<dyn Http01Provider>>,
    dns: Option<Box<dyn DnsProvider>>,
}

struct ProvisionRequest<'a> {
    client: &'a Client,
    directory_url: &'a str,
    domains: &'a [String],
    contact_email: &'a str,
    challenge_type: ChallengeType,
    http01_provider: Option<&'a dyn Http01Provider>,
    dns_provider: Option<&'a dyn DnsProvider>,
    account_key_path: &'a Path,
}

async fn provision_certificate(
    request: ProvisionRequest<'_>,
) -> io::Result<(Vec<u8>, Vec<u8>, Option<String>)> {
    let directory = fetch_directory(request.client, request.directory_url).await?;
    let account_key = load_or_create_account_key(request.account_key_path)?;
    let account_id = register_account(
        request.client,
        &directory,
        &account_key,
        request.contact_email,
    )
    .await?;
    let account = AcmeAccount {
        id: account_id.clone(),
        key: account_key,
    };

    let order_url = create_order(request.client, &directory, &account, request.domains).await?;
    let order = fetch_order(request.client, &directory, &order_url, &account).await?;
    handle_challenge(
        request.client,
        &directory,
        &order,
        request.challenge_type,
        request.http01_provider,
        request.dns_provider,
        &account,
    )
    .await?;
    let cert = finalize_order(
        request.client,
        &directory,
        &order,
        &order_url,
        &account,
        request.domains,
    )
    .await?;
    Ok((cert.certificate, cert.private_key, Some(account_id)))
}

async fn fetch_directory(client: &Client, directory_url: &str) -> io::Result<AcmeDirectory> {
    let response = client
        .get(directory_url)
        .send()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
        .error_for_status()
        .map_err(|err| io::Error::other(err.to_string()))?;
    response
        .json::<AcmeDirectory>()
        .await
        .map_err(|err| io::Error::other(err.to_string()))
}

fn load_or_create_account_key(path: &Path) -> io::Result<Vec<u8>> {
    if path.exists() {
        return fs::read(path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key_pair = EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let key = key_pair.as_ref().to_vec();
    fs::write(path, &key)?;
    Ok(key)
}

async fn register_account(
    client: &Client,
    directory: &AcmeDirectory,
    key: &[u8],
    contact_email: &str,
) -> io::Result<String> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;

    let payload = AcmeAccountPayload {
        contact: vec![format!("mailto:{}", contact_email)],
        terms_of_service_agreed: true,
    };
    let response = post_jws_with_retry(client, directory, &directory.new_account, |nonce| {
        create_jws(&key_pair, &directory.new_account, None, nonce, &payload)
    })
    .await?;

    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| io::Error::other("Missing account location"))
}

async fn create_order(
    client: &Client,
    directory: &AcmeDirectory,
    account: &AcmeAccount,
    domains: &[String],
) -> io::Result<String> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &account.key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let payload = AcmeOrderPayload {
        identifiers: domains
            .iter()
            .map(|domain| AcmeIdentifier {
                type_: "dns".to_string(),
                value: domain.to_string(),
            })
            .collect(),
    };
    let response = post_jws_with_retry(client, directory, &directory.new_order, |nonce| {
        create_jws(
            &key_pair,
            &directory.new_order,
            Some(&account.id),
            nonce,
            &payload,
        )
    })
    .await?;
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| io::Error::other("Missing order URL"))
}

async fn fetch_order(
    client: &Client,
    directory: &AcmeDirectory,
    order_url: &str,
    account: &AcmeAccount,
) -> io::Result<AcmeOrder> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &account.key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let response = post_jws_with_retry(client, directory, order_url, |nonce| {
        create_jws_post_as_get(&key_pair, order_url, Some(&account.id), nonce)
    })
    .await?;
    response
        .json::<AcmeOrder>()
        .await
        .map_err(|err| io::Error::other(err.to_string()))
}

async fn finalize_order(
    client: &Client,
    directory: &AcmeDirectory,
    order: &AcmeOrder,
    order_url: &str,
    account: &AcmeAccount,
    domains: &[String],
) -> io::Result<AcmeCertResult> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &account.key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let (csr, private_key_pem) = generate_csr(domains)?;
    let payload = json!({ "csr": URL_SAFE_NO_PAD.encode(&csr) });
    let response = post_jws_with_retry(client, directory, &order.finalize, |nonce| {
        create_jws(
            &key_pair,
            &order.finalize,
            Some(&account.id),
            nonce,
            &payload,
        )
    })
    .await?;

    let mut current_order: AcmeOrder = response
        .json()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;
    if current_order.status != "valid" {
        for _ in 0..10 {
            tokio::time::sleep(StdDuration::from_secs(2)).await;
            current_order = fetch_order(client, directory, order_url, account).await?;
            if current_order.status == "valid" {
                break;
            }
            if current_order.status == "invalid" {
                return Err(io::Error::other("Order not valid"));
            }
        }
    }

    if current_order.status != "valid" {
        return Err(io::Error::other("Order not valid"));
    }

    if let Some(cert_url) = current_order.certificate.as_ref() {
        let response = post_jws_with_retry(client, directory, cert_url, |nonce| {
            create_jws_post_as_get(&key_pair, cert_url, Some(&account.id), nonce)
        })
        .await?;
        let cert = response
            .bytes()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(AcmeCertResult {
            certificate: cert.to_vec(),
            private_key: private_key_pem,
        })
    } else {
        Err(io::Error::other("Order not valid"))
    }
}

async fn handle_challenge(
    client: &Client,
    directory: &AcmeDirectory,
    order: &AcmeOrder,
    challenge_type: ChallengeType,
    http01_provider: Option<&dyn Http01Provider>,
    dns_provider: Option<&dyn DnsProvider>,
    account: &AcmeAccount,
) -> io::Result<()> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &account.key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let thumbprint = jwk_thumbprint(&key_pair)?;

    for auth_url in &order.authorizations {
        let mut auth = fetch_authorization(client, directory, auth_url, account).await?;
        let domain = auth.identifier.value.clone();
        let challenge = auth
            .challenges
            .iter()
            .find(|candidate| {
                candidate.type_
                    == match challenge_type {
                        ChallengeType::Http01 => "http-01",
                        ChallengeType::Dns01 => "dns-01",
                    }
            })
            .cloned()
            .ok_or_else(|| io::Error::other("Challenge not found"))?;

        let key_authorization = format!("{}.{}", challenge.token, thumbprint);
        let mut dns_cleanup: Option<(String, String)> = None;

        match challenge_type {
            ChallengeType::Http01 => {
                let provider = http01_provider
                    .ok_or_else(|| io::Error::other("HTTP-01 requires a provider"))?;
                provider
                    .present(&domain, &challenge.token, &key_authorization)
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?;

                let nonce = get_nonce(client, directory).await?;
                let jws = create_jws(
                    &key_pair,
                    &challenge.url,
                    Some(&account.id),
                    &nonce,
                    &json!({}),
                )?;
                client
                    .post(&challenge.url)
                    .header("Content-Type", "application/jose+json")
                    .body(jws)
                    .send()
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?
                    .error_for_status()
                    .map_err(|err| io::Error::other(err.to_string()))?;
            }
            ChallengeType::Dns01 => {
                let provider = dns_provider
                    .ok_or_else(|| io::Error::other("DNS-01 requires a DNS provider"))?;
                let txt_value = dns01_txt_value(&key_authorization);
                let name = format!("_acme-challenge.{domain}");
                provider
                    .add_txt_record(&name, &txt_value)
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?;

                let nonce = get_nonce(client, directory).await?;
                let jws = create_jws(
                    &key_pair,
                    &challenge.url,
                    Some(&account.id),
                    &nonce,
                    &json!({}),
                )?;
                client
                    .post(&challenge.url)
                    .header("Content-Type", "application/jose+json")
                    .body(jws)
                    .send()
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?
                    .error_for_status()
                    .map_err(|err| io::Error::other(err.to_string()))?;

                dns_cleanup = Some((name, txt_value));
            }
        }

        for _ in 0..10 {
            auth = fetch_authorization(client, directory, auth_url, account).await?;
            if auth.status == "valid" {
                break;
            }
            if auth.status == "invalid" {
                if let Some((name, txt_value)) = dns_cleanup.take()
                    && let Some(provider) = dns_provider
                {
                    provider
                        .remove_txt_record(&name, &txt_value)
                        .await
                        .map_err(|err| io::Error::other(err.to_string()))?;
                }
                return Err(io::Error::other("Challenge validation failed"));
            }
            tokio::time::sleep(StdDuration::from_secs(2)).await;
        }

        if challenge_type == ChallengeType::Http01
            && let Some(provider) = http01_provider
        {
            provider
                .cleanup(&challenge.token)
                .await
                .map_err(|err| io::Error::other(err.to_string()))?;
        }

        if let Some((name, txt_value)) = dns_cleanup
            && let Some(provider) = dns_provider
        {
            provider
                .remove_txt_record(&name, &txt_value)
                .await
                .map_err(|err| io::Error::other(err.to_string()))?;
        }
    }

    Ok(())
}

async fn fetch_authorization(
    client: &Client,
    directory: &AcmeDirectory,
    auth_url: &str,
    account: &AcmeAccount,
) -> io::Result<AcmeAuthorization> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &account.key,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let response = post_jws_with_retry(client, directory, auth_url, |nonce| {
        create_jws_post_as_get(&key_pair, auth_url, Some(&account.id), nonce)
    })
    .await?;
    response
        .json::<AcmeAuthorization>()
        .await
        .map_err(|err| io::Error::other(err.to_string()))
}

async fn get_nonce(client: &Client, directory: &AcmeDirectory) -> io::Result<String> {
    let response = client
        .head(&directory.new_nonce)
        .send()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;
    response
        .headers()
        .get("replay-nonce")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| io::Error::other("Missing nonce"))
}

fn create_jws<T: Serialize>(
    key_pair: &EcdsaKeyPair,
    url: &str,
    kid: Option<&str>,
    nonce: &str,
    payload: &T,
) -> io::Result<String> {
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(payload).map_err(|err| io::Error::other(err.to_string()))?);
    let mut protected = serde_json::Map::new();
    protected.insert("alg".to_string(), json!("ES256"));
    protected.insert("nonce".to_string(), json!(nonce));
    protected.insert("url".to_string(), json!(url));
    if let Some(kid) = kid {
        protected.insert("kid".to_string(), json!(kid));
    } else {
        protected.insert("jwk".to_string(), jwk_from_key_pair(key_pair));
    }
    let protected_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&protected).map_err(|err| io::Error::other(err.to_string()))?);
    let input = format!("{}.{}", protected_b64, payload_b64);
    let signature = key_pair
        .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
        .map_err(|err| io::Error::other(format!("ring sign error: {err:?}")))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());
    serde_json::to_string(&json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }))
    .map_err(|err| io::Error::other(err.to_string()))
}

fn create_jws_post_as_get(
    key_pair: &EcdsaKeyPair,
    url: &str,
    kid: Option<&str>,
    nonce: &str,
) -> io::Result<String> {
    let payload_b64 = "";
    let mut protected = serde_json::Map::new();
    protected.insert("alg".to_string(), json!("ES256"));
    protected.insert("nonce".to_string(), json!(nonce));
    protected.insert("url".to_string(), json!(url));
    if let Some(kid) = kid {
        protected.insert("kid".to_string(), json!(kid));
    } else {
        protected.insert("jwk".to_string(), jwk_from_key_pair(key_pair));
    }
    let protected_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&protected).map_err(|err| io::Error::other(err.to_string()))?);
    let input = format!("{}.{}", protected_b64, payload_b64);
    let signature = key_pair
        .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
        .map_err(|err| io::Error::other(format!("ring sign error: {err:?}")))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());
    serde_json::to_string(&json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }))
    .map_err(|err| io::Error::other(err.to_string()))
}

async fn post_jws_with_retry<F>(
    client: &Client,
    directory: &AcmeDirectory,
    url: &str,
    build_jws: F,
) -> io::Result<reqwest::Response>
where
    F: Fn(&str) -> io::Result<String>,
{
    for attempt in 0..2 {
        let nonce = get_nonce(client, directory).await?;
        let jws = build_jws(&nonce)?;
        let response = client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;

        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "ACME request failed".to_string());
        if status == StatusCode::BAD_REQUEST && body.contains("badNonce") && attempt == 0 {
            continue;
        }
        return Err(io::Error::other(body));
    }

    Err(io::Error::other("ACME nonce retry exhausted"))
}

fn jwk_from_key_pair(key_pair: &EcdsaKeyPair) -> serde_json::Value {
    let (x, y) = key_pair.public_key().as_ref()[1..].split_at(32);
    json!({
        "crv": "P-256",
        "kty": "EC",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    })
}

fn jwk_thumbprint(key_pair: &EcdsaKeyPair) -> io::Result<String> {
    let jwk_json = serde_json::to_string(&jwk_from_key_pair(key_pair))
        .map_err(|err| io::Error::other(err.to_string()))?;
    let digest = Sha256::digest(jwk_json.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn dns01_txt_value(key_authorization: &str) -> String {
    let digest = Sha256::digest(key_authorization.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn generate_csr(domains: &[String]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};

    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|err| io::Error::other(err.to_string()))?;
    params.distinguished_name = rcgen::DistinguishedName::new();

    let key_pair = RcgenKeyPair::generate().map_err(|err| io::Error::other(err.to_string()))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|err| io::Error::other(err.to_string()))?
        .der()
        .as_ref()
        .to_vec();
    let private_key_pem = key_pair.serialize_pem().into_bytes();

    Ok((csr, private_key_pem))
}

pub async fn ensure_acme_certificate(
    runtime_paths: &RuntimePaths,
    config: &ValidatedConfig,
    token_store: Option<AcmeTokenStore>,
    provider_override: Option<AcmeProviderOverride>,
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

    let fingerprint = tls_config_fingerprint(tls)?;
    let state = match read_tls_state(runtime_paths) {
        Ok(state) => state,
        Err(err) => {
            warn!("TLS state invalid; forcing ACME issuance: {}", err);
            None
        }
    };
    let state_matches = state
        .as_ref()
        .map(|state| {
            state.mode == TlsMode::Acme
                && state.config_fingerprint == fingerprint
                && state.acme.is_some()
        })
        .unwrap_or(false);

    let mut status = cert_status(&cert_path, &key_path)?;
    if matches!(status, CertStatus::Valid | CertStatus::ExpiringSoon)
        && validate_private_key(&key_path).is_err()
    {
        status = CertStatus::Invalid;
    }

    let domains_match = if matches!(status, CertStatus::Valid | CertStatus::ExpiringSoon) {
        cert_covers_domains(&cert_path, &tls.domains).unwrap_or(false)
    } else {
        false
    };

    let must_issue = matches!(
        status,
        CertStatus::Missing | CertStatus::Expired | CertStatus::Invalid
    ) || !state_matches
        || !domains_match;
    let should_issue = matches!(status, CertStatus::ExpiringSoon) && state_matches && domains_match;

    if !must_issue && !should_issue {
        return Ok(false);
    }

    let mut reasons = Vec::new();
    match status {
        CertStatus::Missing => reasons.push("cert_missing"),
        CertStatus::Expired => reasons.push("cert_expired"),
        CertStatus::Invalid => reasons.push("cert_invalid"),
        CertStatus::ExpiringSoon => reasons.push("cert_expiring_soon"),
        CertStatus::Valid => {}
    }
    if !state_matches {
        reasons.push("state_mismatch");
    }
    if !domains_match {
        reasons.push("domains_mismatch");
    }
    info!(
        "ACME issuance decision (must_issue={}, should_issue={}, reasons={:?}, domains={})",
        must_issue,
        should_issue,
        reasons,
        tls.domains.join(", ")
    );

    let result = issue_certificate(runtime_paths, tls, acme, token_store, provider_override).await;

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
    tls: &nop_config::TlsConfig,
    acme: &AcmeConfig,
    token_store: Option<AcmeTokenStore>,
    provider_override: Option<AcmeProviderOverride>,
) -> io::Result<()> {
    let client = build_client(acme)?;
    let tls_dir = runtime_paths.state_sys_dir.join("tls");
    fs::create_dir_all(&tls_dir)?;
    let account_key_path = tls_dir.join("account.key");
    let directory_url = resolve_directory_url(acme);

    info!(
        "ACME issuance starting (challenge={:?}, domains={}, directory_url={})",
        acme.challenge,
        tls.domains.join(", "),
        directory_url
    );

    let challenge = match acme.challenge {
        AcmeChallenge::Http01 => ChallengeType::Http01,
        AcmeChallenge::Dns01 => ChallengeType::Dns01,
    };

    let providers = match acme.challenge {
        AcmeChallenge::Http01 => {
            let provider: Box<dyn Http01Provider> = match provider_override {
                Some(AcmeProviderOverride::Http01(provider)) => provider,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ACME provider override does not match http-01 challenge",
                    ));
                }
                None => {
                    let store = token_store.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "ACME http-01 requires a token store",
                        )
                    })?;
                    Box::new(AcmeHttp01Provider::new(store))
                }
            };
            AcmeProviderSet {
                http01: Some(provider),
                dns: None,
            }
        }
        AcmeChallenge::Dns01 => {
            let provider: Box<dyn DnsProvider> = match provider_override {
                Some(AcmeProviderOverride::Dns01(provider)) => provider,
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ACME provider override does not match dns-01 challenge",
                    ));
                }
                None => build_dns_provider(acme)?,
            };
            AcmeProviderSet {
                http01: None,
                dns: Some(provider),
            }
        }
    };

    let request = ProvisionRequest {
        client: &client,
        directory_url: &directory_url,
        domains: &tls.domains,
        contact_email: &acme.contact_email,
        challenge_type: challenge,
        http01_provider: providers.http01.as_deref(),
        dns_provider: providers.dns.as_deref(),
        account_key_path: &account_key_path,
    };
    let (cert_pem, key_pem, account_id) = provision_certificate(request).await?;

    let acme_state = TlsAcmeState {
        directory_url,
        contact_email: acme.contact_email.clone(),
        account_id,
    };

    fs::write(tls_dir.join("cert.pem"), cert_pem)?;
    fs::write(tls_dir.join("key.pem"), key_pem)?;
    fs::write(
        tls_dir.join("last-renewed.txt"),
        OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
    )?;

    let state = build_tls_state(tls, OffsetDateTime::now_utc(), Some(acme_state))?;
    write_tls_state(runtime_paths, &state)?;

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

fn build_cloudflare_client() -> io::Result<Client> {
    Client::builder()
        .user_agent("nopressure-acme")
        .build()
        .map_err(|err| io::Error::other(err.to_string()))
}

fn build_dns_provider(acme: &AcmeConfig) -> io::Result<Box<dyn DnsProvider>> {
    let dns = acme.dns.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME DNS-01 requires dns configuration",
        )
    })?;

    let provider = dns.provider.trim().to_lowercase();
    info!("ACME DNS-01 provider configured (provider={})", provider);
    if provider != "cloudflare" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported DNS-01 provider: {}", dns.provider),
        ));
    }

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

    let resolver: Arc<dyn DnsTxtResolver> = if dns.resolver.is_empty() {
        Arc::new(AuthoritativeDnsResolver::new()?)
    } else {
        Arc::new(ExplicitDnsResolver::new(dns)?)
    };
    let propagation_delay = StdDuration::from_secs(dns.propagation_delay_seconds);
    let solver_label = format!("dns-01:{provider}");
    info!(
        "ACME DNS-01 propagation configured (check_enabled={}, delay={:?}, solver={})",
        dns.propagation_check, propagation_delay, solver_label
    );
    let client = build_cloudflare_client()?;
    let propagation = DnsPropagation::new(
        resolver,
        solver_label,
        dns.propagation_check,
        propagation_delay,
    );
    Ok(Box::new(CloudflareDnsProvider::new(
        client,
        token,
        propagation,
    )))
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

fn resolve_directory_url(acme: &AcmeConfig) -> String {
    if let Some(url) = &acme.directory_url {
        return url.clone();
    }

    match acme.environment {
        AcmeEnvironment::Production => "https://acme-v02.api.letsencrypt.org/directory".to_string(),
        AcmeEnvironment::Staging => {
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use nop_config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig,
    };
    use nop_testing::test_fixtures::TestFixtureRoot;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fs;
    use std::future::Future;
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, OnceLock, mpsc};
    use std::thread;
    use std::time::{Duration as StdDuration, Instant};
    use tokio::sync::Semaphore;
    use tokio::time::sleep;

    #[tokio::test]
    async fn http01_solver_stores_and_cleans() {
        let store = AcmeTokenStore::new();
        let provider = AcmeHttp01Provider::new(store.clone());

        provider
            .present("example.com", "token", "authz")
            .await
            .expect("present should succeed");
        assert_eq!(
            store.get_key_authorization("token"),
            Some("authz".to_string())
        );

        provider
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

    #[tokio::test]
    async fn dns_propagation_waits_for_txt() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct StubResolver {
            calls: AtomicUsize,
            expected: String,
        }

        #[async_trait]
        impl DnsTxtResolver for StubResolver {
            async fn lookup_txt(&self, _name: &str) -> io::Result<Vec<String>> {
                let count = self.calls.fetch_add(1, Ordering::SeqCst);
                if count >= 1 {
                    Ok(vec![self.expected.clone()])
                } else {
                    Ok(Vec::new())
                }
            }
        }

        let resolver = Arc::new(StubResolver {
            calls: AtomicUsize::new(0),
            expected: "token".to_string(),
        });
        let propagation = DnsPropagation::new(
            resolver,
            "test".to_string(),
            true,
            StdDuration::from_secs(0),
        );
        let result = propagation
            .wait_for_propagation("_acme-challenge.example.com", "token")
            .await;
        assert!(result.is_ok(), "expected propagation wait to succeed");
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
        mut provider_override: F,
    ) -> bool
    where
        F: FnMut() -> AcmeProviderOverride,
    {
        let mut last_error = None;

        for attempt in 1..=3 {
            match ensure_acme_certificate(runtime_paths, config, None, Some(provider_override()))
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
            let provider = PebbleHttp01Provider::new("http://127.0.0.1:8055");
            let issued = ensure_acme_with_retry(&runtime_paths, &config, || {
                AcmeProviderOverride::Http01(Box::new(provider.clone()))
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
            let provider = PebbleDns01Provider::new("http://127.0.0.1:8055");
            let issued = ensure_acme_with_retry(&runtime_paths, &config, || {
                AcmeProviderOverride::Dns01(Box::new(provider.clone()))
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
        let dns = if challenge == AcmeChallenge::Dns01 {
            Some(AcmeDnsConfig {
                provider: "cloudflare".to_string(),
                api_token: Some("token".to_string()),
                resolver: Vec::new(),
                propagation_check: false,
                propagation_delay_seconds: 0,
            })
        } else {
            None
        };

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
            users: nop_config::ValidatedUsersConfig::Local(nop_config::ValidatedLocalAuthConfig {
                jwt: nop_config::JwtConfig {
                    secret: "test-secret".to_string(),
                    issuer: "nopressure".to_string(),
                    audience: "nopressure-users".to_string(),
                    expiration_hours: 12,
                    cookie_name: "nop_auth".to_string(),
                    force_secure_cookie: false,
                    disable_refresh: false,
                    refresh_threshold_percentage: 10,
                    refresh_threshold_hours: 24,
                },
                password: nop_config::PasswordHashingParams::default(),
                password_complexity_enabled: true,
            }),
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
                login_sessions: nop_config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: Some(nop_config::TlsConfig {
                mode: nop_config::TlsMode::Acme,
                domains: vec!["example.com".to_string()],
                redirect_base_url: None,
                acme: Some(AcmeConfig {
                    environment: AcmeEnvironment::Staging,
                    directory_url: Some("https://localhost:14000/dir".to_string()),
                    insecure_skip_verify: true,
                    contact_email: "admin@example.com".to_string(),
                    challenge,
                    dns,
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
            search: nop_config::SearchConfig::default(),
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
    struct PebbleHttp01Provider {
        client: Client,
        api_base: String,
        tokens: TestTokenStore,
    }

    impl PebbleHttp01Provider {
        fn new(api_base: &str) -> Self {
            Self {
                client: Client::new(),
                api_base: api_base.to_string(),
                tokens: TestTokenStore::new(),
            }
        }
    }

    #[derive(Clone)]
    struct PebbleDns01Provider {
        client: Client,
        api_base: String,
        tokens: TestTokenStore,
    }

    impl PebbleDns01Provider {
        fn new(api_base: &str) -> Self {
            Self {
                client: Client::new(),
                api_base: api_base.to_string(),
                tokens: TestTokenStore::new(),
            }
        }
    }

    #[async_trait]
    impl Http01Provider for PebbleHttp01Provider {
        async fn present(
            &self,
            domain: &str,
            token: &str,
            key_authorization: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let addresses = ["10.30.50.3"];
            post_json(
                &self.client,
                &format!("{}/add-a", self.api_base),
                &DnsRequest {
                    host: domain,
                    addresses: Some(&addresses),
                },
            )
            .await?;

            post_json(
                &self.client,
                &format!("{}/add-http01", self.api_base),
                &Http01Request {
                    token,
                    content: Some(key_authorization),
                },
            )
            .await?;

            self.tokens.insert(token.to_string(), domain.to_string());

            Ok(())
        }

        async fn cleanup(&self, token: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    impl DnsProvider for PebbleDns01Provider {
        async fn add_txt_record(
            &self,
            domain: &str,
            value: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let host = format!("{domain}.");
            post_json(
                &self.client,
                &format!("{}/set-txt", self.api_base),
                &DnsTxtRequest { host: &host, value },
            )
            .await?;

            self.tokens.insert(domain.to_string(), host);

            Ok(())
        }

        async fn remove_txt_record(
            &self,
            domain: &str,
            _value: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let host = self.tokens.take(domain);
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
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        manifest_dir
            .ancestors()
            .find(|path| path.join("scripts").join("acme-pebble.sh").is_file())
            .expect("repo root with ACME harness script")
            .to_path_buf()
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
