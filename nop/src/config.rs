// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::warn;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    LoadError(String),
    ValidationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::LoadError(msg) => write!(f, "Configuration load error: {}", msg),
            ConfigError::ValidationError(msg) => {
                write!(f, "Configuration validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DevMode {
    Localhost,
    Dangerous,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UploadConfig {
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64, // 0 means unlimited
    #[serde(default = "default_allowed_extensions")]
    pub allowed_extensions: Vec<String>,
}

fn default_max_file_size_mb() -> u64 {
    100 // 100MB default limit
}

fn default_allowed_extensions() -> Vec<String> {
    vec![
        // Images
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "webp".to_string(),
        "svg".to_string(),
        "bmp".to_string(),
        "ico".to_string(),
        // Documents
        "pdf".to_string(),
        "doc".to_string(),
        "docx".to_string(),
        "txt".to_string(),
        "rtf".to_string(),
        "odt".to_string(),
        // Spreadsheets
        "xls".to_string(),
        "xlsx".to_string(),
        "csv".to_string(),
        "ods".to_string(),
        // Presentations
        "ppt".to_string(),
        "pptx".to_string(),
        "odp".to_string(),
        // Archives
        "zip".to_string(),
        "rar".to_string(),
        "7z".to_string(),
        "tar".to_string(),
        "gz".to_string(),
        // Video
        "mp4".to_string(),
        "avi".to_string(),
        "mov".to_string(),
        "wmv".to_string(),
        "flv".to_string(),
        "webm".to_string(),
        "mkv".to_string(),
        "m4v".to_string(),
        // Audio
        "mp3".to_string(),
        "wav".to_string(),
        "flac".to_string(),
        "aac".to_string(),
        "ogg".to_string(),
        "wma".to_string(),
        "m4a".to_string(),
        // Web files
        "html".to_string(),
        "css".to_string(),
        "js".to_string(),
        "json".to_string(),
        "xml".to_string(),
        // Markdown (will be renamed to .markdown)
        "md".to_string(),
        "markdown".to_string(),
        // Other common files
        "log".to_string(),
        "conf".to_string(),
        "cfg".to_string(),
    ]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StreamingConfig {
    #[serde(default = "default_streaming_enabled")]
    pub enabled: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: default_streaming_enabled(),
        }
    }
}

fn default_streaming_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ShortcodeConfig {
    #[serde(default = "default_start_unibox_search_url")]
    pub start_unibox: String,
}

impl Default for ShortcodeConfig {
    fn default() -> Self {
        Self {
            start_unibox: default_start_unibox_search_url(),
        }
    }
}

fn default_start_unibox_search_url() -> String {
    "https://duckduckgo.com?q=<QUERY>".to_string()
}

fn default_short_paragraph_length() -> usize {
    256
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RenderingConfig {
    #[serde(default = "default_short_paragraph_length")]
    pub short_paragraph_length: usize,
}

impl Default for RenderingConfig {
    fn default() -> Self {
        Self {
            short_paragraph_length: default_short_paragraph_length(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub admin: AdminConfig,
    pub users: UsersConfig,
    pub navigation: NavigationConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub tls: Option<TlsConfig>,
    pub app: AppConfig,
    #[allow(dead_code)]
    pub upload: UploadConfig,
    #[serde(default)]
    pub streaming: StreamingConfig,
    #[serde(default)]
    pub shortcodes: ShortcodeConfig,
    #[serde(default)]
    pub rendering: RenderingConfig,
    pub dev_mode: Option<DevMode>,
}

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub servers: Vec<ServerListenerConfig>,
    pub server: ServerConfig,
    pub admin: AdminConfig,
    pub users: ValidatedUsersConfig,
    #[allow(dead_code)]
    pub navigation: NavigationConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub tls: Option<TlsConfig>,
    pub app: AppConfig,
    #[allow(dead_code)]
    pub upload: UploadConfig,
    pub streaming: StreamingConfig,
    pub shortcodes: ShortcodeConfig,
    pub rendering: RenderingConfig,
    pub dev_mode: Option<DevMode>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerRole {
    Main,
    WellKnown,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ServerProtocol {
    Http,
    Https,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerListenerConfig {
    pub name: Option<String>,
    pub role: ServerRole,
    pub host: String,
    pub port: u16,
    pub protocol: ServerProtocol,
}

impl ServerListenerConfig {
    fn main_http(host: &str, port: u16) -> Self {
        Self {
            name: Some("main-http".to_string()),
            role: ServerRole::Main,
            host: host.to_string(),
            port,
            protocol: ServerProtocol::Http,
        }
    }

    fn main_https(host: &str, port: u16) -> Self {
        Self {
            name: Some("main-https".to_string()),
            role: ServerRole::Main,
            host: host.to_string(),
            port,
            protocol: ServerProtocol::Https,
        }
    }

    fn well_known_http(host: &str, port: u16) -> Self {
        Self {
            name: Some("well-known-http".to_string()),
            role: ServerRole::WellKnown,
            host: host.to_string(),
            port,
            protocol: ServerProtocol::Http,
        }
    }

    pub fn address_tuple(&self) -> (&str, u16) {
        (self.host.as_str(), self.port)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_port: Option<u16>,
    #[serde(default = "default_workers")]
    pub workers: usize,
}

fn default_workers() -> usize {
    4
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdminConfig {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NavigationConfig {
    #[serde(default = "default_max_dropdown_items")]
    pub max_dropdown_items: usize,
}

fn default_max_dropdown_items() -> usize {
    7
}

fn default_log_rotation_max_size_mb() -> u64 {
    16
}

fn default_log_rotation_max_files() -> u32 {
    10
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingRotationConfig {
    #[serde(default = "default_log_rotation_max_size_mb")]
    pub max_size_mb: u64,
    #[serde(default = "default_log_rotation_max_files")]
    pub max_files: u32,
}

impl Default for LoggingRotationConfig {
    fn default() -> Self {
        Self {
            max_size_mb: default_log_rotation_max_size_mb(),
            max_files: default_log_rotation_max_files(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    #[serde(default)]
    pub rotation: LoggingRotationConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_max_violations")]
    pub max_violations: u32,
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_use_forwarded_for")]
    pub use_forwarded_for: bool,
    #[serde(default)]
    pub login_sessions: LoginSessionConfig,
    #[serde(default = "default_hsts_enabled")]
    pub hsts_enabled: bool,
    #[serde(default = "default_hsts_max_age")]
    pub hsts_max_age: u64,
    #[serde(default = "default_hsts_include_subdomains")]
    pub hsts_include_subdomains: bool,
    #[serde(default = "default_hsts_preload")]
    pub hsts_preload: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoginSessionConfig {
    #[serde(default = "default_login_sessions_period_seconds")]
    pub period_seconds: u64,
    #[serde(default = "default_login_sessions_id_requests")]
    pub id_requests: u32,
    #[serde(default = "default_login_sessions_lockout_seconds")]
    pub lockout_seconds: u64,
}

impl Default for LoginSessionConfig {
    fn default() -> Self {
        LoginSessionConfig {
            period_seconds: default_login_sessions_period_seconds(),
            id_requests: default_login_sessions_id_requests(),
            lockout_seconds: default_login_sessions_lockout_seconds(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    SelfSigned,
    UserProvided,
    Acme,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub mode: TlsMode,
    #[serde(default)]
    pub domains: Vec<String>,
    pub redirect_base_url: Option<String>,
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeChallenge {
    Http01,
    Dns01,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AcmeEnvironment {
    Production,
    Staging,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeConfig {
    #[serde(default = "default_acme_provider")]
    pub provider: String,
    #[serde(default = "default_acme_environment")]
    pub environment: AcmeEnvironment,
    pub directory_url: Option<String>,
    #[serde(default = "default_acme_insecure_skip_verify")]
    pub insecure_skip_verify: bool,
    pub contact_email: String,
    pub challenge: AcmeChallenge,
    pub dns: Option<AcmeDnsConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeDnsConfig {
    pub provider: String,
    pub api_token: Option<String>,
    pub exec: Option<AcmeDnsExecConfig>,
    #[serde(default, deserialize_with = "deserialize_resolver_vec")]
    pub resolver: Vec<String>,
    #[serde(default = "default_acme_dns_propagation_check")]
    pub propagation_check: bool,
    #[serde(default = "default_acme_dns_propagation_delay_seconds")]
    pub propagation_delay_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeDnsExecConfig {
    pub present_command: String,
    pub cleanup_command: String,
}

fn deserialize_resolver_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ResolverVisitor;

    impl<'de> Visitor<'de> for ResolverVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(ResolverVisitor)
}

fn default_acme_provider() -> String {
    "lers".to_string()
}

fn default_acme_environment() -> AcmeEnvironment {
    AcmeEnvironment::Production
}

fn default_acme_insecure_skip_verify() -> bool {
    false
}

fn default_acme_dns_propagation_check() -> bool {
    false
}

fn default_acme_dns_propagation_delay_seconds() -> u64 {
    30
}

fn parse_dns_resolver_addr(value: &str) -> Option<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr);
    }
    value
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 53))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LocalAuthConfig {
    pub jwt: JwtConfig,
    #[serde(default)]
    pub password: PasswordHashingConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PasswordHashingConfig {
    #[serde(default)]
    pub front_end: Argon2ParamsConfig,
    #[serde(default)]
    pub back_end: Argon2ParamsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Argon2ParamsConfig {
    #[serde(default)]
    pub memory_kib: Option<u32>,
    #[serde(default)]
    pub iterations: Option<u32>,
    #[serde(default)]
    pub parallelism: Option<u32>,
    #[serde(default)]
    pub output_len: Option<u32>,
    #[serde(default)]
    pub salt_len: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
    #[serde(default = "default_jwt_expiration_hours")]
    pub expiration_hours: u64,
    #[serde(default = "default_jwt_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_jwt_disable_refresh")]
    pub disable_refresh: bool,
    #[serde(default = "default_jwt_refresh_threshold_percentage")]
    pub refresh_threshold_percentage: u32,
    #[serde(default = "default_jwt_refresh_threshold_hours")]
    pub refresh_threshold_hours: u64,
}

fn default_max_violations() -> u32 {
    2
}

fn default_cooldown_seconds() -> u64 {
    30
}

fn default_use_forwarded_for() -> bool {
    false
}

fn default_login_sessions_period_seconds() -> u64 {
    300
}

fn default_login_sessions_id_requests() -> u32 {
    5
}

fn default_login_sessions_lockout_seconds() -> u64 {
    600
}

fn default_hsts_enabled() -> bool {
    false // Default HSTS to disabled for local testing
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year in seconds
}

fn default_hsts_include_subdomains() -> bool {
    true
}

fn default_hsts_preload() -> bool {
    false
}

fn default_jwt_issuer() -> String {
    "nopressure".to_string()
}

fn default_jwt_audience() -> String {
    "nopressure-users".to_string()
}

fn default_jwt_expiration_hours() -> u64 {
    12
}

fn default_jwt_cookie_name() -> String {
    "nop_auth".to_string()
}

fn default_jwt_disable_refresh() -> bool {
    false
}

fn default_jwt_refresh_threshold_percentage() -> u32 {
    10
}

fn default_jwt_refresh_threshold_hours() -> u64 {
    24
}

pub const DEFAULT_ARGON2_FRONT_END_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 65536,
    iterations: 2,
    parallelism: 1,
    output_len: 32,
    salt_len: 16,
};

pub const DEFAULT_ARGON2_BACK_END_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 131072,
    iterations: 3,
    parallelism: 2,
    output_len: 32,
    salt_len: 16,
};

fn default_argon2_front_end_params() -> Argon2Params {
    DEFAULT_ARGON2_FRONT_END_PARAMS
}

fn default_argon2_back_end_params() -> Argon2Params {
    DEFAULT_ARGON2_BACK_END_PARAMS
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UsersConfig {
    pub auth_method: AuthMethod,
    pub local: Option<LocalAuthConfig>,
    pub oidc: Option<OidcConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Local,
    Oidc,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcConfig {
    pub server_url: String,
    pub realm: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    #[serde(default = "default_oidc_scope")]
    pub scope: String,
    #[serde(default = "default_verify_ssl")]
    pub verify_ssl: bool,
}

fn default_oidc_scope() -> String {
    "openid email profile".to_string()
}

fn default_verify_ssl() -> bool {
    true
}

#[derive(Debug, Clone)]
pub enum ValidatedUsersConfig {
    Local(ValidatedLocalAuthConfig),
    Oidc(OidcConfig),
}

impl ValidatedUsersConfig {
    pub fn local(&self) -> Option<&ValidatedLocalAuthConfig> {
        match self {
            ValidatedUsersConfig::Local(local) => Some(local),
            ValidatedUsersConfig::Oidc(_) => None,
        }
    }

    #[allow(dead_code)]
    pub fn oidc(&self) -> Option<&OidcConfig> {
        match self {
            ValidatedUsersConfig::Local(_) => None,
            ValidatedUsersConfig::Oidc(oidc) => Some(oidc),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedLocalAuthConfig {
    pub jwt: JwtConfig,
    pub password: PasswordHashingParams,
}

#[derive(Debug, Clone)]
pub struct PasswordHashingParams {
    pub front_end: Argon2Params,
    pub back_end: Argon2Params,
}

impl Default for PasswordHashingParams {
    fn default() -> Self {
        PasswordHashingParams {
            front_end: default_argon2_front_end_params(),
            back_end: default_argon2_back_end_params(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: u32,
    pub salt_len: u32,
}

impl Argon2Params {
    fn resolve(
        label: &str,
        config: &Argon2ParamsConfig,
        defaults: Argon2Params,
    ) -> Result<Self, ConfigError> {
        let resolved = Argon2Params {
            memory_kib: config.memory_kib.unwrap_or(defaults.memory_kib),
            iterations: config.iterations.unwrap_or(defaults.iterations),
            parallelism: config.parallelism.unwrap_or(defaults.parallelism),
            output_len: config.output_len.unwrap_or(defaults.output_len),
            salt_len: config.salt_len.unwrap_or(defaults.salt_len),
        };

        if resolved.memory_kib == 0
            || resolved.iterations == 0
            || resolved.parallelism == 0
            || resolved.output_len == 0
            || resolved.salt_len == 0
        {
            return Err(ConfigError::ValidationError(format!(
                "Argon2id params for {} must be non-zero",
                label
            )));
        }

        if resolved.salt_len < 8 {
            return Err(ConfigError::ValidationError(format!(
                "Argon2id salt_len for {} must be at least 8 bytes, got {}",
                label, resolved.salt_len
            )));
        }

        let output_len = usize::try_from(resolved.output_len).map_err(|_| {
            ConfigError::ValidationError(format!(
                "Argon2id output_len for {} is too large: {}",
                label, resolved.output_len
            ))
        })?;

        if let Err(err) = argon2::Params::new(
            resolved.memory_kib,
            resolved.iterations,
            resolved.parallelism,
            Some(output_len),
        ) {
            return Err(ConfigError::ValidationError(format!(
                "Invalid Argon2id params for {}: {}",
                label, err
            )));
        }

        Ok(resolved)
    }
}

#[cfg(test)]
pub fn test_local_users_config() -> ValidatedUsersConfig {
    ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
        jwt: JwtConfig {
            secret: "test-secret".to_string(),
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            expiration_hours: default_jwt_expiration_hours(),
            cookie_name: default_jwt_cookie_name(),
            disable_refresh: default_jwt_disable_refresh(),
            refresh_threshold_percentage: default_jwt_refresh_threshold_percentage(),
            refresh_threshold_hours: default_jwt_refresh_threshold_hours(),
        },
        password: PasswordHashingParams {
            front_end: default_argon2_front_end_params(),
            back_end: default_argon2_back_end_params(),
        },
    })
}

impl Config {
    pub fn load(root: &Path) -> Result<Self, ConfigError> {
        let config_path = root.join("config.yaml");
        let config_content = fs::read_to_string(&config_path).map_err(|e| {
            ConfigError::LoadError(format!(
                "Failed to read config file '{}': {}",
                config_path.display(),
                e
            ))
        })?;
        let raw_config: serde_yaml::Value = serde_yaml::from_str(&config_content).map_err(|e| {
            ConfigError::LoadError(format!(
                "Failed to parse config file '{}': {}",
                config_path.display(),
                e
            ))
        })?;
        if let serde_yaml::Value::Mapping(mapping) = &raw_config {
            let servers_key = serde_yaml::Value::String("servers".to_string());
            if mapping.contains_key(&servers_key) {
                return Err(ConfigError::LoadError(
                    "Unsupported config section 'servers'; use 'server' and optional 'tls' instead"
                        .to_string(),
                ));
            }
        }
        let config: Config = serde_yaml::from_value(raw_config).map_err(|e| {
            ConfigError::LoadError(format!(
                "Failed to parse config file '{}': {}",
                config_path.display(),
                e
            ))
        })?;
        Ok(config)
    }

    /// Loads and validates configuration at startup. If validation fails, the application should not start.
    pub fn load_and_validate(root: &Path) -> Result<ValidatedConfig, ConfigError> {
        let config = Self::load(root)?;

        // Validate users configuration based on auth method
        let validated_users = match config.users.auth_method {
            AuthMethod::Local => {
                let local_config = config.users.local.as_ref().ok_or_else(|| {
                    ConfigError::ValidationError(
                        "Local auth method requires 'local' configuration".to_string(),
                    )
                })?;

                // Validate JWT refresh configuration
                let jwt_config = &local_config.jwt;

                // Validate refresh_threshold_percentage (10-90)
                if jwt_config.refresh_threshold_percentage < 10
                    || jwt_config.refresh_threshold_percentage > 90
                {
                    return Err(ConfigError::ValidationError(format!(
                        "JWT refresh_threshold_percentage must be between 10 and 90, got: {}",
                        jwt_config.refresh_threshold_percentage
                    )));
                }

                // Validate refresh_threshold_hours (minimum 1)
                if jwt_config.refresh_threshold_hours < 1 {
                    return Err(ConfigError::ValidationError(format!(
                        "JWT refresh_threshold_hours must be at least 1, got: {}",
                        jwt_config.refresh_threshold_hours
                    )));
                }

                // Log warning if refresh_threshold_hours > expiration_hours
                if jwt_config.refresh_threshold_hours > jwt_config.expiration_hours {
                    log::warn!(
                        "JWT refresh_threshold_hours ({}) is greater than expiration_hours ({}). \
                        Long-lived token refresh will not be effective.",
                        jwt_config.refresh_threshold_hours,
                        jwt_config.expiration_hours
                    );
                }

                let password_params = PasswordHashingParams {
                    front_end: Argon2Params::resolve(
                        "front_end",
                        &local_config.password.front_end,
                        default_argon2_front_end_params(),
                    )?,
                    back_end: Argon2Params::resolve(
                        "back_end",
                        &local_config.password.back_end,
                        default_argon2_back_end_params(),
                    )?,
                };

                ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
                    jwt: local_config.jwt.clone(),
                    password: password_params,
                })
            }
            AuthMethod::Oidc => {
                if config.users.oidc.is_none() {
                    return Err(ConfigError::ValidationError(
                        "OIDC auth method requires 'oidc' configuration".to_string(),
                    ));
                }

                let oidc = config.users.oidc.clone().ok_or_else(|| {
                    ConfigError::ValidationError(
                        "OIDC auth method requires 'oidc' configuration".to_string(),
                    )
                })?;

                ValidatedUsersConfig::Oidc(oidc)
            }
        };

        let dev_mode = if let Some(dev_mode) = config.dev_mode.clone() {
            if cfg!(debug_assertions) {
                match dev_mode {
                    DevMode::Dangerous => {
                        warn!(
                            "🚨 WARNING: Development mode set to 'dangerous' - ALL access controls are bypassed!"
                        );
                        warn!("🚨 This should NEVER be used in production!");
                    }
                    DevMode::Localhost => {
                        warn!("🔧 Development mode enabled for localhost connections");
                    }
                }
                Some(dev_mode)
            } else {
                warn!(
                    "🚨 WARNING: dev_mode is configured but ignored in release builds; remove it from config.yaml"
                );
                None
            }
        } else {
            None
        };

        // Validate shortcode configuration
        Self::validate_shortcodes(&config.shortcodes)?;
        Self::validate_logging(&config.logging)?;

        let servers = Self::build_servers(&config.server, config.tls.as_ref())?;

        if let Some(tls) = config.tls.as_ref() {
            Self::validate_tls_config(tls)?;
        }

        let validated_config = ValidatedConfig {
            servers,
            server: config.server,
            admin: config.admin,
            users: validated_users,
            navigation: config.navigation,
            logging: config.logging,
            security: config.security,
            tls: config.tls,
            app: config.app,
            upload: config.upload,
            streaming: config.streaming,
            shortcodes: config.shortcodes,
            rendering: config.rendering,
            dev_mode,
        };

        Ok(validated_config)
    }

    /// Validate shortcode configuration
    fn validate_shortcodes(shortcodes: &ShortcodeConfig) -> Result<(), ConfigError> {
        // Validate start-unibox search URL
        let url = &shortcodes.start_unibox;

        // Check if URL contains the required <QUERY> placeholder
        if !url.contains("<QUERY>") {
            return Err(ConfigError::ValidationError(
                "Shortcode start-unibox search URL must contain '<QUERY>' placeholder".to_string(),
            ));
        }

        // Check if it's a valid URL format (basic check)
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ConfigError::ValidationError(
                "Shortcode start-unibox search URL must be a fully qualified URL starting with http:// or https://".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_logging(logging: &LoggingConfig) -> Result<(), ConfigError> {
        let max_size_mb = logging.rotation.max_size_mb;
        if !(1..=1024).contains(&max_size_mb) {
            return Err(ConfigError::ValidationError(format!(
                "Logging rotation max_size_mb must be between 1 and 1024, got: {}",
                max_size_mb
            )));
        }

        let max_files = logging.rotation.max_files;
        if !(1..=100).contains(&max_files) {
            return Err(ConfigError::ValidationError(format!(
                "Logging rotation max_files must be between 1 and 100, got: {}",
                max_files
            )));
        }

        Ok(())
    }

    fn build_servers(
        server: &ServerConfig,
        tls: Option<&TlsConfig>,
    ) -> Result<Vec<ServerListenerConfig>, ConfigError> {
        if server.host.trim().is_empty() {
            return Err(ConfigError::ValidationError(
                "server.host cannot be empty".to_string(),
            ));
        }
        if server.port == 0 {
            return Err(ConfigError::ValidationError(
                "server.port must be greater than 0".to_string(),
            ));
        }

        if tls.is_some() {
            let http_port = server.http_port.ok_or_else(|| {
                ConfigError::ValidationError(
                    "TLS enabled: server.http_port is required".to_string(),
                )
            })?;
            if http_port == 0 {
                return Err(ConfigError::ValidationError(
                    "TLS enabled: server.http_port must be greater than 0".to_string(),
                ));
            }
            if http_port == server.port {
                return Err(ConfigError::ValidationError(
                    "TLS enabled: server.http_port must differ from server.port".to_string(),
                ));
            }

            Ok(vec![
                ServerListenerConfig::main_https(&server.host, server.port),
                ServerListenerConfig::well_known_http(&server.host, http_port),
            ])
        } else {
            if server.http_port.is_some() {
                return Err(ConfigError::ValidationError(
                    "TLS disabled: server.http_port must not be set".to_string(),
                ));
            }

            Ok(vec![ServerListenerConfig::main_http(
                &server.host,
                server.port,
            )])
        }
    }

    fn validate_tls_config(tls: &TlsConfig) -> Result<(), ConfigError> {
        if let Some(base_url) = &tls.redirect_base_url
            && !base_url.starts_with("https://")
        {
            return Err(ConfigError::ValidationError(
                "tls.redirect_base_url must start with https://".to_string(),
            ));
        }

        match tls.mode {
            TlsMode::SelfSigned | TlsMode::Acme => {
                if tls.domains.is_empty() {
                    return Err(ConfigError::ValidationError(
                        "tls.domains must include at least one domain".to_string(),
                    ));
                }
                if tls.domains.iter().any(|domain| domain.trim().is_empty()) {
                    return Err(ConfigError::ValidationError(
                        "tls.domains entries cannot be empty".to_string(),
                    ));
                }
            }
            TlsMode::UserProvided => {}
        }

        if tls.mode == TlsMode::Acme {
            let acme = tls.acme.as_ref().ok_or_else(|| {
                ConfigError::ValidationError(
                    "tls.acme configuration is required for mode: acme".to_string(),
                )
            })?;

            if acme.provider.trim().to_lowercase() != "lers" {
                return Err(ConfigError::ValidationError(
                    "tls.acme.provider must be set to lers".to_string(),
                ));
            }

            if acme.contact_email.trim().is_empty() || !acme.contact_email.contains('@') {
                return Err(ConfigError::ValidationError(
                    "tls.acme.contact_email must be a valid email".to_string(),
                ));
            }

            if let Some(url) = acme.directory_url.as_ref()
                && !url.starts_with("https://")
            {
                return Err(ConfigError::ValidationError(
                    "tls.acme.directory_url must start with https://".to_string(),
                ));
            }

            if acme.challenge == AcmeChallenge::Dns01 {
                let dns = acme.dns.as_ref().ok_or_else(|| {
                    ConfigError::ValidationError(
                        "tls.acme.dns settings are required for DNS-01".to_string(),
                    )
                })?;

                if dns.provider.trim().is_empty() {
                    return Err(ConfigError::ValidationError(
                        "tls.acme.dns.provider cannot be empty".to_string(),
                    ));
                }
                let provider = dns.provider.trim().to_lowercase();
                match provider.as_str() {
                    "cloudflare" => {
                        let token = dns.api_token.as_ref().ok_or_else(|| {
                            ConfigError::ValidationError(
                                "tls.acme.dns.api_token is required for cloudflare".to_string(),
                            )
                        })?;
                        if token.trim().is_empty() {
                            return Err(ConfigError::ValidationError(
                                "tls.acme.dns.api_token cannot be empty".to_string(),
                            ));
                        }
                    }
                    "exec" => {
                        let exec = dns.exec.as_ref().ok_or_else(|| {
                            ConfigError::ValidationError(
                                "tls.acme.dns.exec is required for exec provider".to_string(),
                            )
                        })?;
                        if exec.present_command.trim().is_empty() {
                            return Err(ConfigError::ValidationError(
                                "tls.acme.dns.exec.present_command cannot be empty".to_string(),
                            ));
                        }
                        if exec.cleanup_command.trim().is_empty() {
                            return Err(ConfigError::ValidationError(
                                "tls.acme.dns.exec.cleanup_command cannot be empty".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(ConfigError::ValidationError(
                            "tls.acme.dns.provider must be cloudflare or exec".to_string(),
                        ));
                    }
                }

                if !dns.resolver.is_empty() {
                    for resolver in &dns.resolver {
                        let trimmed = resolver.trim();
                        if trimmed.is_empty() {
                            return Err(ConfigError::ValidationError(
                                "tls.acme.dns.resolver cannot be empty".to_string(),
                            ));
                        }
                        if parse_dns_resolver_addr(trimmed).is_none() {
                            return Err(ConfigError::ValidationError(format!(
                                "tls.acme.dns.resolver must be an IP address or socket address: {}",
                                resolver
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl ValidatedConfig {
    pub fn is_tls_enabled(&self) -> bool {
        self.servers.iter().any(|server| {
            server.role == ServerRole::Main && server.protocol == ServerProtocol::Https
        })
    }

    pub fn is_localhost_only(&self) -> bool {
        let mut has_main = false;
        let localhost = ["127.0.0.1", "localhost"];

        for server in &self.servers {
            if server.role != ServerRole::Main {
                continue;
            }

            has_main = true;
            if !localhost.contains(&server.host.as_str()) {
                return false;
            }
        }

        has_main
    }

    pub fn servers_for_role(
        &self,
        role: ServerRole,
        protocol: Option<ServerProtocol>,
    ) -> Vec<&ServerListenerConfig> {
        self.servers
            .iter()
            .filter(|server| server.role == role)
            .filter(|server| protocol.is_none_or(|proto| server.protocol == proto))
            .collect()
    }
}

#[cfg(test)]
pub fn test_server_list() -> Vec<ServerListenerConfig> {
    vec![ServerListenerConfig {
        name: Some("main".to_string()),
        role: ServerRole::Main,
        host: "127.0.0.1".to_string(),
        port: 5466,
        protocol: ServerProtocol::Http,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;

    fn base_server_config() -> ServerConfig {
        ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            http_port: None,
            workers: 1,
        }
    }

    fn tls_server_config(http_port: Option<u16>) -> ServerConfig {
        ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8443,
            http_port,
            workers: 1,
        }
    }

    fn base_tls_config(mode: TlsMode) -> TlsConfig {
        TlsConfig {
            mode,
            domains: vec!["example.com".to_string()],
            redirect_base_url: Some("https://example.com".to_string()),
            acme: None,
        }
    }

    fn base_logging_config() -> LoggingConfig {
        LoggingConfig {
            level: "info".to_string(),
            rotation: LoggingRotationConfig::default(),
        }
    }

    #[test]
    fn build_servers_allows_http_only() {
        let server = base_server_config();
        let servers = Config::build_servers(&server, None).expect("valid server config");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].role, ServerRole::Main);
        assert_eq!(servers[0].protocol, ServerProtocol::Http);
        assert_eq!(servers[0].port, 8080);
    }

    #[test]
    fn build_servers_rejects_http_port_without_tls() {
        let mut server = base_server_config();
        server.http_port = Some(8081);
        let result = Config::build_servers(&server, None);
        assert!(result.is_err(), "http_port without TLS should fail");
    }

    #[test]
    fn build_servers_requires_http_port_with_tls() {
        let server = tls_server_config(None);
        let tls = base_tls_config(TlsMode::SelfSigned);
        let result = Config::build_servers(&server, Some(&tls));
        assert!(result.is_err(), "missing http_port should fail");
    }

    #[test]
    fn build_servers_rejects_matching_ports_with_tls() {
        let server = tls_server_config(Some(8443));
        let tls = base_tls_config(TlsMode::SelfSigned);
        let result = Config::build_servers(&server, Some(&tls));
        assert!(result.is_err(), "http_port equal to port should fail");
    }

    #[test]
    fn build_servers_creates_https_and_well_known() {
        let server = tls_server_config(Some(8080));
        let tls = base_tls_config(TlsMode::SelfSigned);
        let servers = Config::build_servers(&server, Some(&tls)).expect("valid TLS config");
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().any(|listener| {
            listener.role == ServerRole::Main
                && listener.protocol == ServerProtocol::Https
                && listener.port == 8443
        }));
        assert!(servers.iter().any(|listener| {
            listener.role == ServerRole::WellKnown
                && listener.protocol == ServerProtocol::Http
                && listener.port == 8080
        }));
    }

    #[test]
    fn load_rejects_servers_section() {
        let fixture = TestFixtureRoot::new_unique("config-servers").unwrap();
        let config_path = fixture.path().join("config.yaml");
        fs::write(&config_path, "servers:\n  - name: \"main\"\n").unwrap();
        let err = Config::load(fixture.path()).expect_err("servers section should be rejected");
        assert!(err.to_string().contains("servers"));
    }

    #[test]
    fn validate_logging_accepts_defaults() {
        let logging = base_logging_config();
        assert!(Config::validate_logging(&logging).is_ok());
    }

    #[test]
    fn validate_logging_rejects_small_max_size() {
        let mut logging = base_logging_config();
        logging.rotation.max_size_mb = 0;
        assert!(Config::validate_logging(&logging).is_err());
    }

    #[test]
    fn validate_logging_rejects_large_max_files() {
        let mut logging = base_logging_config();
        logging.rotation.max_files = 101;
        assert!(Config::validate_logging(&logging).is_err());
    }

    #[test]
    fn validate_tls_config_rejects_non_https_redirect() {
        let mut tls = base_tls_config(TlsMode::SelfSigned);
        tls.redirect_base_url = Some("http://example.com".to_string());
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "redirect_base_url must be https");
    }

    #[test]
    fn validate_tls_config_requires_acme_settings() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = None;
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "acme mode requires acme config");
    }

    #[test]
    fn validate_tls_config_requires_dns_settings_for_dns01() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = Some(AcmeConfig {
            provider: "lers".to_string(),
            environment: AcmeEnvironment::Staging,
            directory_url: None,
            insecure_skip_verify: false,
            contact_email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Dns01,
            dns: None,
        });
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "dns-01 requires dns config");
    }

    #[test]
    fn validate_tls_config_rejects_unknown_acme_provider() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = Some(AcmeConfig {
            provider: "other".to_string(),
            environment: AcmeEnvironment::Staging,
            directory_url: None,
            insecure_skip_verify: false,
            contact_email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Http01,
            dns: None,
        });
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "unknown provider should fail");
    }

    #[test]
    fn validate_tls_config_rejects_invalid_directory_url() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = Some(AcmeConfig {
            provider: "lers".to_string(),
            environment: AcmeEnvironment::Staging,
            directory_url: Some("http://localhost/dir".to_string()),
            insecure_skip_verify: false,
            contact_email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Http01,
            dns: None,
        });
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "directory_url must be https");
    }

    #[test]
    fn validate_tls_config_rejects_unknown_dns_provider() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = Some(AcmeConfig {
            provider: "lers".to_string(),
            environment: AcmeEnvironment::Staging,
            directory_url: None,
            insecure_skip_verify: false,
            contact_email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Dns01,
            dns: Some(AcmeDnsConfig {
                provider: "other".to_string(),
                api_token: Some("token".to_string()),
                exec: None,
                resolver: Vec::new(),
                propagation_check: false,
                propagation_delay_seconds: 30,
            }),
        });
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "unknown dns provider should fail");
    }

    #[test]
    fn validate_tls_config_requires_exec_commands() {
        let mut tls = base_tls_config(TlsMode::Acme);
        tls.acme = Some(AcmeConfig {
            provider: "lers".to_string(),
            environment: AcmeEnvironment::Staging,
            directory_url: None,
            insecure_skip_verify: false,
            contact_email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Dns01,
            dns: Some(AcmeDnsConfig {
                provider: "exec".to_string(),
                api_token: None,
                exec: Some(AcmeDnsExecConfig {
                    present_command: "".to_string(),
                    cleanup_command: "".to_string(),
                }),
                resolver: Vec::new(),
                propagation_check: false,
                propagation_delay_seconds: 30,
            }),
        });
        let result = Config::validate_tls_config(&tls);
        assert!(result.is_err(), "exec provider requires commands");
    }
}
