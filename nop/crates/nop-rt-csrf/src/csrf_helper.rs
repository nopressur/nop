// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::HttpRequest;
use nop_config::ValidatedConfig;
use nop_rt_iam::middleware::AuthRequest;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const CSRF_TOKEN_EXPIRY_SECONDS: u64 = 3600; // Changed from 15 minutes to 1 hour

/// Template-based list of endpoints exempt from CSRF validation
/// Placeholders will be replaced with actual configured values at initialization
static CSRF_EXEMPT_ENDPOINT_TEMPLATES: &[&str] = &[
    "/login",                      // Initial login - no auth yet
    "/login/bootstrap",            // Login session bootstrap
    "/login/pwd/email",            // Password provider salt fetch
    "/login/pwd/password",         // Password provider verification
    "/login/csrf-token-api",       // Login CSRF token acquisition
    "/login/logout-api",           // Logout (unauthenticated endpoint)
    "/login/oidc/callback",        // OIDC callback - external redirect
    "{ADMIN_PATH}/csrf-token-api", // CSRF token acquisition itself (configurable admin path)
];

#[derive(Clone, Debug)]
struct CsrfTokenData {
    created_at: Instant,
    jwt_id: String,
}

#[derive(Clone)]
pub struct CsrfTokenStore {
    sender: mpsc::Sender<CsrfCommand>,
    // Generated CSRF exempt endpoints list with actual configured paths
    exempt_endpoints: Arc<HashSet<String>>,
}

enum CsrfCommand {
    #[cfg(test)]
    GetNewToken {
        jwt_id: String,
        reply: mpsc::Sender<String>,
    },
    GetOrRefresh {
        jwt_id: String,
        reply: mpsc::Sender<String>,
    },
    ValidateAndRenew {
        token_value: String,
        jwt_id: String,
        reply: mpsc::Sender<bool>,
    },
    CleanupTokens {
        jwt_id: String,
    },
    #[cfg(test)]
    SnapshotJwtIds {
        reply: mpsc::Sender<HashMap<String, String>>,
    },
}

pub enum CsrfTokenOutcome {
    Authorized { jwt_id: String, token: String },
    DevMode { jwt_id: String, token: String },
    Unauthorized,
}

pub fn issue_csrf_token(
    req: &HttpRequest,
    csrf_store: &CsrfTokenStore,
    config: &ValidatedConfig,
) -> CsrfTokenOutcome {
    if let Some(jwt_id) = req.jwt_id() {
        let csrf_token = csrf_store.get_or_refresh_token(&jwt_id);
        return CsrfTokenOutcome::Authorized {
            jwt_id,
            token: csrf_token,
        };
    }

    if nop_rt_security::is_dev_mode_bypass_allowed(req, config) {
        let jwt_id = "localhost".to_string();
        let csrf_token = csrf_store.get_or_refresh_token(&jwt_id);
        return CsrfTokenOutcome::DevMode {
            jwt_id,
            token: csrf_token,
        };
    }

    CsrfTokenOutcome::Unauthorized
}

impl CsrfTokenStore {
    pub fn new(config: &ValidatedConfig) -> Self {
        // Generate the actual exempt endpoints list from templates using configuration
        let mut exempt_endpoints = HashSet::new();

        for template in CSRF_EXEMPT_ENDPOINT_TEMPLATES {
            let endpoint = template.replace("{ADMIN_PATH}", &config.admin.path);
            exempt_endpoints.insert(endpoint);
        }

        log::debug!("Generated CSRF exempt endpoints: {:?}", exempt_endpoints);

        CsrfTokenStore {
            sender: start_csrf_worker(),
            exempt_endpoints: Arc::new(exempt_endpoints),
        }
    }

    pub fn expiry_seconds(&self) -> u64 {
        CSRF_TOKEN_EXPIRY_SECONDS
    }

    /// Check if an endpoint is exempt from CSRF validation
    pub fn is_exempt(&self, path: &str, method: &str) -> bool {
        // Skip non-modifying requests
        if !["POST", "PUT", "PATCH", "DELETE"].contains(&method) {
            return true;
        }

        // Check against generated exempt list
        self.exempt_endpoints.contains(path)
    }

    fn generate_new_token_value() -> String {
        Uuid::new_v4().to_string()
    }

    fn request<T>(&self, build: impl FnOnce(mpsc::Sender<T>) -> CsrfCommand, fallback: T) -> T {
        let (reply, receive) = mpsc::channel();
        if self.sender.send(build(reply)).is_err() {
            log::error!("🚨 CRITICAL: CsrfTokenStore channel closed");
            return fallback;
        }
        receive.recv().unwrap_or(fallback)
    }

    fn send_command(&self, command: CsrfCommand) {
        if self.sender.send(command).is_err() {
            log::error!("🚨 CRITICAL: CsrfTokenStore channel closed");
        }
    }

    /// Test-only helper: generates a new CSRF token bound to the given JWT ID.
    /// Also cleans up expired tokens.
    #[cfg(test)]
    pub fn get_new_token(&self, jwt_id: &str) -> String {
        self.request(
            |reply| CsrfCommand::GetNewToken {
                jwt_id: jwt_id.to_string(),
                reply,
            },
            String::new(),
        )
    }

    /// Validates a CSRF token against the provided JWT ID. If valid, it's renewed instead of removed.
    /// Returns true if valid, false otherwise.
    /// Also cleans up expired tokens before validation.
    pub fn validate_and_renew_token(&self, token_value: &str, jwt_id: &str) -> bool {
        self.request(
            |reply| CsrfCommand::ValidateAndRenew {
                token_value: token_value.to_string(),
                jwt_id: jwt_id.to_string(),
                reply,
            },
            false,
        )
    }

    /// Clean up all tokens associated with a specific JWT ID (for logout)
    pub fn cleanup_tokens_for_jwt_id(&self, jwt_id: &str) {
        self.send_command(CsrfCommand::CleanupTokens {
            jwt_id: jwt_id.to_string(),
        });
    }

    /// Get or refresh a token for the given JWT ID
    /// Returns existing valid token if found, or creates a new one
    pub fn get_or_refresh_token(&self, jwt_id: &str) -> String {
        self.request(
            |reply| CsrfCommand::GetOrRefresh {
                jwt_id: jwt_id.to_string(),
                reply,
            },
            String::new(),
        )
    }

    #[cfg(test)]
    fn snapshot_jwt_ids(&self) -> HashMap<String, String> {
        self.request(
            |reply| CsrfCommand::SnapshotJwtIds { reply },
            HashMap::new(),
        )
    }
}

fn start_csrf_worker() -> mpsc::Sender<CsrfCommand> {
    let (sender, receiver) = mpsc::channel();
    let thread = thread::Builder::new().name("csrf-token-store".to_string());
    if let Err(err) = thread.spawn(move || run_csrf_worker(receiver)) {
        log::error!("CsrfTokenStore worker failed to start: {}", err);
    }
    sender
}

fn run_csrf_worker(receiver: mpsc::Receiver<CsrfCommand>) {
    let mut tokens: HashMap<String, CsrfTokenData> = HashMap::new();
    while let Ok(command) = receiver.recv() {
        let now = Instant::now();
        cleanup_expired_tokens(&mut tokens, now);
        match command {
            #[cfg(test)]
            CsrfCommand::GetNewToken { jwt_id, reply } => {
                let token = generate_new_token(jwt_id, &mut tokens, now);
                let _ = reply.send(token);
            }
            CsrfCommand::GetOrRefresh { jwt_id, reply } => {
                let token = find_or_refresh_token(jwt_id, &mut tokens, now);
                let _ = reply.send(token);
            }
            CsrfCommand::ValidateAndRenew {
                token_value,
                jwt_id,
                reply,
            } => {
                let valid = validate_and_renew(&token_value, &jwt_id, &mut tokens, now);
                let _ = reply.send(valid);
            }
            CsrfCommand::CleanupTokens { jwt_id } => {
                cleanup_tokens_for_jwt_id(&jwt_id, &mut tokens);
            }
            #[cfg(test)]
            CsrfCommand::SnapshotJwtIds { reply } => {
                let snapshot = tokens
                    .iter()
                    .map(|(token, data)| (token.clone(), data.jwt_id.clone()))
                    .collect::<HashMap<_, _>>();
                let _ = reply.send(snapshot);
            }
        }
    }
}

fn generate_new_token(
    jwt_id: String,
    tokens: &mut HashMap<String, CsrfTokenData>,
    now: Instant,
) -> String {
    let token = CsrfTokenStore::generate_new_token_value();
    tokens.insert(
        token.clone(),
        CsrfTokenData {
            created_at: now,
            jwt_id,
        },
    );
    token
}

fn find_or_refresh_token(
    jwt_id: String,
    tokens: &mut HashMap<String, CsrfTokenData>,
    now: Instant,
) -> String {
    if let Some((token, data)) = tokens.iter_mut().find(|(_, data)| data.jwt_id == jwt_id) {
        data.created_at = now;
        return token.clone();
    }

    generate_new_token(jwt_id, tokens, now)
}

fn validate_and_renew(
    token_value: &str,
    jwt_id: &str,
    tokens: &mut HashMap<String, CsrfTokenData>,
    now: Instant,
) -> bool {
    if let Some(data) = tokens.get_mut(token_value) {
        if data.jwt_id == jwt_id {
            data.created_at = now;
            return true;
        }
        tokens.remove(token_value);
    }
    false
}

fn cleanup_tokens_for_jwt_id(jwt_id: &str, tokens: &mut HashMap<String, CsrfTokenData>) {
    let expired_tokens = tokens
        .iter()
        .filter_map(|(token, data)| {
            if data.jwt_id == jwt_id {
                Some(token.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for token in expired_tokens {
        tokens.remove(&token);
    }
}

fn cleanup_expired_tokens(tokens: &mut HashMap<String, CsrfTokenData>, now: Instant) {
    tokens.retain(|_, data| {
        now.duration_since(data.created_at) < Duration::from_secs(CSRF_TOKEN_EXPIRY_SECONDS)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_config::{
        AdminConfig, AppConfig, DEFAULT_ARGON2_BACK_END_PARAMS, DEFAULT_ARGON2_FRONT_END_PARAMS,
        JwtConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig, PasswordHashingParams,
        RenderingConfig, SearchConfig, SecurityConfig, ServerConfig, ServerListenerConfig,
        ServerProtocol, ServerRole, ShortcodeConfig, StreamingConfig, UploadConfig,
        ValidatedConfig, ValidatedLocalAuthConfig, ValidatedUsersConfig,
    };

    fn create_test_config() -> ValidatedConfig {
        TestConfigBuilder::new().build()
    }

    #[derive(Debug, Clone)]
    struct TestConfigBuilder {
        config: ValidatedConfig,
    }

    impl TestConfigBuilder {
        fn new() -> Self {
            Self {
                config: ValidatedConfig {
                    servers: build_test_server_list(),
                    server: ServerConfig {
                        host: "127.0.0.1".to_string(),
                        port: 5466,
                        http_port: None,
                        workers: 1,
                    },
                    admin: AdminConfig {
                        path: "/admin".to_string(),
                    },
                    users: build_test_local_users_config(),
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
                    tls: None,
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
                    search: SearchConfig::default(),
                    dev_mode: None,
                },
            }
        }

        fn build(self) -> ValidatedConfig {
            self.config
        }
    }

    fn build_test_server_list() -> Vec<ServerListenerConfig> {
        vec![ServerListenerConfig {
            name: Some("main".to_string()),
            role: ServerRole::Main,
            host: "127.0.0.1".to_string(),
            port: 5466,
            protocol: ServerProtocol::Http,
        }]
    }

    fn build_test_local_users_config() -> ValidatedUsersConfig {
        ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
            jwt: JwtConfig {
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
            password: PasswordHashingParams {
                front_end: DEFAULT_ARGON2_FRONT_END_PARAMS,
                back_end: DEFAULT_ARGON2_BACK_END_PARAMS,
            },
            password_complexity_enabled: true,
        })
    }

    #[test]
    fn test_get_new_token_with_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token = store.get_new_token("jwt123");
        assert!(!token.is_empty());
    }

    #[test]
    fn test_validate_and_renew_token_valid() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token = store.get_new_token("jwt123");
        assert!(store.validate_and_renew_token(&token, "jwt123"));
    }

    #[test]
    fn test_validate_and_renew_token_wrong_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token = store.get_new_token("jwt123");
        assert!(!store.validate_and_renew_token(&token, "jwt456"));
    }

    #[test]
    fn test_validate_and_renew_token_invalid() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        assert!(!store.validate_and_renew_token("invalid_token", "jwt123"));
    }

    #[test]
    fn test_validate_and_renew_token_empty_store() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        assert!(!store.validate_and_renew_token("token", "jwt123"));
    }

    #[test]
    fn test_token_expiration() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token = store.get_new_token("jwt123");
        let snapshot = store.snapshot_jwt_ids();
        assert_eq!(snapshot.get(&token), Some(&"jwt123".to_string()));
    }

    #[test]
    fn test_cleanup_tokens_for_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token1 = store.get_new_token("jwt123");
        let token2 = store.get_new_token("jwt456");
        store.cleanup_tokens_for_jwt_id("jwt123");
        let snapshot = store.snapshot_jwt_ids();
        assert!(!snapshot.contains_key(&token1));
        assert!(snapshot.contains_key(&token2));
    }

    #[test]
    fn test_get_or_refresh_token() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token1 = store.get_or_refresh_token("jwt123");
        let token2 = store.get_or_refresh_token("jwt123");
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_get_or_refresh_token_different_jwt_ids() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token1 = store.get_or_refresh_token("jwt123");
        let token2 = store.get_or_refresh_token("jwt456");
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_integration_csrf_workflow() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token = store.get_or_refresh_token("jwt123");
        assert!(store.validate_and_renew_token(&token, "jwt123"));
        store.cleanup_tokens_for_jwt_id("jwt123");
        assert!(!store.validate_and_renew_token(&token, "jwt123"));
    }

    #[test]
    fn test_csrf_store_characteristics() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        assert_eq!(store.expiry_seconds(), CSRF_TOKEN_EXPIRY_SECONDS);
    }

    #[test]
    fn test_cleanup_multiple_tokens() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let token1 = store.get_or_refresh_token("jwt123");
        // Force a second token by deleting the first
        let snapshot = store.snapshot_jwt_ids();
        let _ = snapshot.get(&token1);
        store.cleanup_tokens_for_jwt_id("jwt123");

        // So we need to create a new token to continue testing
        let token2 = store.get_or_refresh_token("jwt123");
        assert_ne!(token1, token2);
        store.cleanup_tokens_for_jwt_id("jwt123");
        assert!(!store.validate_and_renew_token(&token2, "jwt123"));
    }
}
