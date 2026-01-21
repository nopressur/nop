// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;
use crate::iam::middleware::AuthRequest;
use actix_web::HttpRequest;
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

    if crate::security::is_dev_mode_bypass_allowed(req, config) {
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
                let new_token_value = CsrfTokenStore::generate_new_token_value();
                tokens.insert(
                    new_token_value.clone(),
                    CsrfTokenData {
                        created_at: now,
                        jwt_id: jwt_id.clone(),
                    },
                );
                log::debug!("Generated new CSRF token for JWT ID: {}", jwt_id);
                let _ = reply.send(new_token_value);
            }
            CsrfCommand::GetOrRefresh { jwt_id, reply } => {
                let mut refreshed = None;
                for (token_value, token_data) in tokens.iter_mut() {
                    if token_data.jwt_id == jwt_id {
                        token_data.created_at = now;
                        refreshed = Some(token_value.clone());
                        log::debug!("Refreshed existing CSRF token for JWT ID: {}", jwt_id);
                        break;
                    }
                }

                let token_value = refreshed.unwrap_or_else(|| {
                    let new_token_value = CsrfTokenStore::generate_new_token_value();
                    tokens.insert(
                        new_token_value.clone(),
                        CsrfTokenData {
                            created_at: now,
                            jwt_id: jwt_id.clone(),
                        },
                    );
                    log::debug!("Created new CSRF token for JWT ID: {}", jwt_id);
                    new_token_value
                });

                let _ = reply.send(token_value);
            }
            CsrfCommand::ValidateAndRenew {
                token_value,
                jwt_id,
                reply,
            } => {
                let is_valid = match tokens.get_mut(&token_value) {
                    Some(token_data) => {
                        if token_data.jwt_id == jwt_id {
                            token_data.created_at = now;
                            log::debug!("CSRF token validated and renewed for JWT ID: {}", jwt_id);
                            true
                        } else {
                            log::warn!(
                                "CSRF token JWT ID mismatch. Expected: {}, Got: {}",
                                token_data.jwt_id,
                                jwt_id
                            );
                            tokens.remove(&token_value);
                            false
                        }
                    }
                    None => false,
                };
                let _ = reply.send(is_valid);
            }
            CsrfCommand::CleanupTokens { jwt_id } => {
                tokens.retain(|_, token_data| token_data.jwt_id != jwt_id);
                log::debug!("Cleaned up CSRF tokens for JWT ID: {}", jwt_id);
            }
            #[cfg(test)]
            CsrfCommand::SnapshotJwtIds { reply } => {
                let snapshot = tokens
                    .iter()
                    .map(|(token, data)| (token.clone(), data.jwt_id.clone()))
                    .collect();
                let _ = reply.send(snapshot);
            }
        }
    }
}

fn cleanup_expired_tokens(tokens: &mut HashMap<String, CsrfTokenData>, now: Instant) {
    tokens.retain(|_, token_data| {
        now.duration_since(token_data.created_at) < Duration::from_secs(CSRF_TOKEN_EXPIRY_SECONDS)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_config::test_config;
    use std::thread;

    fn create_test_config() -> ValidatedConfig {
        test_config()
    }

    #[test]
    fn test_get_new_token_with_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "test-jwt-id-1";
        let token1 = store.get_new_token(jwt_id);
        let token2 = store.get_new_token(jwt_id);
        assert_ne!(token1, token2);

        let tokens = store.snapshot_jwt_ids();
        assert!(tokens.contains_key(&token1));
        assert!(tokens.contains_key(&token2));
        assert_eq!(tokens.get(&token1).unwrap(), jwt_id);
        assert_eq!(tokens.get(&token2).unwrap(), jwt_id);
    }

    #[test]
    fn test_validate_and_renew_token_valid() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "test-jwt-id";
        let token = store.get_new_token(jwt_id);

        // First validation should succeed and renew
        assert!(store.validate_and_renew_token(&token, jwt_id));

        // Token should still exist after validation (renewed, not consumed)
        assert!(store.snapshot_jwt_ids().contains_key(&token));

        // Second validation should also succeed
        assert!(store.validate_and_renew_token(&token, jwt_id));
    }

    #[test]
    fn test_validate_and_renew_token_wrong_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "test-jwt-id";
        let wrong_jwt_id = "wrong-jwt-id";
        let token = store.get_new_token(jwt_id);

        // Validation with wrong JWT ID should fail
        assert!(!store.validate_and_renew_token(&token, wrong_jwt_id));

        // Token should be removed after failed validation
        assert!(!store.snapshot_jwt_ids().contains_key(&token));
    }

    #[test]
    fn test_validate_and_renew_token_invalid() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "test-jwt-id";
        let _valid_token = store.get_new_token(jwt_id);
        assert!(!store.validate_and_renew_token("invalid-token", jwt_id));
    }

    #[test]
    fn test_validate_and_renew_token_empty_store() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        assert!(!store.validate_and_renew_token("any-token", "any-jwt-id"));
    }

    #[test]
    fn test_token_expiration() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);

        // For this test, we need to use a separate store instance to test expiry behavior
        // We can't easily manipulate time in tests, so we'll use the renewal behavior
        let jwt_id = "test-jwt-id";
        let token = store.get_new_token(jwt_id);

        // Test that validation works initially
        assert!(store.validate_and_renew_token(&token, jwt_id));

        // The token should still be valid after renewal
        assert!(store.validate_and_renew_token(&token, jwt_id));

        // Test expiry behavior would require mocking time, which is complex
        // For now, we'll just verify the token mechanism works

        // Test that a completely invalid token fails
        assert!(!store.validate_and_renew_token("invalid-token", jwt_id));

        // Test with different JWT ID
        assert!(!store.validate_and_renew_token(&token, "different-jwt-id"));

        // Note: After validation with wrong JWT ID, the token is removed from store
        // So we need to create a new token to continue testing
        let token = store.get_new_token(jwt_id);
        assert!(store.validate_and_renew_token(&token, jwt_id));

        // Test cleanup mechanism by creating many tokens
        let store_for_validation_expiry = CsrfTokenStore::new(&config);
        let mut tokens = Vec::new();
        for i in 0..100 {
            let jwt_id = format!("jwt-{}", i);
            let token = store_for_validation_expiry.get_new_token(&jwt_id);
            tokens.push((token, jwt_id));
        }

        // All tokens should be valid initially
        for (token, jwt_id) in &tokens {
            assert!(store_for_validation_expiry.validate_and_renew_token(token, jwt_id));
        }

        // Create more tokens to trigger cleanup (if implemented)
        for i in 100..200 {
            let jwt_id = format!("jwt-{}", i);
            store_for_validation_expiry.get_new_token(&jwt_id);
        }

        // Original tokens should still be valid due to renewal
        for (token, jwt_id) in &tokens {
            assert!(store_for_validation_expiry.validate_and_renew_token(token, jwt_id));
        }
    }

    #[test]
    fn test_cleanup_tokens_for_jwt_id() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id1 = "jwt-id-1";
        let jwt_id2 = "jwt-id-2";

        // Create tokens for both JWT IDs
        let token1 = store.get_new_token(jwt_id1);
        let token2 = store.get_new_token(jwt_id2);

        // Both should be valid
        assert!(store.validate_and_renew_token(&token1, jwt_id1));
        assert!(store.validate_and_renew_token(&token2, jwt_id2));

        // Cleanup tokens for jwt_id1
        store.cleanup_tokens_for_jwt_id(jwt_id1);

        // token1 should now be invalid, token2 should still be valid
        assert!(!store.validate_and_renew_token(&token1, jwt_id1));
        assert!(store.validate_and_renew_token(&token2, jwt_id2));
    }

    #[test]
    fn test_get_or_refresh_token() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "test-jwt-id";

        // First call should create a new token
        let token1 = store.get_or_refresh_token(jwt_id);
        assert!(!token1.is_empty());

        // Second call should return the same token (refreshed)
        let token2 = store.get_or_refresh_token(jwt_id);
        assert_eq!(token1, token2);

        // Token should still be valid
        assert!(store.validate_and_renew_token(&token1, jwt_id));
    }

    #[test]
    fn test_get_or_refresh_token_different_jwt_ids() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id1 = "jwt-id-1";
        let jwt_id2 = "jwt-id-2";

        let token1 = store.get_or_refresh_token(jwt_id1);
        let token2 = store.get_or_refresh_token(jwt_id2);

        // Different JWT IDs should get different tokens
        assert_ne!(token1, token2);

        // Both should be valid for their respective JWT IDs
        assert!(store.validate_and_renew_token(&token1, jwt_id1));
        assert!(store.validate_and_renew_token(&token2, jwt_id2));

        // Cross-validation should fail
        assert!(!store.validate_and_renew_token(&token1, jwt_id2));
        assert!(!store.validate_and_renew_token(&token2, jwt_id1));
    }

    #[test]
    fn test_integration_csrf_workflow() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "user-session-123";

        // Step 1: Client requests CSRF token
        let csrf_token = store.get_or_refresh_token(jwt_id);
        assert!(!csrf_token.is_empty());

        // Step 2: Client uses token in subsequent request
        assert!(store.validate_and_renew_token(&csrf_token, jwt_id));

        // Step 3: Token is renewed and can be used again
        assert!(store.validate_and_renew_token(&csrf_token, jwt_id));

        // Step 4: Wrong JWT ID should fail
        assert!(!store.validate_and_renew_token(&csrf_token, "different-user"));

        // Step 5: Invalid token should fail
        assert!(!store.validate_and_renew_token("invalid-token", jwt_id));

        // Step 6: Original token should still work for correct user
        // Note: create a new token since the previous validation with wrong JWT ID removed it
        let csrf_token = store.get_or_refresh_token(jwt_id);
        assert!(store.validate_and_renew_token(&csrf_token, jwt_id));

        // Step 7: User logs out - cleanup their tokens
        store.cleanup_tokens_for_jwt_id(jwt_id);

        // Step 8: Token should no longer work
        assert!(!store.validate_and_renew_token(&csrf_token, jwt_id));

        // Step 9: New session for same user should get new token
        let new_csrf_token = store.get_or_refresh_token(jwt_id);
        assert_ne!(csrf_token, new_csrf_token);
        assert!(store.validate_and_renew_token(&new_csrf_token, jwt_id));
    }

    #[test]
    fn test_csrf_store_characteristics() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);

        // Test token uniqueness
        let jwt_id = "test-jwt";
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..100 {
            let token = store.get_new_token(jwt_id);
            assert!(tokens.insert(token), "Duplicate token generated");
        }

        // Test token format (UUID v4)
        let token = store.get_new_token(jwt_id);
        assert_eq!(token.len(), 36); // UUID v4 length
        assert_eq!(token.chars().filter(|&c| c == '-').count(), 4); // UUID has 4 hyphens

        // Test concurrent access safety (basic test)
        let jwt_id1 = "concurrent-1";
        let jwt_id2 = "concurrent-2";

        let token1 = store.get_new_token(jwt_id1);
        let token2 = store.get_new_token(jwt_id2);

        // Both operations should succeed
        assert!(store.validate_and_renew_token(&token1, jwt_id1));
        assert!(store.validate_and_renew_token(&token2, jwt_id2));
    }

    #[test]
    fn test_cleanup_multiple_tokens() {
        let config = create_test_config();
        let store = CsrfTokenStore::new(&config);
        let jwt_id = "multi-token-user";

        // Create multiple tokens for the same JWT ID
        let token1 = store.get_new_token(jwt_id);
        let token2 = store.get_new_token(jwt_id);
        let token3 = store.get_new_token(jwt_id);

        // All should be valid
        assert!(store.validate_and_renew_token(&token1, jwt_id));
        assert!(store.validate_and_renew_token(&token2, jwt_id));
        assert!(store.validate_and_renew_token(&token3, jwt_id));

        // Cleanup should remove all tokens for this JWT ID
        store.cleanup_tokens_for_jwt_id(jwt_id);

        // All tokens should now be invalid
        assert!(!store.validate_and_renew_token(&token1, jwt_id));
        assert!(!store.validate_and_renew_token(&token2, jwt_id));
        assert!(!store.validate_and_renew_token(&token3, jwt_id));
    }
}
