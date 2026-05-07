// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::codec::{decode_hs256, encode_hs256};
use super::types::{Claims, JwtError};
use crate::types::User;
use chrono::{Duration, Utc};
use nop_config::ValidatedConfig;
use uuid::Uuid;

pub struct JwtService {
    secret: String,
    issuer: String,
    audience: String,
    expiration_hours: u64,
    cookie_name: String,
    is_localhost: bool,
    force_secure_cookie: bool,
    disable_refresh: bool,
    refresh_threshold_percentage: u32,
    refresh_threshold_hours: u64,
}

impl JwtService {
    /// Create a new JwtService from configuration
    pub fn new(config: &ValidatedConfig) -> Result<Self, JwtError> {
        let jwt_config = &config
            .users
            .local()
            .ok_or_else(|| {
                JwtError::Configuration("Local authentication not configured".to_string())
            })?
            .jwt;

        // Check if all main listeners are localhost
        let is_localhost = config.is_localhost_only();

        Ok(JwtService {
            secret: jwt_config.secret.clone(),
            issuer: jwt_config.issuer.clone(),
            audience: jwt_config.audience.clone(),
            expiration_hours: jwt_config.expiration_hours,
            cookie_name: jwt_config.cookie_name.clone(),
            is_localhost,
            force_secure_cookie: jwt_config.force_secure_cookie,
            disable_refresh: jwt_config.disable_refresh,
            refresh_threshold_percentage: jwt_config.refresh_threshold_percentage,
            refresh_threshold_hours: jwt_config.refresh_threshold_hours,
        })
    }

    /// Create a JWT token for a user
    pub fn create_token(&self, email: &str, user: &User) -> Result<String, JwtError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(self.expiration_hours as i64);

        let claims = Claims {
            sub: email.to_string(),
            name: user.name.clone(),
            groups: user.roles.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: Uuid::new_v4().to_string(),
            password_version: user.password_version,
        };

        encode_hs256(&claims, self.secret.as_ref())
    }

    /// Verify a JWT token and return claims
    pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
        decode_hs256(
            token,
            self.secret.as_ref(),
            &self.issuer,
            &self.audience,
            Utc::now().timestamp(),
        )
    }

    /// Create a secure HTTP-only cookie with the JWT token
    pub fn create_auth_cookie<'a>(&self, token: &str) -> actix_web::cookie::Cookie<'a> {
        let expiration = Utc::now() + Duration::hours(self.expiration_hours as i64);

        let expires = match actix_web::cookie::time::OffsetDateTime::from_unix_timestamp(
            expiration.timestamp(),
        ) {
            Ok(val) => val,
            Err(e) => {
                log::error!(
                    "Failed to convert expiration timestamp for auth cookie: {}",
                    e
                );
                actix_web::cookie::time::OffsetDateTime::now_utc()
                    + actix_web::cookie::time::Duration::hours(self.expiration_hours as i64)
            }
        };

        let secure_cookie = if self.force_secure_cookie {
            true
        } else {
            !self.is_localhost
        };

        if secure_cookie {
            // Secure cookie settings
            actix_web::cookie::Cookie::build(self.cookie_name.clone(), token.to_string())
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .expires(expires)
                .finish()
        } else {
            // Localhost: Safari-friendly settings
            actix_web::cookie::Cookie::build(self.cookie_name.clone(), token.to_string())
                .path("/")
                .secure(false) // Allow HTTP on localhost
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax) // Less strict for Safari
                .expires(expires)
                .finish()
        }
    }

    /// Create a cookie for logout (removes the JWT)
    pub fn create_logout_cookie<'a>(&self) -> actix_web::cookie::Cookie<'a> {
        let secure_cookie = if self.force_secure_cookie {
            true
        } else {
            !self.is_localhost
        };

        if secure_cookie {
            // Secure cookie settings
            actix_web::cookie::Cookie::build(self.cookie_name.clone(), "")
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .expires(actix_web::cookie::time::OffsetDateTime::UNIX_EPOCH)
                .finish()
        } else {
            // Localhost: Safari-friendly settings
            actix_web::cookie::Cookie::build(self.cookie_name.clone(), "")
                .path("/")
                .secure(false) // Allow HTTP on localhost
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax) // Less strict for Safari
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .expires(actix_web::cookie::time::OffsetDateTime::UNIX_EPOCH)
                .finish()
        }
    }

    /// Check if a JWT token should be refreshed based on its age and configured thresholds
    pub fn should_refresh_token(&self, claims: &Claims) -> bool {
        // If refresh is disabled, never refresh
        if self.disable_refresh {
            return false;
        }

        let now = Utc::now().timestamp();
        let token_age_seconds = now - claims.iat;
        let token_lifetime_seconds = claims.exp - claims.iat;

        // Convert hours to seconds for comparison
        let token_lifetime_hours = token_lifetime_seconds / 3600;
        let threshold_hours_seconds = self.refresh_threshold_hours * 3600;

        if token_lifetime_hours <= 24 {
            // For tokens with lifetime <= 24 hours: refresh if age > percentage of lifetime
            let threshold_seconds = (token_lifetime_seconds as f64
                * self.refresh_threshold_percentage as f64
                / 100.0) as i64;
            token_age_seconds >= threshold_seconds
        } else {
            // For tokens with lifetime > 24 hours: refresh if age >= threshold hours
            token_age_seconds >= threshold_hours_seconds as i64
        }
    }

    /// Create a refreshed token with the same user info but updated timestamps
    pub fn create_refreshed_token(&self, old_claims: &Claims) -> Result<String, JwtError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(self.expiration_hours as i64);

        let new_claims = Claims {
            sub: old_claims.sub.clone(),
            name: old_claims.name.clone(),
            groups: old_claims.groups.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: Uuid::new_v4().to_string(), // Generate new JWT ID
            password_version: old_claims.password_version,
        };

        encode_hs256(&new_claims, self.secret.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use nop_config::JwtConfig;

    fn create_test_jwt_service(
        expiration_hours: u64,
        refresh_percentage: u32,
        refresh_hours: u64,
    ) -> JwtService {
        let jwt_config = JwtConfig {
            secret: "test-secret-key".to_string(),
            issuer: "test-issuer".to_string(),
            audience: "test-audience".to_string(),
            expiration_hours,
            cookie_name: "test_auth".to_string(),
            force_secure_cookie: false,
            disable_refresh: false,
            refresh_threshold_percentage: refresh_percentage,
            refresh_threshold_hours: refresh_hours,
        };

        JwtService {
            secret: jwt_config.secret,
            issuer: jwt_config.issuer,
            audience: jwt_config.audience,
            expiration_hours: jwt_config.expiration_hours,
            cookie_name: jwt_config.cookie_name,
            is_localhost: true,
            force_secure_cookie: jwt_config.force_secure_cookie,
            disable_refresh: jwt_config.disable_refresh,
            refresh_threshold_percentage: jwt_config.refresh_threshold_percentage,
            refresh_threshold_hours: jwt_config.refresh_threshold_hours,
        }
    }

    fn create_test_claims(iat_hours_ago: i64, exp_hours_from_now: i64) -> Claims {
        let now = Utc::now();
        let iat = (now - Duration::hours(iat_hours_ago)).timestamp();
        let exp = (now + Duration::hours(exp_hours_from_now)).timestamp();

        Claims {
            sub: "test@example.com".to_string(),
            name: "Test User".to_string(),
            groups: vec!["user".to_string()],
            iat,
            exp,
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            jti: "test-jti".to_string(),
            password_version: 1,
        }
    }

    #[test]
    fn test_should_refresh_token_short_lived_fresh_token() {
        let service = create_test_jwt_service(2, 10, 24); // 2 hour expiration, 10% threshold
        let claims = create_test_claims(0, 2); // Just issued, expires in 2 hours

        assert!(!service.should_refresh_token(&claims));
    }

    #[test]
    fn test_should_refresh_token_short_lived_old_token() {
        let service = create_test_jwt_service(2, 10, 24); // 2 hour expiration, 10% threshold
        let claims = create_test_claims(1, 1); // 1 hour old, expires in 1 hour (50% of lifetime)

        assert!(service.should_refresh_token(&claims));
    }

    #[test]
    fn test_should_refresh_token_long_lived_fresh_token() {
        let service = create_test_jwt_service(48, 10, 24); // 48 hour expiration, 24 hour threshold
        let claims = create_test_claims(0, 48); // Just issued, expires in 48 hours

        assert!(!service.should_refresh_token(&claims));
    }

    #[test]
    fn test_should_refresh_token_long_lived_old_token() {
        let service = create_test_jwt_service(48, 10, 24); // 48 hour expiration, 24 hour threshold
        let claims = create_test_claims(25, 23); // 25 hours old, expires in 23 hours

        assert!(service.should_refresh_token(&claims));
    }

    #[test]
    fn test_should_refresh_token_long_lived_at_threshold() {
        let service = create_test_jwt_service(48, 10, 24); // 48 hour expiration, 24 hour threshold
        let claims = create_test_claims(24, 24); // Exactly 24 hours old

        assert!(service.should_refresh_token(&claims));
    }

    #[test]
    fn test_create_refreshed_token() {
        let service = create_test_jwt_service(12, 10, 24);
        let old_claims = create_test_claims(6, 6); // 6 hours old, 6 hours remaining

        let new_token = service.create_refreshed_token(&old_claims).unwrap();
        let new_claims = service.verify_token(&new_token).unwrap();

        // Verify that user info is preserved
        assert_eq!(new_claims.sub, old_claims.sub);
        assert_eq!(new_claims.name, old_claims.name);
        assert_eq!(new_claims.groups, old_claims.groups);

        // Verify that timestamps are updated
        assert!(new_claims.iat > old_claims.iat);
        assert!(new_claims.exp > old_claims.exp);

        // Verify new JWT ID
        assert_ne!(new_claims.jti, old_claims.jti);
        assert_eq!(new_claims.password_version, old_claims.password_version);
    }

    #[test]
    fn test_edge_case_24_hour_boundary() {
        let service = create_test_jwt_service(24, 10, 24); // Exactly 24 hour expiration
        let claims = create_test_claims(2, 22); // 2 hours old, 22 hours remaining (< 10% threshold)

        // Should use percentage-based refresh for exactly 24-hour tokens
        assert!(!service.should_refresh_token(&claims));

        let claims_old = create_test_claims(3, 21); // 3 hours old (> 10% of 24 hours = 2.4 hours)
        assert!(service.should_refresh_token(&claims_old));
    }

    #[test]
    fn test_disable_refresh_functionality() {
        // Create a service with refresh disabled
        let jwt_config = JwtConfig {
            secret: "test-secret-key".to_string(),
            issuer: "test-issuer".to_string(),
            audience: "test-audience".to_string(),
            expiration_hours: 2,
            cookie_name: "test_auth".to_string(),
            force_secure_cookie: false,
            disable_refresh: true, // Refresh disabled
            refresh_threshold_percentage: 10,
            refresh_threshold_hours: 24,
        };

        let service = JwtService {
            secret: jwt_config.secret,
            issuer: jwt_config.issuer,
            audience: jwt_config.audience,
            expiration_hours: jwt_config.expiration_hours,
            cookie_name: jwt_config.cookie_name,
            is_localhost: true,
            force_secure_cookie: jwt_config.force_secure_cookie,
            disable_refresh: jwt_config.disable_refresh,
            refresh_threshold_percentage: jwt_config.refresh_threshold_percentage,
            refresh_threshold_hours: jwt_config.refresh_threshold_hours,
        };

        // Test with old tokens that would normally trigger refresh
        let claims_short = create_test_claims(1, 1); // 50% of lifetime passed
        let claims_long = create_test_claims(25, 23); // > 24 hours old

        // Both should return false since refresh is disabled
        assert!(!service.should_refresh_token(&claims_short));
        assert!(!service.should_refresh_token(&claims_long));
    }

    #[test]
    fn test_localhost_auth_cookie_not_secure_by_default() {
        let service = create_test_jwt_service(12, 10, 24);
        let cookie = service.create_auth_cookie("token");
        assert!(!cookie.secure().unwrap_or(false));
    }

    #[test]
    fn test_force_secure_cookie_overrides_localhost() {
        let mut service = create_test_jwt_service(12, 10, 24);
        service.force_secure_cookie = true;
        let cookie = service.create_auth_cookie("token");
        assert!(cookie.secure().unwrap_or(false));
    }

    #[test]
    fn test_non_localhost_auth_cookie_is_secure() {
        let mut service = create_test_jwt_service(12, 10, 24);
        service.is_localhost = false;
        let cookie = service.create_auth_cookie("token");
        assert!(cookie.secure().unwrap_or(false));
    }
}
