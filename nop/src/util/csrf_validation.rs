// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpMessage, HttpRequest, web::Data};

use crate::iam::middleware::AuthRequest;
use crate::util::CsrfTokenStore;

pub const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// Marker struct to indicate a request has a validated CSRF token
#[derive(Debug, Clone)]
pub struct ValidatedCsrfToken;

/// Validate CSRF token against JWT ID from authenticated user
pub fn validate_csrf_token(csrf_store: &CsrfTokenStore, token: &str, jwt_id: &str) -> bool {
    csrf_store.validate_and_renew_token(token, jwt_id)
}

/// Mark request as having a validated CSRF token
pub fn mark_csrf_validated(req: &HttpRequest) {
    req.extensions_mut().insert(ValidatedCsrfToken);
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn test_mark_csrf_validated() {
        let req = TestRequest::default().to_http_request();

        // Initially should not have validated token
        assert!(req.extensions().get::<ValidatedCsrfToken>().is_none());

        // After marking as validated
        mark_csrf_validated(&req);
        assert!(req.extensions().get::<ValidatedCsrfToken>().is_some());
    }
}
