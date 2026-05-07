// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::CsrfTokenStore;
use actix_web::{HttpMessage, HttpRequest};

pub const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

#[derive(Clone, Debug)]
pub struct ValidatedCsrfToken;

pub fn validate_csrf_token(csrf_store: &CsrfTokenStore, token_value: &str, jwt_id: &str) -> bool {
    csrf_store.validate_and_renew_token(token_value, jwt_id)
}

pub fn mark_csrf_validated(req: &HttpRequest) {
    req.extensions_mut().insert(ValidatedCsrfToken);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mark_csrf_validated() {
        let req = actix_web::test::TestRequest::default().to_http_request();
        mark_csrf_validated(&req);
        let extensions = req.extensions();
        let validated = extensions.get::<ValidatedCsrfToken>();
        assert!(validated.is_some());
    }
}
