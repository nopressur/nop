// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_http::Request;
use actix_web::body::BoxBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{http::StatusCode, test};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use nop::iam::derive_front_end_hash;
use nop::iam::jwt::Claims;
use nop::login::types::{
    LoginBootstrapRequest, LoginBootstrapResponse, LoginErrorResponse, LoginSuccessResponse,
    PasswordEmailRequest, PasswordEmailResponse, PasswordLoginRequest,
    ProfilePasswordChangeRequest, ProfilePasswordSaltResponse, ProfileUpdateRequest,
};
use nop::util::csrf_validation::CSRF_HEADER_NAME;
use serde_json::Value;
use uuid::Uuid;

const TEST_PEER_ADDR: &str = "127.0.0.1:1234";
const LOGIN_CONFIG_MARKER: &str = "window.nopLoginConfig = ";

fn extract_login_config(body: &[u8]) -> Value {
    let text = std::str::from_utf8(body).expect("login html");
    let start =
        text.find(LOGIN_CONFIG_MARKER).expect("login config marker") + LOGIN_CONFIG_MARKER.len();
    let remainder = &text[start..];
    let end = remainder.find(';').expect("login config end");
    let json = &remainder[..end].trim();
    serde_json::from_str(json).expect("login config json")
}

async fn login_bootstrap<S>(app: &S, return_path: Option<&str>) -> LoginBootstrapResponse
where
    S: Service<Request, Response = ServiceResponse<BoxBody>, Error = actix_web::Error>,
{
    let payload = LoginBootstrapRequest {
        return_path: return_path.map(|path| path.to_string()),
    };
    let req = test::TestRequest::post()
        .uri("/login/bootstrap")
        .set_json(&payload)
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    serde_json::from_slice(&body).expect("bootstrap json")
}

async fn password_email<S>(app: &S, login_session_id: &str, email: &str) -> PasswordEmailResponse
where
    S: Service<Request, Response = ServiceResponse<BoxBody>, Error = actix_web::Error>,
{
    let payload = PasswordEmailRequest {
        login_session_id: login_session_id.to_string(),
        email: email.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/login/pwd/email")
        .set_json(&payload)
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    serde_json::from_slice(&body).expect("salt json")
}

async fn password_login<S>(
    app: &S,
    login_session_id: &str,
    email: &str,
    front_end_hash: &str,
) -> ServiceResponse<BoxBody>
where
    S: Service<Request, Response = ServiceResponse<BoxBody>, Error = actix_web::Error>,
{
    let payload = PasswordLoginRequest {
        login_session_id: login_session_id.to_string(),
        email: email.to_string(),
        front_end_hash: front_end_hash.to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/login/pwd/password")
        .set_json(&payload)
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .to_request();
    test::call_service(app, req).await
}

#[actix_web::test]
async fn login_success_sets_cookie_and_returns_path() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let bootstrap = login_bootstrap(&app, Some("/admin")).await;
    let salt = password_email(&app, &bootstrap.login_session_id, common::ADMIN_EMAIL).await;
    let params = &harness
        .config
        .users
        .local()
        .expect("local auth config")
        .password
        .front_end;
    let front_end_hash = derive_front_end_hash(
        &harness.admin_password_plaintext,
        &salt.front_end_salt,
        params,
    )
    .expect("front end hash");

    let resp = password_login(
        &app,
        &bootstrap.login_session_id,
        common::ADMIN_EMAIL,
        &front_end_hash,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("set-cookie"));
    let body = test::read_body(resp).await;
    let json: LoginSuccessResponse = serde_json::from_slice(&body).expect("login response");
    assert_eq!(json.return_path, "/admin");
}

#[actix_web::test]
async fn login_invalid_credentials_returns_error() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let bootstrap = login_bootstrap(&app, Some("/admin")).await;
    let salt = password_email(&app, &bootstrap.login_session_id, common::ADMIN_EMAIL).await;
    let params = &harness
        .config
        .users
        .local()
        .expect("local auth config")
        .password
        .front_end;
    let front_end_hash = derive_front_end_hash("wrong-password", &salt.front_end_salt, params)
        .expect("front end hash");

    let resp = password_login(
        &app,
        &bootstrap.login_session_id,
        common::ADMIN_EMAIL,
        &front_end_hash,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = test::read_body(resp).await;
    let json: LoginErrorResponse = serde_json::from_slice(&body).expect("error response");
    assert_eq!(json.code, "invalid_credentials");
}

#[actix_web::test]
async fn login_rejects_unsafe_return_paths() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let params = &harness
        .config
        .users
        .local()
        .expect("local auth config")
        .password
        .front_end;

    let bootstrap = login_bootstrap(&app, Some("//evil.example")).await;
    let salt = password_email(&app, &bootstrap.login_session_id, common::ADMIN_EMAIL).await;
    let front_end_hash = derive_front_end_hash(
        &harness.admin_password_plaintext,
        &salt.front_end_salt,
        params,
    )
    .expect("front end hash");
    let resp = password_login(
        &app,
        &bootstrap.login_session_id,
        common::ADMIN_EMAIL,
        &front_end_hash,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: LoginSuccessResponse = serde_json::from_slice(&body).expect("login response");
    assert_eq!(json.return_path, "/admin");

    let bootstrap = login_bootstrap(&app, Some("/assets/sample.bin")).await;
    let salt = password_email(&app, &bootstrap.login_session_id, common::ADMIN_EMAIL).await;
    let front_end_hash = derive_front_end_hash(
        &harness.admin_password_plaintext,
        &salt.front_end_salt,
        params,
    )
    .expect("front end hash");
    let resp = password_login(
        &app,
        &bootstrap.login_session_id,
        common::ADMIN_EMAIL,
        &front_end_hash,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: LoginSuccessResponse = serde_json::from_slice(&body).expect("login response");
    assert_eq!(json.return_path, "/admin");
}

#[actix_web::test]
async fn logout_clears_cookie_without_refresh() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let jwt_service = harness.user_services.jwt_service().expect("jwt service");
    let local_config = harness.config.users.local().expect("local auth config");
    let now = Utc::now();
    let claims = Claims {
        sub: harness.admin_user.email.clone(),
        name: harness.admin_user.name.clone(),
        groups: harness.admin_user.roles.clone(),
        iat: (now - Duration::hours(2)).timestamp(),
        exp: (now + Duration::hours(10)).timestamp(),
        iss: local_config.jwt.issuer.clone(),
        aud: local_config.jwt.audience.clone(),
        jti: Uuid::new_v4().to_string(),
        password_version: harness.admin_user.password_version,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(local_config.jwt.secret.as_ref()),
    )
    .expect("token");
    let cookie = jwt_service.create_auth_cookie(&token).into_owned();

    let req = test::TestRequest::post()
        .uri("/login/logout-api")
        .cookie(cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let auth_cookies: Vec<_> = resp
        .response()
        .cookies()
        .filter(|cookie| cookie.name() == local_config.jwt.cookie_name)
        .collect();
    assert!(!auth_cookies.is_empty());
    assert!(auth_cookies.iter().all(|cookie| cookie.value().is_empty()));
}

#[actix_web::test]
async fn profile_return_path_rejects_external() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let session = harness.admin_auth();

    let req = test::TestRequest::get()
        .uri("/login/profile?return_path=//evil.example")
        .cookie(session.cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    let config = extract_login_config(&body);
    let return_path = config.get("returnPath").and_then(|value| value.as_str());
    assert!(return_path.is_none());
}

#[actix_web::test]
async fn csrf_token_api_requires_auth() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::post()
        .uri("/admin/csrf-token-api")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get("Location")
        .expect("location header")
        .to_str()
        .expect("location string");
    assert!(location.contains("/login"));

    let session = harness.admin_auth();
    let req = test::TestRequest::post()
        .uri("/admin/csrf-token-api")
        .cookie(session.cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("json body");
    let token = json
        .get("csrf_token")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(!token.is_empty());
}

#[actix_web::test]
async fn profile_update_refreshes_jwt_and_requires_new_csrf() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let session = harness.admin_auth();
    let csrf_req = test::TestRequest::post()
        .uri("/login/csrf-token-api")
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(session.cookie.clone())
        .to_request();
    let csrf_resp = test::call_service(&app, csrf_req).await;
    assert_eq!(csrf_resp.status(), StatusCode::OK);
    let body = test::read_body(csrf_resp).await;
    let json: Value = serde_json::from_slice(&body).expect("csrf json");
    let initial_csrf = json
        .get("csrf_token")
        .and_then(|value| value.as_str())
        .expect("csrf token")
        .to_string();

    let update = ProfileUpdateRequest {
        name: "Admin Updated".to_string(),
    };
    let req = test::TestRequest::post()
        .uri("/profile/update")
        .set_json(&update)
        .insert_header((CSRF_HEADER_NAME, initial_csrf.clone()))
        .cookie(session.cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let refreshed_cookie = resp
        .response()
        .cookies()
        .next()
        .expect("refreshed cookie")
        .to_owned();

    let jwt_service = harness.user_services.jwt_service().expect("jwt service");
    let refreshed_claims = jwt_service
        .verify_token(refreshed_cookie.value())
        .expect("claims");
    assert_ne!(refreshed_claims.jti, session.jwt_id);

    let blocked = test::TestRequest::post()
        .uri("/profile/update")
        .set_json(&ProfileUpdateRequest {
            name: "Admin Updated Again".to_string(),
        })
        .insert_header((CSRF_HEADER_NAME, initial_csrf))
        .cookie(refreshed_cookie.clone())
        .to_request();
    let blocked_resp = test::try_call_service(&app, blocked).await;
    let blocked_err = blocked_resp.expect_err("expected csrf rejection");
    assert_eq!(blocked_err.error_response().status(), StatusCode::FORBIDDEN);

    let csrf_req = test::TestRequest::post()
        .uri("/login/csrf-token-api")
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(refreshed_cookie.clone())
        .to_request();
    let csrf_resp = test::call_service(&app, csrf_req).await;
    assert_eq!(csrf_resp.status(), StatusCode::OK);
    let body = test::read_body(csrf_resp).await;
    let json: Value = serde_json::from_slice(&body).expect("csrf json");
    let refreshed_csrf = json
        .get("csrf_token")
        .and_then(|value| value.as_str())
        .expect("csrf token")
        .to_string();

    let final_req = test::TestRequest::post()
        .uri("/profile/update")
        .set_json(&ProfileUpdateRequest {
            name: "Admin Updated Final".to_string(),
        })
        .insert_header((CSRF_HEADER_NAME, refreshed_csrf))
        .cookie(refreshed_cookie)
        .to_request();
    let final_resp = test::call_service(&app, final_req).await;
    assert_eq!(final_resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn profile_password_change_invalidates_change_token() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let session = harness.admin_auth();
    let params = &harness
        .config
        .users
        .local()
        .expect("local auth config")
        .password
        .front_end;

    let salt_req = test::TestRequest::post()
        .uri("/profile/pwd/salt")
        .insert_header((CSRF_HEADER_NAME, session.csrf_token.clone()))
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(session.cookie.clone())
        .to_request();
    let salt_resp = test::call_service(&app, salt_req).await;
    assert_eq!(salt_resp.status(), StatusCode::OK);
    let salt_body = test::read_body(salt_resp).await;
    let salt: ProfilePasswordSaltResponse =
        serde_json::from_slice(&salt_body).expect("salt response");

    let current_front_end_hash = derive_front_end_hash(
        &harness.admin_password_plaintext,
        &salt.current.front_end_salt,
        params,
    )
    .expect("current hash");
    let new_password = "admin-password-updated";
    let new_front_end_hash =
        derive_front_end_hash(new_password, &salt.next.front_end_salt, params).expect("new hash");

    let change_payload = ProfilePasswordChangeRequest {
        change_token: salt.change_token.clone(),
        current_front_end_hash,
        new_front_end_hash,
        new_front_end_salt: salt.next.front_end_salt.clone(),
    };
    let change_req = test::TestRequest::post()
        .uri("/profile/pwd/change")
        .set_json(&change_payload)
        .insert_header((CSRF_HEADER_NAME, session.csrf_token.clone()))
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(session.cookie.clone())
        .to_request();
    let change_resp = test::call_service(&app, change_req).await;
    assert_eq!(change_resp.status(), StatusCode::OK);
    let refreshed_cookie = change_resp
        .response()
        .cookies()
        .next()
        .expect("refreshed cookie")
        .to_owned();

    let csrf_req = test::TestRequest::post()
        .uri("/login/csrf-token-api")
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(refreshed_cookie.clone())
        .to_request();
    let csrf_resp = test::call_service(&app, csrf_req).await;
    assert_eq!(csrf_resp.status(), StatusCode::OK);
    let body = test::read_body(csrf_resp).await;
    let json: Value = serde_json::from_slice(&body).expect("csrf json");
    let refreshed_csrf = json
        .get("csrf_token")
        .and_then(|value| value.as_str())
        .expect("csrf token");

    let retry_req = test::TestRequest::post()
        .uri("/profile/pwd/change")
        .set_json(&change_payload)
        .insert_header((CSRF_HEADER_NAME, refreshed_csrf))
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(refreshed_cookie)
        .to_request();
    let retry_resp = test::call_service(&app, retry_req).await;
    assert_eq!(retry_resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn ws_ticket_requires_csrf_and_auth() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::post()
        .uri("/admin/ws-ticket")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let session = harness.admin_auth();
    let req = test::TestRequest::post()
        .uri("/admin/ws-ticket")
        .cookie(session.cookie)
        .to_request();
    let resp = test::try_call_service(&app, req).await;
    let err = resp.expect_err("expected csrf rejection");
    assert_eq!(err.error_response().status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn ws_ticket_returns_ticket_for_valid_request() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let session = harness.admin_auth();

    let req = test::TestRequest::post()
        .uri("/admin/ws-ticket")
        .insert_header((CSRF_HEADER_NAME, session.csrf_token))
        .peer_addr(TEST_PEER_ADDR.parse().expect("peer addr"))
        .cookie(session.cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("ticket json");
    let ticket = json
        .get("ticket")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(!ticket.is_empty());
}
