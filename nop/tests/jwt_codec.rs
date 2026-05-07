// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use nop_rt_iam::jwt::{Claims, JwtService};
use nop_testing::test_config::TestConfigBuilder;
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SECRET: &[u8] = b"test-secret";
const ISSUER: &str = "nopressure";
const AUDIENCE: &str = "nopressure-users";
const NOW: i64 = 1_700_000_000;
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_SEGMENT_BYTES: usize = 1024;
const MAX_PAYLOAD_SEGMENT_BYTES: usize = 6144;
const MAX_SIGNATURE_SEGMENT_BYTES: usize = 512;
const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Serialize)]
struct Header<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
    alg: &'a str,
}

fn service() -> JwtService {
    JwtService::new(&TestConfigBuilder::new().build()).expect("jwt service")
}

fn claims() -> Claims {
    Claims {
        sub: "user@example.com".to_string(),
        name: "Test User".to_string(),
        groups: vec!["admin".to_string()],
        iat: NOW,
        exp: 4_102_444_800,
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password_version: 1,
    }
}

fn token(header_json: &str, payload_json: &str, secret: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    sign_segments(&header, &payload, secret)
}

fn sign_segments(header: &str, payload: &str, secret: &[u8]) -> String {
    let signing_input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

fn non_canonical_signature_token(token: &str) -> String {
    let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
    let signature = parts.get_mut(2).expect("signature segment");
    let last = signature.pop().expect("signature last char");
    let index = BASE64URL_ALPHABET
        .iter()
        .position(|candidate| *candidate == last as u8)
        .expect("base64url char");
    assert_eq!(index & 0b11, 0, "canonical 32-byte signature suffix");
    signature.push(BASE64URL_ALPHABET[index | 0b01] as char);
    parts.join(".")
}

fn valid_payload() -> String {
    serde_json::to_string(&claims()).expect("claims json")
}

fn valid_token() -> String {
    let header = serde_json::to_string(&Header {
        typ: Some("JWT"),
        alg: "HS256",
    })
    .expect("header json");
    token(&header, &valid_payload(), SECRET)
}

#[test]
fn jwt_service_verifies_valid_hs256_token() {
    let claims = service()
        .verify_token(&valid_token())
        .expect("claims should verify");

    assert_eq!(claims.sub, "user@example.com");
    assert_eq!(claims.groups, vec!["admin".to_string()]);
    assert_eq!(claims.jti, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn jwt_service_rejects_malformed_compact_tokens() {
    for token in [
        "",
        "one",
        "one.two",
        "one.two.three.four",
        ".two.three",
        "one..three",
        "one.two.",
        "one two.three.four",
        "one\ntwo.three.four",
        "one=.two.three",
        "one/two.three.four",
    ] {
        assert!(
            service().verify_token(token).is_err(),
            "token should fail: {token:?}",
        );
    }
}

#[test]
fn jwt_service_rejects_oversize_tokens_and_segments() {
    let cases = [
        "a".repeat(MAX_TOKEN_BYTES + 1),
        format!("{}.b.c", "a".repeat(MAX_HEADER_SEGMENT_BYTES + 1)),
        format!("a.{}.c", "b".repeat(MAX_PAYLOAD_SEGMENT_BYTES + 1)),
        format!("a.b.{}", "c".repeat(MAX_SIGNATURE_SEGMENT_BYTES + 1)),
    ];

    for token in cases {
        assert!(service().verify_token(&token).is_err());
    }
}

#[test]
fn jwt_service_rejects_invalid_base64url_and_json_bytes() {
    let valid = valid_token();
    let parts = valid.split('.').collect::<Vec<_>>();

    let padded_header = format!("{}=.{}.{}", parts[0], parts[1], parts[2]);
    assert!(service().verify_token(&padded_header).is_err());

    let invalid_alphabet = format!("{}/.{}.{}", parts[0], parts[1], parts[2]);
    assert!(service().verify_token(&invalid_alphabet).is_err());

    let invalid_utf8_header = sign_segments("_w", parts[1], SECRET);
    assert!(service().verify_token(&invalid_utf8_header).is_err());
}

#[test]
fn jwt_service_rejects_defensive_header_failures() {
    let payload = valid_payload();
    for header in [
        r#"{"typ":"JWT"}"#,
        r#"{"typ":"JWT","alg":"none"}"#,
        r#"{"typ":"JWT","alg":"RS256"}"#,
        r#"{"typ":"JWS","alg":"HS256"}"#,
        r#"{"typ":"JWT","alg":"HS256","kid":"key"}"#,
        r#"{"typ":"JWT","alg":"HS256","crit":[]}"#,
        r#"{"typ":"JWT","alg":"HS256","cty":"JWT"}"#,
        r#"{"typ":"JWT","alg":"HS256","jku":"https://example.test/jwks"}"#,
        r#"{"typ":"JWT","alg":"HS256","jwk":{}}"#,
        r#"{"typ":"JWT","alg":"HS256","x5u":"https://example.test/cert"}"#,
        r#"{"typ":"JWT","alg":"HS256","x5c":[]}"#,
        r#"{"typ":"JWT","alg":"HS256","x5t":"thumbprint"}"#,
        r#"{"typ":"JWT","alg":"HS256","x5t#S256":"thumbprint"}"#,
        r#"{"typ":"JWT","alg":"HS256","alg":"HS256"}"#,
        r#"{"typ":"JWT","alg":123}"#,
        r#"{"typ":123,"alg":"HS256"}"#,
    ] {
        let token = token(header, &payload, SECRET);
        assert!(
            service().verify_token(&token).is_err(),
            "header should fail: {header}",
        );
    }
}

#[test]
fn jwt_service_rejects_signature_tampering() {
    let valid = valid_token();
    let mut parts = valid.split('.').collect::<Vec<_>>();
    parts[1] = "e30";
    assert!(service().verify_token(&parts.join(".")).is_err());

    let mut parts = valid.split('.').collect::<Vec<_>>();
    parts[2] = "AAAA";
    assert!(service().verify_token(&parts.join(".")).is_err());

    let wrong_secret = token(
        r#"{"typ":"JWT","alg":"HS256"}"#,
        &valid_payload(),
        b"wrong-secret",
    );
    assert!(service().verify_token(&wrong_secret).is_err());
}

#[test]
fn jwt_service_rejects_non_canonical_base64url_signature() {
    let token = non_canonical_signature_token(&valid_token());
    assert!(service().verify_token(&token).is_err());
}

#[test]
fn jwt_service_rejects_defensive_claim_failures() {
    let too_many_groups = (0..128)
        .map(|index| format!(r#""role-{index}""#))
        .collect::<Vec<_>>()
        .join(",");
    let excessive_groups = format!(
        r#"{{"sub":"user@example.com","name":"Test User","groups":[{too_many_groups}],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}}"#,
    );
    let excessive_subject = format!(
        r#"{{"sub":"{}@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}}"#,
        "a".repeat(1000),
    );
    let excessive_name = format!(
        r#"{{"sub":"user@example.com","name":"{}","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}}"#,
        "a".repeat(1000),
    );
    let payloads = [
        r#"{"name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1,"extra":true}"#.to_string(),
        r#"{"sub":"user@example.com","sub":"other@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":"1700000000","exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1,"nbf":1700000000}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"wrong","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"wrong","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"not-a-uuid","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":0}"#.to_string(),
        r#"{"sub":"","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":[""],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":1700000000,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":4102444800,"exp":4102448400,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#.to_string(),
        excessive_groups,
        excessive_subject,
        excessive_name,
    ];

    for payload in payloads {
        let token = token(r#"{"typ":"JWT","alg":"HS256"}"#, &payload, SECRET);
        assert!(
            service().verify_token(&token).is_err(),
            "payload should fail: {payload}",
        );
    }
}

#[test]
fn jwt_service_applies_expiration_leeway() {
    let now = Utc::now().timestamp();
    let within_leeway = Claims {
        iat: now - 3600,
        exp: now - 30,
        ..claims()
    };
    let within_leeway_token = token(
        r#"{"typ":"JWT","alg":"HS256"}"#,
        &serde_json::to_string(&within_leeway).expect("claims json"),
        SECRET,
    );
    assert!(service().verify_token(&within_leeway_token).is_ok());

    let beyond_leeway = Claims {
        iat: now - 3600,
        exp: now - 61,
        ..claims()
    };
    let beyond_leeway_token = token(
        r#"{"typ":"JWT","alg":"HS256"}"#,
        &serde_json::to_string(&beyond_leeway).expect("claims json"),
        SECRET,
    );
    assert!(service().verify_token(&beyond_leeway_token).is_err());
}

#[test]
fn jwt_service_accepts_defensive_claim_baseline() {
    for payload in [
        r#"{"sub":"user@example.com","name":"A","groups":[],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#,
        r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000","password_version":1}"#,
    ] {
        let token = token(r#"{"typ":"JWT","alg":"HS256"}"#, payload, SECRET);
        assert!(
            service().verify_token(&token).is_ok(),
            "payload should verify: {payload}",
        );
    }
}

#[test]
fn jwt_service_accepts_legacy_token_without_password_version() {
    let payload = r#"{"sub":"user@example.com","name":"Test User","groups":["admin"],"iat":1700000000,"exp":4102444800,"iss":"nopressure","aud":"nopressure-users","jti":"550e8400-e29b-41d4-a716-446655440000"}"#;
    let token = token(r#"{"typ":"JWT","alg":"HS256"}"#, payload, SECRET);
    let claims = service().verify_token(&token).expect("claims");

    assert_eq!(claims.password_version, 1);
}

#[test]
fn jwt_service_verifies_legacy_jsonwebtoken_hs256_fixture() {
    // Fixture generated with the previous jsonwebtoken HS256 implementation:
    //
    // rm -rf /tmp/nop-jwt-fixture && cargo new --bin /tmp/nop-jwt-fixture
    // cd /tmp/nop-jwt-fixture
    // cargo add jsonwebtoken@10.3.0 --features rust_crypto
    // cargo add serde@1 --features derive
    // cat > src/main.rs <<'RS'
    // use jsonwebtoken::{encode, EncodingKey, Header};
    // use serde::Serialize;
    //
    // #[derive(Serialize)]
    // struct Claims {
    //     sub: &'static str,
    //     name: &'static str,
    //     groups: Vec<&'static str>,
    //     iat: i64,
    //     exp: i64,
    //     iss: &'static str,
    //     aud: &'static str,
    //     jti: &'static str,
    //     password_version: u32,
    // }
    //
    // fn main() {
    //     let claims = Claims {
    //         sub: "fixture@example.com",
    //         name: "Fixture User",
    //         groups: vec!["admin", "editor"],
    //         iat: 1_700_000_000,
    //         exp: 4_102_444_800,
    //         iss: "nopressure",
    //         aud: "nopressure-users",
    //         jti: "550e8400-e29b-41d4-a716-446655440001",
    //         password_version: 7,
    //     };
    //     println!(
    //         "{}",
    //         encode(
    //             &Header::default(),
    //             &claims,
    //             &EncodingKey::from_secret(b"test-secret"),
    //         )
    //         .expect("fixture token")
    //     );
    // }
    // RS
    // cargo run --quiet
    let token = concat!(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.",
        "eyJzdWIiOiJmaXh0dXJlQGV4YW1wbGUuY29tIiwibmFtZSI6IkZpeHR1cmUgVXNlciIs",
        "Imdyb3VwcyI6WyJhZG1pbiIsImVkaXRvciJdLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6",
        "NDEwMjQ0NDgwMCwiaXNzIjoibm9wcmVzc3VyZSIsImF1ZCI6Im5vcHJlc3N1cmUtdXNlcnMi",
        "LCJqdGkiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDEiLCJwYXNzd29y",
        "ZF92ZXJzaW9uIjo3fQ.",
        "Qjgx8XpP971G-1I6ItTd5qBX-ch0W_8RHUz5v1dtHTM",
    );

    let claims = service().verify_token(token).expect("claims");

    assert_eq!(claims.sub, "fixture@example.com");
    assert_eq!(
        claims.groups,
        vec!["admin".to_string(), "editor".to_string()]
    );
    assert_eq!(claims.password_version, 7);
}

#[test]
fn hs256_signature_matches_rfc_7515_known_answer() {
    // RFC 7515 Appendix A.1 JWS HMAC SHA-256 example.
    let signing_input = concat!(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    );
    let key = URL_SAFE_NO_PAD
        .decode(concat!(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQ",
            "Lr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        ))
        .expect("rfc key");
    let mut mac = HmacSha256::new_from_slice(&key).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();

    assert_eq!(
        URL_SAFE_NO_PAD.encode(signature),
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
}
