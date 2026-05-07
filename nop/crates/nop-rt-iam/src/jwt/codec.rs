// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use nop_library::{MAX_EMAIL_CHARS, MAX_NAME_CHARS};
use nop_roles::{MAX_ROLE_CHARS, MAX_ROLE_COUNT};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use sha2::Sha256;
use uuid::Uuid;

use super::types::{Claims, JwtError};
use crate::types::DEFAULT_PASSWORD_VERSION;

type HmacSha256 = Hmac<Sha256>;

const JWT_LEEWAY_SECONDS: i64 = 60;
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_SEGMENT_BYTES: usize = 1024;
const MAX_PAYLOAD_SEGMENT_BYTES: usize = 6144;
const MAX_SIGNATURE_SEGMENT_BYTES: usize = 512;
const MAX_HEADER_JSON_BYTES: usize = 768;
const MAX_PAYLOAD_JSON_BYTES: usize = 4096;
const HS256_SIGNATURE_BYTES: usize = 32;

#[derive(Debug, PartialEq, Eq)]
struct JwtHeader {
    typ: Option<String>,
    alg: String,
}

impl Serialize for JwtHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("JwtHeader", 2)?;
        if let Some(typ) = &self.typ {
            state.serialize_field("typ", typ)?;
        }
        state.serialize_field("alg", &self.alg)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for JwtHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JwtHeaderVisitor)
    }
}

struct JwtHeaderVisitor;

impl<'de> Visitor<'de> for JwtHeaderVisitor {
    type Value = JwtHeader;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JWT header object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut typ = None::<String>;
        let mut alg = None::<String>;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "typ" => {
                    if typ.is_some() {
                        return Err(de::Error::duplicate_field("typ"));
                    }
                    typ = Some(map.next_value()?);
                }
                "alg" => {
                    if alg.is_some() {
                        return Err(de::Error::duplicate_field("alg"));
                    }
                    alg = Some(map.next_value()?);
                }
                _ => return Err(de::Error::unknown_field(&key, &["typ", "alg"])),
            }
        }

        Ok(JwtHeader {
            typ,
            alg: alg.ok_or_else(|| de::Error::missing_field("alg"))?,
        })
    }
}

impl JwtHeader {
    fn new_hs256() -> Self {
        Self {
            typ: Some("JWT".to_string()),
            alg: "HS256".to_string(),
        }
    }

    fn validate(&self) -> Result<(), JwtError> {
        if self.alg != "HS256" {
            return Err(verification_error("unsupported jwt algorithm"));
        }
        if self.typ.as_deref().is_some_and(|typ| typ != "JWT") {
            return Err(verification_error("invalid jwt header"));
        }
        Ok(())
    }
}

struct WireClaims(Claims);

impl Serialize for WireClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let claims = &self.0;
        let mut state = serializer.serialize_struct("Claims", 9)?;
        state.serialize_field("sub", &claims.sub)?;
        state.serialize_field("name", &claims.name)?;
        state.serialize_field("groups", &claims.groups)?;
        state.serialize_field("iat", &claims.iat)?;
        state.serialize_field("exp", &claims.exp)?;
        state.serialize_field("iss", &claims.iss)?;
        state.serialize_field("aud", &claims.aud)?;
        state.serialize_field("jti", &claims.jti)?;
        state.serialize_field("password_version", &claims.password_version)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for WireClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(WireClaimsVisitor)
    }
}

struct WireClaimsVisitor;

impl<'de> Visitor<'de> for WireClaimsVisitor {
    type Value = WireClaims;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JWT claims object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut sub = None::<String>;
        let mut name = None::<String>;
        let mut groups = None::<Vec<String>>;
        let mut iat = None::<i64>;
        let mut exp = None::<i64>;
        let mut iss = None::<String>;
        let mut aud = None::<String>;
        let mut jti = None::<String>;
        let mut password_version = None::<u32>;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "sub" => assign_once(&mut sub, map.next_value()?, "sub")?,
                "name" => assign_once(&mut name, map.next_value()?, "name")?,
                "groups" => assign_once(&mut groups, map.next_value()?, "groups")?,
                "iat" => assign_once(&mut iat, map.next_value()?, "iat")?,
                "exp" => assign_once(&mut exp, map.next_value()?, "exp")?,
                "iss" => assign_once(&mut iss, map.next_value()?, "iss")?,
                "aud" => assign_once(&mut aud, map.next_value()?, "aud")?,
                "jti" => assign_once(&mut jti, map.next_value()?, "jti")?,
                "password_version" => {
                    assign_once(&mut password_version, map.next_value()?, "password_version")?
                }
                _ => {
                    return Err(de::Error::unknown_field(
                        &key,
                        &[
                            "sub",
                            "name",
                            "groups",
                            "iat",
                            "exp",
                            "iss",
                            "aud",
                            "jti",
                            "password_version",
                        ],
                    ));
                }
            }
        }

        Ok(WireClaims(Claims {
            sub: sub.ok_or_else(|| de::Error::missing_field("sub"))?,
            name: name.ok_or_else(|| de::Error::missing_field("name"))?,
            groups: groups.ok_or_else(|| de::Error::missing_field("groups"))?,
            iat: iat.ok_or_else(|| de::Error::missing_field("iat"))?,
            exp: exp.ok_or_else(|| de::Error::missing_field("exp"))?,
            iss: iss.ok_or_else(|| de::Error::missing_field("iss"))?,
            aud: aud.ok_or_else(|| de::Error::missing_field("aud"))?,
            jti: jti.ok_or_else(|| de::Error::missing_field("jti"))?,
            password_version: password_version.unwrap_or(DEFAULT_PASSWORD_VERSION),
        }))
    }
}

fn assign_once<T, E>(target: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if target.is_some() {
        return Err(de::Error::duplicate_field(field));
    }
    *target = Some(value);
    Ok(())
}

pub(crate) fn encode_hs256(claims: &Claims, secret: &[u8]) -> Result<String, JwtError> {
    let header = serialize_segment(&JwtHeader::new_hs256())?;
    let payload = serialize_segment(&WireClaims(claims.clone()))?;
    let signing_input = format!("{header}.{payload}");
    let signature = sign_hs256(signing_input.as_bytes(), secret)?;
    Ok(format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub(crate) fn decode_hs256(
    token: &str,
    secret: &[u8],
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<Claims, JwtError> {
    let parts = parse_compact_token(token)?;
    let header_bytes = decode_segment(parts.header, MAX_HEADER_JSON_BYTES)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| verification_error("invalid jwt header"))?;
    header.validate()?;

    let signature = decode_segment(parts.signature, HS256_SIGNATURE_BYTES)?;
    if signature.len() != HS256_SIGNATURE_BYTES {
        return Err(verification_error("invalid jwt signature"));
    }

    let signing_input = format!("{}.{}", parts.header, parts.payload);
    verify_hs256(signing_input.as_bytes(), secret, &signature)?;

    let payload_bytes = decode_segment(parts.payload, MAX_PAYLOAD_JSON_BYTES)?;
    let claims = serde_json::from_slice::<WireClaims>(&payload_bytes)
        .map_err(|_| verification_error("invalid jwt claims"))?
        .0;
    validate_claims(&claims, issuer, audience, now)?;
    Ok(claims)
}

fn serialize_segment<T: Serialize>(value: &T) -> Result<String, JwtError> {
    let json = serde_json::to_vec(value).map_err(|err| creation_error(err.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

struct CompactToken<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

fn parse_compact_token(token: &str) -> Result<CompactToken<'_>, JwtError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(verification_error("token too large"));
    }
    if token
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(verification_error("invalid token character"));
    }

    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return Err(verification_error("invalid token structure"));
    };
    let Some(payload) = parts.next() else {
        return Err(verification_error("invalid token structure"));
    };
    let Some(signature) = parts.next() else {
        return Err(verification_error("invalid token structure"));
    };
    if parts.next().is_some() {
        return Err(verification_error("invalid token structure"));
    }

    validate_segment(header, MAX_HEADER_SEGMENT_BYTES)?;
    validate_segment(payload, MAX_PAYLOAD_SEGMENT_BYTES)?;
    validate_segment(signature, MAX_SIGNATURE_SEGMENT_BYTES)?;

    Ok(CompactToken {
        header,
        payload,
        signature,
    })
}

fn validate_segment(segment: &str, max_len: usize) -> Result<(), JwtError> {
    if segment.is_empty() || segment.len() > max_len {
        return Err(verification_error("invalid token structure"));
    }
    if !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(verification_error("invalid token character"));
    }
    Ok(())
}

fn decode_segment(segment: &str, max_decoded_len: usize) -> Result<Vec<u8>, JwtError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| verification_error("invalid token character"))?;
    if decoded.len() > max_decoded_len {
        return Err(verification_error("token too large"));
    }
    Ok(decoded)
}

fn sign_hs256(message: &[u8], secret: &[u8]) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| creation_error("invalid key"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_hs256(message: &[u8], secret: &[u8], signature: &[u8]) -> Result<(), JwtError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| verification_error("invalid jwt secret"))?;
    mac.update(message);
    mac.verify_slice(signature)
        .map_err(|_| verification_error("invalid jwt signature"))
}

fn validate_claims(
    claims: &Claims,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<(), JwtError> {
    if claims.sub.trim().is_empty() || claims.sub.chars().count() > MAX_EMAIL_CHARS {
        return Err(verification_error("invalid jwt claims"));
    }
    if claims.name.trim().is_empty() || claims.name.chars().count() > MAX_NAME_CHARS {
        return Err(verification_error("invalid jwt claims"));
    }
    if claims.groups.len() > MAX_ROLE_COUNT {
        return Err(verification_error("invalid jwt claims"));
    }
    for group in &claims.groups {
        if group.trim().is_empty() || group.chars().count() > MAX_ROLE_CHARS {
            return Err(verification_error("invalid jwt claims"));
        }
    }
    if claims.exp <= claims.iat {
        return Err(verification_error("invalid jwt timing"));
    }
    if claims.exp < now - JWT_LEEWAY_SECONDS {
        return Err(verification_error("expired jwt"));
    }
    if claims.iat > now + JWT_LEEWAY_SECONDS {
        return Err(verification_error("invalid jwt timing"));
    }
    if claims.iss != issuer {
        return Err(verification_error("invalid jwt issuer"));
    }
    if claims.aud != audience {
        return Err(verification_error("invalid jwt audience"));
    }
    if Uuid::parse_str(&claims.jti).is_err() {
        return Err(verification_error("invalid jwt claims"));
    }
    if claims.password_version == 0 {
        return Err(verification_error("invalid jwt claims"));
    }
    Ok(())
}

fn creation_error(message: impl Into<String>) -> JwtError {
    JwtError::TokenCreation(message.into())
}

fn verification_error(message: impl Into<String>) -> JwtError {
    JwtError::TokenVerification(message.into())
}
