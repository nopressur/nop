# HS256 JWT Codec

Status: Developed

## Objectives

- Replace the general-purpose JWT library dependency used for local session tokens with a
  small, repo-owned HS256-only codec.
- Remove the `rsa` dependency risk caused by pulling unsupported JWT algorithms into the
  authentication dependency graph.
- Preserve the current local-session behavior: login issues an auth cookie, middleware verifies
  the cookie, authenticated requests expose claims and user context, refresh creates a new JWT ID,
  and logout clears cookies and CSRF state.
- Keep the implementation defensive, auditable, dependency-light, and portable across macOS,
  Linux, and Windows without native crypto toolchains.

## Technical Details

### Ownership and Scope

The codec belongs to `nop-rt-iam` because it exists only to support local authentication sessions.
It must not become a general JOSE/JWT toolkit.

Implementation:

```text
nop/crates/nop-rt-iam/src/jwt/codec.rs
```

The codec surface is intentionally narrow:

```rust
pub(crate) fn encode_hs256(claims: &Claims, secret: &[u8]) -> Result<String, JwtError>;

pub(crate) fn decode_hs256(
    token: &str,
    secret: &[u8],
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<Claims, JwtError>;
```

`JwtService` remains the caller-facing API for the rest of IAM. Login providers, middleware, CSRF,
profile, and admin code must continue to depend on `JwtService`, not on codec internals.
`JwtService` also remains responsible for building claim values from configuration and user state:
issuer, audience, expiration, secret selection, refresh thresholds, and cookie policy stay in
`JwtService`. The codec signs and verifies the serialized local-session token and validates the
token's cryptographic, structural, timing, issuer, and audience binding.

Keeping issuer, audience, and timing checks inside `decode_hs256` is intentional. This codec is not
a reusable JWS verifier; it is the verifier for NoPressure local session cookies. A token that is
cryptographically valid but bound to the wrong issuer, audience, or time window is invalid for this
runtime and should fail at the same boundary as signature verification. This prevents future callers
from using a lower-level "verified but not bound to config" API by accident.

### Non-Goals

- No RSA, ECDSA, EdDSA, PSS, JWK, JWKS, JWE, `kid`, remote key discovery, PEM parsing, or
  algorithm negotiation.
- No support for unsigned JWTs.
- No support for third-party identity provider tokens. OIDC remains unimplemented and must use a
  separate reviewed design if enabled later.
- No native crypto backend, CMake, OpenSSL, BoringSSL, AWS-LC, or platform-specific toolchain.

### Dependencies

Runtime dependencies for the codec:

- `base64` for URL-safe no-padding base64url encoding and decoding.
- `hmac` for HMAC construction and constant-time verification.
- `sha2` for SHA-256.
- `serde` and `serde_json` for strict JSON serialization/deserialization.
- `chrono` and `uuid` may continue to be used by `JwtService` for timestamp and `jti` creation.

The codec must not add a new JWT, JOSE, ASN.1, PEM, RSA, EC, or native TLS/crypto dependency.

### Token Format

Only compact JWT/JWS serialization is supported:

```text
base64url(header).base64url(payload).base64url(signature)
```

The parser rejects:

- Tokens that are empty or exceed `MAX_TOKEN_BYTES`.
- Tokens with anything other than exactly three dot-separated segments.
- Empty header, payload, or signature segments.
- Tokens containing ASCII whitespace or control characters anywhere.
- Segments containing characters outside `[A-Za-z0-9_-]`.
- Segments containing `=` padding.
- Header or payload JSON that exceeds configured decoded-size limits.
- Decoded header or payload bytes that are not valid UTF-8 JSON objects.

Limits:

```rust
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_SEGMENT_BYTES: usize = 1024;
const MAX_PAYLOAD_SEGMENT_BYTES: usize = 6144;
const MAX_SIGNATURE_SEGMENT_BYTES: usize = 512;
const MAX_HEADER_JSON_BYTES: usize = 768;
const MAX_PAYLOAD_JSON_BYTES: usize = 4096;
```

These limits are intentionally above the current session-token size while still preventing the
auth middleware from doing unbounded work on attacker-controlled cookies.

### Header Contract

New tokens emit a minimal header:

```json
{"typ":"JWT","alg":"HS256"}
```

Verification requires:

- `alg` exists and is exactly `"HS256"`.
- `typ` is absent or exactly `"JWT"`.
- The header object contains no other members.

Verification rejects:

- `alg: "none"`.
- Any `alg` other than `"HS256"`, including RSA, EC, PSS, and EdDSA algorithm names.
- `typ` values other than `"JWT"`.
- `kid`, `crit`, `cty`, `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`, or any unknown header
  member.
- Duplicate header members.
- Non-string `alg` or `typ` values.

Rejecting `kid` and key-discovery headers is deliberate. The local auth configuration has exactly
one shared secret for local session cookies, so key selection is not part of the runtime contract.

### Signature Contract

Signing input is the exact ASCII bytes of:

```text
base64url(header) + "." + base64url(payload)
```

Encoding steps:

1. Serialize the header and claims to JSON.
2. Base64url encode each JSON document without padding.
3. Compute `HMAC-SHA256(secret, signing_input)`.
4. Base64url encode the 32-byte signature without padding.

Verification steps:

1. Parse and validate the compact token structure and header.
2. Recreate the signing input from the original header and payload segments, not from reserialized
   JSON.
3. Decode the signature segment and require exactly 32 bytes.
4. Compute HMAC-SHA256 over the signing input.
5. Verify with `Mac::verify_slice` or equivalent constant-time verification.
6. Decode and validate claims only after signature verification succeeds.

Using the original segments for verification preserves compatibility with existing valid tokens
regardless of JSON field ordering.

### Claims Contract

The current `Claims` shape remains the runtime session contract:

```json
{
  "sub": "user@example.com",
  "name": "Example User",
  "groups": ["admin"],
  "iat": 1760000000,
  "exp": 1760043200,
  "iss": "nopressure",
  "aud": "nopressure",
  "jti": "uuid",
  "password_version": 1
}
```

Required fields:

- `sub`
- `name`
- `groups`
- `iat`
- `exp`
- `iss`
- `aud`
- `jti`

`password_version` remains optional for backward compatibility with legacy tokens and defaults to
`DEFAULT_PASSWORD_VERSION` when absent.

`nbf` is intentionally unsupported. NoPressure local session cookies are valid immediately when
issued and do not require delayed activation. Tokens containing `nbf` must be rejected as unknown
claims rather than silently accepted.

The codec deserializes the header and claims through explicit serde visitors. Duplicate fields are
rejected deterministically before constructing `Claims`; unknown fields are rejected.

Field validation:

- `sub` must be non-empty and below the configured email length limit used by IAM validation.
- `name` must be non-empty and within the user display-name limit. The codec deliberately does not
  enforce the account-creation lower bound from `validate_name_field`; a signed token should not
  become invalid only because display-name creation rules are tightened later or a legacy token
  contains a shorter already-accepted name.
- `groups` must be an array of strings and must not exceed the configured maximum role count used
  by role validation.
- Each group string must be non-empty and within the role identifier length limit. Final role
  existence remains a user-store/content authorization concern, not a codec concern.
- `iat` and `exp` must be integer Unix timestamps.
- `exp` must be greater than `iat`.
- `exp` must not be earlier than `now - JWT_LEEWAY_SECONDS`.
- `iat` must not be later than `now + JWT_LEEWAY_SECONDS`.
- `iss` must exactly match `users.local.jwt.issuer`.
- `aud` must exactly match `users.local.jwt.audience`.
- `jti` must be a valid UUID string produced by the server.
- `password_version` must be a positive integer.

Recommended leeway:

```rust
const JWT_LEEWAY_SECONDS: i64 = 60;
```

This preserves the typical validation tolerance from the current JWT library while making it
explicit in repo-owned code.

### Error Behavior

The codec must return `JwtError::TokenVerification` for verification failures and
`JwtError::TokenCreation` for signing/serialization failures. Error strings should be specific
enough for tests and diagnostics, but logs and HTTP responses must not disclose token contents,
secret values, raw signatures, or raw payloads.

Recommended verification error categories:

- `invalid token structure`
- `invalid token character`
- `token too large`
- `invalid jwt header`
- `unsupported jwt algorithm`
- `invalid jwt signature`
- `invalid jwt secret`
- `invalid jwt claims`
- `invalid jwt timing`
- `expired jwt`
- `invalid jwt issuer`
- `invalid jwt audience`

Middleware should continue to treat verification failures as unauthenticated requests and avoid
turning malformed cookies into 500 responses.

### Compatibility Requirements

The implementation verifies valid HS256 tokens produced by the previous `jsonwebtoken`
configuration. The static fixture in `nop/tests/jwt_codec.rs` contains:

- Secret value.
- Token string.
- Expected claims.
- Explanation that the fixture was generated with the previous `jsonwebtoken` HS256 path.
- The exact one-shot generator snippet or command, kept in the test comments, so maintainers can
  regenerate the fixture without guessing the old dependency behavior.

The fixture does not require `jsonwebtoken` as a dev-dependency.

Existing token compatibility applies to verification only. New tokens may have a different header
or payload JSON field order, provided they remain valid compact HS256 JWTs and the local codec
verifies them.

### Security Considerations

- The codec verifies the signature before trusting or deserializing the payload into `Claims`.
- Header parsing is allowed before signature verification only to enforce the expected algorithm
  and reject unsupported token shapes early.
- Do not use `==` for signature comparison.
- Do not support algorithm fallback. The caller cannot ask for a different algorithm.
- Do not accept padded base64url input. Canonical no-padding encoding keeps parser behavior simple
  and predictable.
- Do not accept unknown header fields. This prevents accidental support for key discovery,
  critical extensions, or nested-token semantics.
- Keep JWT secrets in configuration only. Never log them or copy them into error values.
- Keep `jti` authoritative for CSRF binding. A token refresh must always mint a new `jti`, causing
  clients to refresh CSRF tokens as they do today.
- Continue password-change revocation through `password_version`; the codec validates the field
  shape, and `UserServices::validate_jwt_claims` validates it against the current user record.

### Test Matrix

The codec is implemented in a path dependency crate, while the standard Rust project command
executes the root package tests. The authoritative codec safety tests therefore live in
`nop/tests/jwt_codec.rs`, which runs under `scripts/crg.sh nop test`.

Minimum root integration-test matrix for the codec:

| Area | Required cases |
| --- | --- |
| Structure | empty token, one segment, two segments, four segments, empty segment, whitespace, control char, oversize token |
| Base64url | invalid alphabet, padded segment, non-canonical signature, decoded invalid UTF-8 |
| Header | valid minimal header, missing `alg`, `none`, `RS256`, non-string `alg`, unsupported `typ`, `kid`, `crit`, unknown field, duplicate field |
| Signature | valid token, wrong secret, tampered header, tampered payload, tampered signature, empty signature, wrong signature byte length |
| Claims | valid current claims, legacy missing `password_version`, missing required field, unknown field, duplicate field, wrong type, invalid UUID `jti`, invalid timestamps |
| Time | expired beyond leeway, expired within leeway, future `iat` beyond leeway, `exp <= iat` |
| Config binding | wrong issuer, wrong audience |
| Compatibility | static `jsonwebtoken` fixture verifies; locally generated token verifies; RFC HS256 known-answer signature matches |

Minimum application integration-test matrix:

| Flow | Required coverage |
| --- | --- |
| Login | successful password login issues a valid local JWT cookie |
| Middleware | valid cookie injects `Claims` and `User`; malformed cookie does not authenticate |
| Refresh | old valid token refreshes cookie with a new `jti`; fresh token does not refresh |
| Profile | profile update and password update issue replacement JWT cookies |
| Revocation | password-version mismatch rejects otherwise valid signed tokens |
| CSRF | CSRF token binding continues to use `jti`; refreshed JWT requires client token refresh |
| Admin WS | ticket issue and WebSocket auth remain bound to the authenticated `jti` |
| Public RBAC | authenticated content access still uses token roles and user-store validation |

### Test Coverage

`nop/tests/jwt_codec.rs` validates the runtime contract through `JwtService`, including:

- Valid HS256 token verification.
- Header rejection for unsupported algorithms, `none`, unsupported `typ`, key-selection fields,
  `crit`, unknown fields, and duplicate fields.
- Signature rejection for wrong secrets and tampered header, payload, and signature segments.
- Claims rejection for missing required fields, duplicate fields, wrong issuer, wrong audience,
  invalid `jti`, unsupported `nbf`, and invalid `password_version`.
- Backward compatibility for legacy tokens without `password_version`.
- Verification of a stored token generated by the previous `jsonwebtoken` HS256 implementation.
- RFC 7515 Appendix A.1 HS256 signature known-answer coverage.

The full Rust test suite exercises login, logout, profile update, password-change invalidation,
JWT refresh, CSRF binding, admin WebSocket ticket binding, public RBAC, and API profile behavior
through the local HS256 codec.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
