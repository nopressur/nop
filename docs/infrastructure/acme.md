# ACME Automation

Status: Developed

## Objectives

- Replace external ACME crates and vendor patches with an in-house ACME implementation.
- Support HTTP-01 and DNS-01 challenges only (no TLS-ALPN-01).
- Implement DNS-01 via Cloudflare only, with no shell execution and no additional providers.
- Store all ACME state alongside TLS materials under `state/sys/tls/` (no subdirectories).
- Eliminate OpenSSL usage and rely on OS CSPRNG via `getrandom` for entropy.
- Define success as passing the Pebble HTTP-01 and DNS-01 test flows.

## Technical Details

### Configuration & Validation

- ACME settings live under `tls.acme` in `config.yaml` (see `docs/infrastructure/tls.md`).
- Supported challenges: `http-01`, `dns-01` only; `tls-alpn-01` is not supported.
- DNS-01 requires `tls.acme.dns.provider: cloudflare` and `tls.acme.dns.api_token`.
- No exec-based DNS provider is supported; DNS automation must not call shell commands.
- `tls.acme.directory_url`, when provided, must be `https://`.
- `tls.acme.insecure_skip_verify` is test-only for Pebble or local ACME stacks.

### Storage Layout (No Subdirectories)

All ACME state is stored under `state/sys/tls/` alongside TLS material:

- `state/sys/tls/cert.pem`
- `state/sys/tls/key.pem`
- `state/sys/tls/state.yaml`
- `state/sys/tls/last-renewed.txt` (optional)

ACME account keys and any protocol state must also live in `state/sys/tls/` with no subdirectories.
- File naming is implementation-defined and must not require fixed `acme-*` naming.
- If opaque filenames are used, they must be referenced from `state.yaml` so cleanup and rotation are deterministic.

### ACME Protocol Implementation

- Implement the ACME flow internally (directory -> account -> order -> authorizations -> challenge -> finalize -> cert fetch).
- Use POST-as-GET with empty payloads where required by RFC 8555.
- Handle `badNonce` by retrying once with a fresh nonce.
- Generate CSRs with `rcgen`, sign JWS with `ring`, and source randomness via `getrandom`.
- Do not depend on OpenSSL or other external crypto tooling.

### HTTP-01 Challenge

- Store `{token, key_authorization}` in the in-memory token store.
- Serve `/.well-known/acme-challenge/{token}` from the well-known registry only (no filesystem).
- Ensure tokens are cleaned up on completion or failure.

### DNS-01 Challenge (Cloudflare)

- Use the Cloudflare DNS API to create and delete TXT records.
- Support optional DNS resolver overrides and propagation checks.
- Never run shell commands or exec hooks for DNS automation.

### Renewal & Failure Handling

- Keep the existing renewal behavior: check expiry and renew in the background (see `docs/infrastructure/tls.md`).
- If issuance is required and fails at startup, fail fast with a clear error.

### Testing Scope

- Unit tests for JWS signing, POST-as-GET, nonce retries, and token store behavior.
- DNS propagation tests for resolver override and propagation delay handling.
- Pebble integration tests for HTTP-01 and DNS-01; tests skip with a warning when Docker is unavailable.
- Success criteria: both Pebble flows pass with the in-house ACME implementation.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
