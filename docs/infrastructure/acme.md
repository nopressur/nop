# ACME Automation

Status: In Progress

## Objectives

- Replace external ACME crates and vendor patches with an in-house ACME implementation.
- Support HTTP-01 and DNS-01 challenges only (no TLS-ALPN-01).
- Implement DNS-01 via Cloudflare only, with no shell execution and no additional providers.
- Store all ACME state alongside TLS materials under `state/sys/tls/` (no subdirectories).
- Eliminate OpenSSL usage and rely on OS CSPRNG via `getrandom` for entropy.
- Define success as passing the Pebble HTTP-01 and DNS-01 test flows.

## Action Plan

Phase 1 — Documentation + Alignment
- [x] Document the ACME requirements and constraints in this Caravaggio.
- [x] Update TLS documentation and config examples to remove ACME subdirectories and external crates.
- [x] Confirm config validation rules in code match the documented shape (Cloudflare-only DNS-01).

Phase 2 — Core ACME Protocol (with unit tests early)
- [x] Implement ACME directory discovery, nonce handling (including badNonce retry), JWS signing, account creation, order creation, authorization fetch, order finalization, and certificate download.
- [x] Add unit tests for JWS signing, POST-as-GET behavior, and nonce retry handling.
- [x] Run `scripts/cargo.sh test acme` to validate the unit coverage before proceeding to integrations.

Phase 3 — Challenge Implementations (with Pebble tests early)
- [x] Implement HTTP-01 challenge handling using the in-memory well-known registry.
- [x] Implement DNS-01 using the Cloudflare API with optional propagation checks and resolver overrides.
- [x] Add ACME integration tests using the Pebble stack (HTTP-01 + DNS-01); skip with a warning when Docker is unavailable.

Phase 4 — TLS Integration + Cleanup
- [x] Wire the in-house ACME client into TLS issuance/renewal flow and remove the external acmex crate + vendor patching.
- [x] Update TLS storage to keep ACME state under `state/sys/tls/` with no cache subdirectory.
- [x] Run `scripts/cargo.sh check` and re-run the targeted ACME tests after the integration changes.
- [ ] Confirm readiness and mark this document `Developed`.

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
