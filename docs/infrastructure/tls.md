# TLS Modes and Well-Known Routing

Status: In Progress

## Objectives

- Provide a single-server configuration that derives internal main/well-known listeners with role-based routing.
- Enforce two behaviors:
  - TLS disabled: a single HTTP main server serves all routes.
  - TLS enabled: HTTPS main server serves all routes, HTTP well-known server serves `/.well-known/*`.
- Support TLS material sources: self-signed, user-provided, and ACME (in-house implementation).
- Keep TLS material under `state/sys/tls/` with no ACME subdirectories.
- Document reverse-proxy expectations and configuration implications.

## Action Plan

- [x] Update TLS documentation to reflect the in-house ACME implementation, Cloudflare-only DNS-01, and storage rooted in `state/sys/tls/`.
- [x] Add an ACME Caravaggio document for implementation details and scoped action plan.
- [x] Remove the acmex crate + vendor patching and replace ACME logic with the in-house implementation described in `docs/infrastructure/acme.md`.
- [x] Update TLS storage layout to remove any `state/sys/tls/cache/` usage while keeping existing TLS state files stable.
- [x] Run targeted ACME coverage (unit + Pebble HTTP-01/DNS-01) and confirm config validation rules for ACME.
- [ ] Confirm readiness and switch status to `Developed` once approved.

## Technical Details

### In-Memory Well-Known Handlers

- `/.well-known/*` responses are served exclusively by in-memory handlers; no filesystem read/write is allowed for well-known content.
- Remove `tls.well_known.root_dir` from configuration and validation; no runtime path is used for well-known content.
- Provide a handler registry keyed by well-known paths (e.g., `/acme-challenge/<token>`) so subsystems can register responders.
- The well-known HTTP listener routes requests only through the registry; unknown paths return 404.
- ACME HTTP-01 tokens are stored in memory (no disk persistence) and exposed through the registry for the lifetime of the challenge.
- `well-known` listeners remain required when TLS is enabled, but only serve registered in-memory handlers and redirect all other paths to HTTPS.

### Server Roles and Modes

**Server roles**
- `main`: full application routes (admin, login, public, builtin).
- `well-known`: `/.well-known/*` only.

Internal listeners are derived from the `server` block and the presence of `tls`; `config.yaml`
does not expose multi-listener binding.

**TLS disabled**
- `tls` is omitted.
- Main listener uses HTTP on `server.port`.
- `server.http_port` must not be set.

**TLS enabled**
- `tls` is present.
- Main listener uses HTTPS on `server.port`.
- HTTP well-known listener uses `server.http_port` on the same host and redirects all other paths to HTTPS.

### Well-Known Routing

- Actix exposes a dedicated handler for `/.well-known/*` on listeners with role `well-known`.
- The handler routes requests through the in-memory registry and returns 404 for unknown paths.
- `well-known` listeners always serve only `/.well-known/*` and redirect all other paths to HTTPS.
- When TLS is disabled, `well-known` listeners are not configured and the route is not mounted.

### TLS Material Storage

TLS material lives in `state/sys/tls/` with no ACME subdirectories.

**Active certificate and key**
- `state/sys/tls/cert.pem`
- `state/sys/tls/key.pem`

**TLS state**
- `state/sys/tls/state.yaml`

**ACME state and account material**
- Stored under `state/sys/tls/` (no subdirectories). File naming is implementation-defined and must not require an `acme-*` naming convention.

`state.yaml` tracks issuance provenance and the current TLS configuration fingerprint. It records:
- `mode` (`self-signed`, `user-provided`, `acme`)
- `domains`
- `config_fingerprint`
- `issued_at`
- `acme` (directory URL, contact email, optional account ID) when in ACME mode

**Optional bookkeeping**
- `state/sys/tls/last-renewed.txt` (timestamp for diagnostics)

Self-signed generation and user-provided certificates both resolve to the
active `cert.pem` and `key.pem` paths so there is a single canonical location
for the running server.

**Entropy and key material**
- Random bytes are sourced from the OS CSPRNG via `getrandom`.
- ACME account keys are managed by the in-house ACME implementation and stored under `state/sys/tls/`.

### Configuration Shape

```yaml
server:
  host: "0.0.0.0"
  port: 5466
  workers: 4

# TLS configuration (optional, enables HTTPS when present).
# tls:
#   mode: "self-signed"   # self-signed | user-provided | acme
#   domains:
#     - "example.com"
#     - "www.example.com"
#   redirect_base_url: "https://example.com" # optional
#
#   acme:
#     environment: "production" # or "staging"
#     directory_url: "https://acme-v02.api.letsencrypt.org/directory" # optional override
#     insecure_skip_verify: false # testing only
#     contact_email: "admin@example.com"
#     challenge: "http-01"      # http-01 | dns-01
#     dns:
#       provider: "cloudflare"
#       api_token: "env:CF_API_TOKEN" # supports env:NAME lookups
#       resolver: ["1.1.1.1", "1.0.0.1"] # optional DNS resolver override
#       propagation_check: false # optional, defaults to false
#       propagation_delay_seconds: 30 # optional delay before ACME validation
```

TLS-enabled example (dual-port):

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  http_port: 8080
  workers: 4

tls:
  mode: "self-signed"
  domains:
    - "example.com"
```

Validation rules:
- `server.host` cannot be empty.
- `server.port` must be greater than 0.
- TLS is enabled when the `tls` block is present.
- When TLS is enabled, `server.http_port` is required and must be greater than 0.
- When TLS is enabled, `server.http_port` must differ from `server.port`.
- When TLS is disabled, `server.http_port` must not be set.
- `tls.mode` must be one of `self-signed`, `user-provided`, or `acme` when HTTPS is configured.
- `tls.domains` required for `acme` and for SANs on self-signed certs.
- `acme.contact_email` required when `mode: acme`.
- `acme.dns.*` required when `challenge: dns-01`.
- `acme.dns.provider` must be `cloudflare`.
- `acme.dns.resolver` optional list of DNS resolvers for DNS-01 TXT checks; defaults to authoritative name servers.
- `acme.dns.propagation_check` optional boolean to enable DNS-01 TXT propagation checks; defaults to false.
- `acme.dns.propagation_delay_seconds` optional delay before ACME validation; defaults to 30 seconds.
- `acme.directory_url`, when set, must start with `https://`.

### ACME Implementation (In-House)

**HTTP-01**
- Use an HTTP-01 provider that stores `{token, key_authorization}` in
  the in-memory token store.
- Actix `/.well-known/acme-challenge/{token}` serves the stored value.
- HTTP listener remains active to satisfy ACME validation; all other HTTP paths
  redirect to HTTPS.

**DNS-01**
- Use the Cloudflare DNS provider with an API token.
- DNS-01 waits for TXT propagation before ACME validation proceeds.
- No HTTP exposure required for validation; HTTP listener still runs for
  redirects if TLS mode requires it.
- DNS providers must not execute shell commands; only Cloudflare is supported.

**Certificate output**
- The in-house ACME client issues a single SAN certificate for `tls.domains`.
- Write the resulting chain and key to `state/sys/tls/cert.pem` and
  `state/sys/tls/key.pem`.

For implementation details and the ACME-specific action plan, see `docs/infrastructure/acme.md`.

**Issuance triggers**
- TLS issuance is driven by `state.yaml` plus certificate validation.
- If `state.yaml` is missing or invalid:
  - `self-signed` and `acme` modes regenerate/re-issue.
  - `user-provided` mode validates existing materials and writes state if valid.
- If the recorded `mode` or `config_fingerprint` does not match the current config:
  - `self-signed` and `acme` modes re-issue.
  - `user-provided` mode requires manual certificate updates.
- All modes validate `cert.pem`/`key.pem` and ensure the certificate covers `tls.domains`.
- Self-signed regenerates at startup when the certificate is missing, invalid, expired, or expires
  within 2 days.

**Current implementation note**
- ACME mode will use the in-house ACME client to issue and renew certificates at runtime.
  If issuance is required and fails, startup fails until issuance succeeds.

### Reload and Renewal

- ACME mode runs a background renewal loop (default: every 12 hours).
- Renew certificates when they are within 30 days of expiration.
- On renewal, rewrite `cert.pem` and `key.pem`.
- TLS uses a reloadable resolver that detects certificate file changes on new
  handshakes, keeping the last known good certificate if reload fails.

### Testing Scope

- Config validation for all TLS modes and ACME settings.
- Routing behavior:
  - TLS disabled: HTTP serves all routes, no well-known mount.
  - TLS enabled: HTTP serves only `/.well-known/*` and redirects others.
- Well-known handler registry responses (in-memory).
- ACME unit tests (token insertion/cleanup, HTTP-01 provider, DNS propagation checks).
- ACME integration test uses a local Pebble stack when Docker is available;
  if Docker is missing, the test warns and skips.
  - Use `scripts/acme-pebble.sh start|stop|status` to manage the Pebble stack
    locally for debugging the ACME flow.

### Testing Additions

- Verify the well-known handler registry serves in-memory responses only.
- Ensure unknown well-known paths return 404 and non-well-known paths redirect to HTTPS.
- Assert no filesystem access for well-known content (no reads/writes to `state/sys/well-known`).

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
