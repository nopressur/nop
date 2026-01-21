# TLS Modes and Well-Known Routing

Status: Developed

## Objectives

- Provide a single-server configuration that derives internal main/well-known listeners with role-based routing.
- Enforce two behaviors:
  - TLS disabled: a single HTTP main server serves all routes.
  - TLS enabled: HTTPS main server serves all routes, HTTP well-known server serves `/.well-known/*`.
- Support TLS material sources: self-signed, user-provided, and ACME (lers).
- Keep all TLS-related files under `state/sys/tls/` with no subdirectories.
- Document reverse-proxy expectations and configuration implications.

## Technical Details

### In-Memory Well-Known Handlers

- `/.well-known/*` responses are served exclusively by in-memory handlers; no filesystem read/write is allowed for well-known content.
- Remove `tls.well_known.root_dir` from configuration and validation; no runtime path is used for well-known content.
- Provide a handler registry keyed by well-known paths (e.g., `/acme-challenge/<token>`) so subsystems can register responders.
- The well-known HTTP listener routes requests only through the registry; unknown paths return 404.
- ACME HTTP-01 tokens are stored in memory (no disk persistence) and exposed through the registry for the lifetime of the challenge.
- ACME DNS-01 exec helpers keep cleanup tokens in an in-memory single-writer worker to avoid shared locks.
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

### TLS Material Storage (No Subdirectories)

All TLS-related files live directly in `state/sys/tls/`.

**Active certificate and key**
- `state/sys/tls/cert.pem`
- `state/sys/tls/key.pem`

**ACME account and metadata**
- `state/sys/tls/acme-account.pem`
- `state/sys/tls/acme-meta.json`
  - Records provider, directory URL, contact email, and optional account ID.

**Optional bookkeeping**
- `state/sys/tls/last-renewed.txt` (timestamp for diagnostics)

Self-signed generation and user-provided certificates both resolve to the
active `cert.pem` and `key.pem` paths so there is a single canonical location
for the running server.

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
#     provider: "lers"
#     environment: "production" # or "staging"
#     directory_url: "https://acme-v02.api.letsencrypt.org/directory" # optional override
#     insecure_skip_verify: false # testing only
#     contact_email: "admin@example.com"
#     challenge: "http-01"      # http-01 | dns-01
#     dns:
#       provider: "cloudflare" # cloudflare | exec
#       api_token: "env:CF_API_TOKEN" # supports env:NAME lookups
#       exec:
#         present_command: "/usr/local/bin/acme-dns-present"
#         cleanup_command: "/usr/local/bin/acme-dns-cleanup"
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
- `acme.provider` must be `lers`.
- `acme.dns.provider` must be `cloudflare` or `exec`.
- `acme.dns.exec` requires `present_command` and `cleanup_command`.
- `acme.directory_url`, when set, must start with `https://`.

### ACME With lers

**HTTP-01**
- Implement a custom `lers::Solver` that stores `{token, key_authorization}` in
  a shared map.
- Actix `/.well-known/acme-challenge/{token}` serves the stored value.
- HTTP listener remains active to satisfy ACME validation; all other HTTP paths
  redirect to HTTPS.

**DNS-01**
- Use `lers` DNS solver with `cloudflare`, or `exec` to run custom commands.
- `exec` provider receives `ACME_DOMAIN`, `ACME_TOKEN`, and `ACME_KEY_AUTHORIZATION`.
- `exec` commands are executed via `sh -c` on the host.
- No HTTP exposure required for validation; HTTP listener still runs for
  redirects if TLS mode requires it.

**Certificate output**
- `lers` issues a single SAN certificate for `tls.domains`.
- Write the resulting chain and key to `state/sys/tls/cert.pem` and
  `state/sys/tls/key.pem`.

**Current implementation note**
- ACME mode uses lers to issue and renew certificates at runtime. If a
  certificate is missing or expired, startup fails until issuance succeeds.

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
- ACME solver unit tests (token insertion, cleanup, and HTTP-01 handler).
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
