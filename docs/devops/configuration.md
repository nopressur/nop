# Configuration & Secrets Management

NoPressure reads `config.yaml` at startup and validates it through `Config::load_and_validate` (`nop/src/config.rs`). This guide explains the schema, defaults, validation rules, and how components consume each section.

## File Locations

- Runtime root defaults to the current working directory; override with `-C <root>`.
- Runtime root must be a dedicated data directory containing only `config.yaml`, `users.yaml`, `content/`, `themes/`, `state/`, `logs/`, and `nop.pid` at the top level.
- Primary file: `config.yaml` in the runtime root (copy from `examples/config.yaml.example` if you want to preseed; auto-bootstrap will generate defaults).
- Local user credentials: `users.yaml` in the runtime root when using local auth (auto-bootstrap can generate this too).
- Content, themes, and state live alongside the config (`content/`, `themes/`, `state/`).
- Admin UI secrets: never store live tokens in source control; rely on environment-specific copies.

## Top-Level Sections

| Section | Purpose | Consumed By |
|---------|---------|-------------|
| `server` | Listener definition (host/port/workers; optional HTTP port when TLS is enabled) | `main.rs` server bootstrap |
| `admin` | Admin base path | `admin::configure`, login redirects |
| `users` | Auth method + local/OIDC details | `iam::UserServices`, login flows |
| `navigation` | Nav menu thresholds | `public::navigation` helpers |
| `logging` | Global log level + rotation settings | `main.rs` log bootstrap |
| `security` | Path traversal guardrails, HSTS | `security::`, `headers::Headers` |
| `tls` | TLS listeners, cert sources, well-known routing | `main.rs` server bootstrap |
| `app` | Display name, description | Error pages, telemetry |
| `upload` | Admin upload constraints | `admin::upload` |
| `streaming` | Range streaming toggle | `public::assets` |
| `shortcodes` | Dynamic shortcode defaults | `public::shortcode` |
| `rendering` | Public markdown layout heuristics | `public::markdown` |
| `dev_mode` | Debug-only bypass controls (ignored in release builds) | Middleware (security + IAM) |

Note: the `server` block is authoritative. TLS is enabled by the presence of the top-level `tls`
block; when TLS is enabled, the HTTP port is provided by `server.http_port`.

## Defaults & Validation

- **Runtime paths**: `config.yaml` and (if local auth) `users.yaml` must be writable; `content/`, `themes/`, `state/`, `state/sys`, and `state/sc` are created if missing and must be writable. `logs/` is allowed at the root and created when daemon logging is enabled. `nop.pid` is allowed at the root and created only for daemon runs.
- **Bootstrap defaults**: missing `config.yaml` is generated with self-signed TLS defaults; missing `users.yaml` (when local auth is enabled) is created with a default admin and a one-time logged password. When bootstrap creates `config.yaml` or `users.yaml`, the server stays in the foreground for that run so the credentials are visible.
- **Local auth** requires:
  - JWT refresh thresholds: `refresh_threshold_percentage` ∈ 10–90, `refresh_threshold_hours` ≥ 1. A warning logs if refresh window exceeds expiration.
- **Argon2id password hashing** (local auth):
  - Defaults live under `users.local.password` and are used for both the login/profile SPA and
    server-side hashing helpers.
  - Front-end params are embedded in the login/profile SPA shell config; login endpoints do not
    return params over the wire.
  - Defaults:
    - Front-end: `memory_kib=65536`, `iterations=2`, `parallelism=1`, `output_len=32`, `salt_len=16`
    - Back-end: `memory_kib=131072`, `iterations=3`, `parallelism=2`, `output_len=32`, `salt_len=16`
- **OIDC auth** requires `users.oidc` to be present when `auth_method: oidc`.
- **Shortcodes**: `shortcodes.start_unibox` must contain `<QUERY>` and start with `http(s)://`; enforced by `validate_shortcodes`.
- **Dev mode**: optional `dev_mode: localhost` or `dangerous`. `dangerous` bypasses access control entirely and logs loud warnings. Dev mode is honored only in debug builds; release builds ignore it and log a warning. Never use in production.
- **Upload config**: defaults include broad file extensions (images, docs, archive, video, audio, web, markdown). `max_file_size_mb` defaults to 100; `0` disables the cap with no hidden safety limit. Upload limits apply to binary uploads and stream-backed Markdown create/update.
- **Rendering**: `rendering.short_paragraph_length` defaults to 256 characters. Set to `0` to disable compact-width detection entirely.
- **Streaming**: default `enabled: true`. Even when disabled, non-Markdown assets respond to HTTP range requests when the feature flag remains true.
- **Security**:
  - `max_violations` (default 2) and `cooldown_seconds` (default 30) power the IP throttler in `security::`.
  - `login_sessions` throttles login session issuance/usage:
    - `period_seconds` (default 300)
    - `id_requests` (default 5)
    - `lockout_seconds` (default 600)
  - HSTS flags default to disabled for local safety. Only enable once traffic is fully HTTPS.
  - `use_forwarded_for` defaults to `false`; enable only when the reverse proxy sets trusted headers.
- **Server**:
  - `server.host` and `server.port` define the main listener bind address.
  - TLS is enabled when the top-level `tls` block is present.
  - When TLS is enabled:
    - The main listener uses HTTPS on `server.port`.
    - `server.http_port` is required for the HTTP well-known listener, which serves `/.well-known/*` and redirects all other paths to HTTPS.
    - `server.http_port` must be greater than 0 and differ from `server.port`.
  - When TLS is disabled:
    - The main listener uses HTTP on `server.port`.
    - `server.http_port` must not be set.
  - Worker count remains in `server.workers` (default 4) and applies to all listeners.
- **TLS**:
  - `tls.mode` must be `self-signed`, `user-provided`, or `acme` when HTTPS is configured.
  - `tls.domains` is required for ACME and should be set for self-signed SANs.
  - All TLS files live in `state/sys/tls/` with no subdirectories:
    - Active cert/key: `state/sys/tls/cert.pem`, `state/sys/tls/key.pem`
    - TLS state + ACME account: `state/sys/tls/state.yaml`, `state/sys/tls/acme-account.pem`
    - Renewal marker: `state/sys/tls/last-renewed.txt`
  - Self-signed TLS regenerates at startup when the certificate is missing, invalid, expired, or
    expires within 2 days.
  - `/.well-known/*` responses are served by in-memory handlers (no filesystem root).
  - When TLS is disabled, `/.well-known/*` routes are not mounted.
  - `tls.acme.provider` must be `lers`.
  - `tls.acme.directory_url` overrides the ACME directory (defaults to the selected environment).
  - `tls.acme.insecure_skip_verify` is for test-only Pebble stacks.
  - `tls.acme.contact_email` is required for ACME; `tls.acme.dns.*` is required for DNS-01.
  - `tls.acme.dns.provider` must be `cloudflare` or `exec`; `api_token` supports `env:NAME` lookups for Cloudflare.
  - `tls.acme.dns.exec.present_command` and `cleanup_command` are required when using `exec`.
  - `tls.acme.dns.resolver` optionally overrides the DNS resolvers used for DNS-01 TXT lookups (defaults to authoritative name servers).
  - `tls.acme.dns.propagation_check` enables DNS-01 TXT propagation checks (defaults to false).
  - `tls.acme.dns.propagation_delay_seconds` adds a delay before ACME validation (defaults to 30).
  - `exec` commands run via `sh -c` with `ACME_DOMAIN`, `ACME_TOKEN`, and `ACME_KEY_AUTHORIZATION` set.
  - ACME issues certificates at startup when required (missing/expired/config mismatch) and renews within 30 days.
  - TLS reloads certificates on new handshakes after files change.
  - ACME integration test uses a local Pebble stack via Docker; tests warn and skip if Docker is unavailable.
- **Logging**:
  - `logging.level` is a free-form string parsed to `debug/info/warn/error`; defaults to `info` on unknown input.
  - `logging.rotation.max_size_mb` defaults to 16 (range 1-1024).
  - `logging.rotation.max_files` defaults to 10 (range 1-100).

## Secrets Handling

- **JWT** (`users.local.jwt.secret`) must be unique per environment.
- **OIDC** secrets (client secret) are optional but, when used, must be stored securely. Consider environment templating or secret managers instead of raw files.
- **Avoid Check-ins**: `.gitignore` should exclude environment-specific `config.yaml`/`users.yaml`. Never commit production secrets.

## Derived Values in Runtime

- `RuntimePaths` (built from the runtime root) provides canonical `content`, `themes`, `state`, and `users.yaml` paths for filesystem safety checks.
- `ValidatedConfig` exposes the validated server list used for binding and remains the shared Actix `web::Data` config payload.

## Update Workflow

1. Choose a dedicated runtime root (for example `./runtime`) and copy `examples/config.yaml.example` to `<runtime-root>/config.yaml` if you want to preseed settings; otherwise auto-bootstrap will generate defaults.
2. Review each section; remove `dev_mode` entries for production (release builds ignore it, but keep configs clean).
3. Set `users.auth_method` and populate either `local` or `oidc`.
4. If using local auth, copy `examples/users.yaml.example` to `<runtime-root>/users.yaml` and manage users with `nop user` subcommands, or let auto-bootstrap create a default admin.
5. Ensure `content/`, `themes/`, and `state/` exist (the server will create them if missing).
6. Restart `nop`; the process exits with descriptive errors if validation fails.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
