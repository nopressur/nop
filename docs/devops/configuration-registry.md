# Configuration Registry

This registry is the data reference for `config.yaml` options. It records the
current typed configuration surface, defaults, validation, runtime consumers,
management exposure, and sensitivity.

Source of truth for parsing and validation: `nop/crates/nop-config/src/lib.rs`.
Example configuration: `examples/config.yaml.example`.

Legend:

- Required: the key or section must be present in `config.yaml` unless a parent
  section rule says otherwise.
- Default: value applied by serde/default code when the key is omitted from a
  present section, or by optional field semantics.
- Restart: whether changing the file directly requires a daemon restart to take
  effect. Management-backed settings can apply live as noted.
- Management: management bus, CLI, or admin UI exposure of the configuration
  value itself. Runtime APIs that only consume the value are listed under
  Consumer / interface exposure.

## Top-Level Sections

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `server` | object | Required | See `server.*` | Listener bootstrap | No | No | Yes |
| `admin` | object | Required | See `admin.*` | Admin routing, login redirects, profile menu, CSRF endpoint generation | No | No | Yes |
| `users` | object | Required | `auth_method` selects required child config | IAM services, login/profile flows | Partial through user management, not as config | Contains secrets | Yes |
| `navigation` | object | Required | See `navigation.*` | Public navbar generation | No | No | Yes |
| `logging` | object | Required | See `logging.*` | Log bootstrap and rotation | Partial | No | Partial |
| `security` | object | Required | See `security.*` | Threat throttling, login sessions, HSTS, client IP extraction | No | No | Yes |
| `tls` | object or null | Optional, default `null` | Required when HTTPS is desired; see `tls.*` | TLS listeners, ACME, well-known routing | No | Contains secrets | Yes |
| `app` | object | Required | None beyond YAML type parsing | Public navbar, admin/login shell titles, SPA runtime config, error pages, logs | No | No | Yes |
| `upload` | object | Required | See `upload.*` | Content upload validation and stream limits | No | No | Yes |
| `streaming` | object | Optional, default object | See `streaming.*` | Public asset/range handling | No | No | Yes |
| `shortcodes` | object | Optional, default object | See `shortcodes.*` | Public shortcode registry | No | No | Yes |
| `rendering` | object | Optional, default object | See `rendering.*` | Public markdown width heuristics | No | No | Yes |
| `search` | object | Optional, default object | See `search.*` | Tantivy search service | Operational reset/invalidate/search only, not config | No | Yes |
| `settings` | object | Optional, default object | See `settings.*` | Public page title composition | Yes | No | No when changed through management |
| `dev_mode` | string or null | Optional, default `null` | `localhost` or `dangerous`; ignored in release builds | Debug-only auth/security bypass | No | Security-sensitive | Yes |

## Server

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `server.host` | string | Required | Must not be empty | Main and well-known listener bind address; logged at startup | No | No | Yes |
| `server.port` | u16 | Required | Must be greater than `0` | Main listener port; HTTP when TLS is disabled, HTTPS when TLS is enabled; logged at startup | No | No | Yes |
| `server.http_port` | u16 or null | Optional, default `null` | Required when `tls` is present; forbidden when `tls` is absent; must be greater than `0` and differ from `server.port` | HTTP well-known and redirect listener when TLS is enabled; logged at startup | No | No | Yes |
| `server.workers` | usize | Optional, default `4` | No explicit range validation | Actix worker count; logged at startup | No | No | Yes |

## Admin

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `admin.path` | string | Required | No central config validation; routing/security code treats it as a path prefix | Admin routes, admin redirects, admin SPA runtime config, profile menu admin link, CSRF/WS endpoint paths, reserved content paths | No | No | Yes |

## Users And Authentication

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `users.auth_method` | enum | Required | `local` or `oidc` | Selects auth backend and whether local user management is enabled | No | No | Yes |
| `users.local` | object or null | Required when `auth_method: local` | Must be present for local auth | Local user store, JWT service, login/profile SPAs | User records are managed separately through user domain | Contains secret child | Yes |
| `users.local.jwt.secret` | string | Required for local auth | No central strength validation | HS256 JWT signing | No | Yes | Yes |
| `users.local.jwt.issuer` | string | Optional, default `nopressure` | No explicit validation | JWT claims | No | No | Yes |
| `users.local.jwt.audience` | string | Optional, default `nopressure-users` | No explicit validation | JWT claims | No | No | Yes |
| `users.local.jwt.expiration_hours` | u64 | Optional, default `12` | No explicit minimum validation | JWT lifetime and cookie max-age | No | No | Yes |
| `users.local.jwt.cookie_name` | string | Optional, default `nop_auth` | No explicit validation | Auth cookie name | No | No | Yes |
| `users.local.jwt.force_secure_cookie` | bool | Optional, default `false` | No explicit validation | Forces `Secure` cookie flag even on localhost | No | Security-sensitive | Yes |
| `users.local.jwt.disable_refresh` | bool | Optional, default `false` | No explicit validation | JWT refresh behavior | No | No | Yes |
| `users.local.jwt.refresh_threshold_percentage` | u32 | Optional, default `10` | Must be `10..=90` | JWT refresh threshold | No | No | Yes |
| `users.local.jwt.refresh_threshold_hours` | u64 | Optional, default `24` | Must be at least `1`; warning if greater than `expiration_hours` | JWT refresh threshold for long-lived tokens | No | No | Yes |
| `users.local.password_complexity_disabled` | bool | Optional, default `false` | Honored only in debug builds; release builds ignore and enable complexity | Admin/login/profile SPA runtime config receives effective `passwordComplexityEnabled` | No | Security-sensitive | Yes |
| `users.local.password.front_end.memory_kib` | u32 or null | Optional, default `65536` | Non-zero; accepted by Argon2 params | Admin/login/profile SPA runtime config; front-end password hashing | No | No | Yes |
| `users.local.password.front_end.iterations` | u32 or null | Optional, default `2` | Non-zero; accepted by Argon2 params | Admin/login/profile SPA runtime config; front-end password hashing | No | No | Yes |
| `users.local.password.front_end.parallelism` | u32 or null | Optional, default `1` | Non-zero; accepted by Argon2 params | Admin/login/profile SPA runtime config; front-end password hashing | No | No | Yes |
| `users.local.password.front_end.output_len` | u32 or null | Optional, default `32` | Non-zero; accepted by Argon2 params | Admin/login/profile SPA runtime config; front-end hash validation | No | No | Yes |
| `users.local.password.front_end.salt_len` | u32 or null | Optional, default `16` | At least `8`; accepted by Argon2 params | Admin/login/profile SPA runtime config; front-end salt generation/validation | No | No | Yes |
| `users.local.password.back_end.memory_kib` | u32 or null | Optional, default `131072` | Non-zero; accepted by Argon2 params | Server-side password hashing | No | No | Yes |
| `users.local.password.back_end.iterations` | u32 or null | Optional, default `3` | Non-zero; accepted by Argon2 params | Server-side password hashing | No | No | Yes |
| `users.local.password.back_end.parallelism` | u32 or null | Optional, default `2` | Non-zero; accepted by Argon2 params | Server-side password hashing | No | No | Yes |
| `users.local.password.back_end.output_len` | u32 or null | Optional, default `32` | Non-zero; accepted by Argon2 params | Server-side password hashing | No | No | Yes |
| `users.local.password.back_end.salt_len` | u32 or null | Optional, default `16` | At least `8`; accepted by Argon2 params | Server-side salt generation | No | No | Yes |
| `users.oidc` | object or null | Required when `auth_method: oidc` | Must be present for OIDC auth | OIDC login flow | No | Contains secret child | Yes |
| `users.oidc.server_url` | string | Required for OIDC | No explicit validation | OIDC provider URL | No | No | Yes |
| `users.oidc.realm` | string | Required for OIDC | No explicit validation | OIDC realm | No | No | Yes |
| `users.oidc.client_id` | string | Required for OIDC | No explicit validation | OIDC client ID | No | No | Yes |
| `users.oidc.client_secret` | string or null | Optional | No explicit validation | OIDC client secret | No | Yes | Yes |
| `users.oidc.redirect_uri` | string | Required for OIDC | No explicit validation | OIDC callback URI | No | No | Yes |
| `users.oidc.scope` | string | Optional, default `openid email profile` | No explicit validation | OIDC scopes | No | No | Yes |
| `users.oidc.verify_ssl` | bool | Optional, default `true` | No explicit validation | OIDC TLS verification behavior | No | Security-sensitive | Yes |

## Navigation

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `navigation.max_dropdown_items` | usize | Optional, default `7` | No explicit range validation; `0` disables truncation behavior | Public navbar generation | No | No | Yes |

## Logging

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `logging.level` | string | Required | Parsed as `debug`, `info`, `warn`, or `error`; unknown values fall back to `info` at bootstrap | Log bootstrap; visible in System logging response | Read-only through System logging get | No | Yes |
| `logging.rotation.max_size_mb` | u64 | Optional, default `16` | Must be `1..=1024` | Daemon file rotation | Read/write through System logging get/set, CLI, and admin System UI | No | No when changed through management |
| `logging.rotation.max_files` | u32 | Optional, default `10` | Must be `1..=100` | Daemon file retention | Read/write through System logging get/set, CLI, and admin System UI | No | No when changed through management |

## Security

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `security.max_violations` | u32 | Optional, default `2` | No explicit range validation | Path traversal/threat throttling | No | Security-sensitive | Yes |
| `security.cooldown_seconds` | u64 | Optional, default `30` | No explicit range validation | Path traversal/threat cooldown | No | Security-sensitive | Yes |
| `security.use_forwarded_for` | bool | Optional, default `false` | No explicit validation; should only be enabled behind trusted proxies | Client IP extraction | No | Security-sensitive | Yes |
| `security.login_sessions.period_seconds` | u64 | Optional, default `300` | No explicit range validation | Login session rate-limit window | No | Security-sensitive | Yes |
| `security.login_sessions.id_requests` | u32 | Optional, default `5` | No explicit range validation | Login session issue limit | No | Security-sensitive | Yes |
| `security.login_sessions.lockout_seconds` | u64 | Optional, default `600` | No explicit range validation | Login session lockout duration | No | Security-sensitive | Yes |
| `security.hsts_enabled` | bool | Optional, default `false` | No explicit validation | Strict-Transport-Security header generation | No | Security-sensitive | Yes |
| `security.hsts_max_age` | u64 | Optional, default `31536000` | No explicit validation | HSTS `max-age` | No | Security-sensitive | Yes |
| `security.hsts_include_subdomains` | bool | Optional, default `true` | No explicit validation | HSTS `includeSubDomains` directive | No | Security-sensitive | Yes |
| `security.hsts_preload` | bool | Optional, default `false` | No explicit validation | HSTS `preload` directive | No | Security-sensitive | Yes |

## TLS And ACME

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tls.mode` | enum | Required when `tls` is present | `self-signed`, `user-provided`, or `acme` | TLS material selection | No | Security-sensitive | Yes |
| `tls.domains` | list of strings | Optional, default `[]`; required for `self-signed` and `acme` | At least one non-empty domain for `self-signed` or `acme` | Self-signed SANs and ACME certificate names | No | No | Yes |
| `tls.redirect_base_url` | string or null | Optional | When set, must start with `https://` | HTTP-to-HTTPS redirects | No | No | Yes |
| `tls.acme` | object or null | Required when `tls.mode: acme` | Must be present for ACME | ACME issuance/renewal | No | Contains secret child | Yes |
| `tls.acme.environment` | enum | Optional, default `production` | `production` or `staging` | ACME directory selection when `directory_url` is unset | No | No | Yes |
| `tls.acme.directory_url` | string or null | Optional | When set, must start with `https://` | Custom ACME directory | No | No | Yes |
| `tls.acme.insecure_skip_verify` | bool | Optional, default `false` | No explicit validation; intended for tests | ACME client TLS verification | No | Security-sensitive | Yes |
| `tls.acme.contact_email` | string | Required for ACME | Must be non-empty and contain `@` | ACME account contact | No | No | Yes |
| `tls.acme.challenge` | enum | Required for ACME | `http-01` or `dns-01` | ACME challenge mode | No | No | Yes |
| `tls.acme.dns` | object or null | Required for `dns-01` | Must be present for DNS-01 | DNS-01 provider settings | No | Contains secret child | Yes |
| `tls.acme.dns.provider` | string | Required for DNS-01 | Must be `cloudflare` | DNS provider selection | No | No | Yes |
| `tls.acme.dns.api_token` | string or null | Required for Cloudflare DNS-01 | Must be present and non-empty; supports `env:NAME` lookup in ACME implementation | Cloudflare API token | No | Yes | Yes |
| `tls.acme.dns.resolver` | string or list of strings | Optional, default `[]` | Each entry must be an IP address or socket address | DNS-01 propagation lookup resolver override | No | No | Yes |
| `tls.acme.dns.propagation_check` | bool | Optional, default `false` | No explicit validation | DNS-01 TXT propagation checking | No | No | Yes |
| `tls.acme.dns.propagation_delay_seconds` | u64 | Optional, default `30` | No explicit validation | DNS-01 wait before ACME validation | No | No | Yes |

## Deprecated App Compatibility Input

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `app.name` | string | Optional compatibility input | Trimmed by migration; empty values ignored when `settings.name` is absent | Migrated to `settings.name` during validated config load | No | No | No after migration |
| `app.description` | string | Optional compatibility input | Trimmed by migration; empty values clear the optional description | Migrated to `settings.description` during validated config load | No | No | No after migration |

## Upload

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `upload.max_file_size_mb` | u64 | Optional, default `100` | `0` means unlimited; no upper validation | Content binary upload and markdown stream size enforcement | No | No | Yes |
| `upload.allowed_extensions` | list of strings | Optional, default broad built-in extension list including common font files (`woff`, `woff2`, `ttf`, `otf`, `eot`, `ttc`) | Empty list means no extension restriction; entries are compared case-insensitively after trimming leading dot | Content upload extension enforcement | No | No | Yes |

## Streaming

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `streaming.enabled` | bool | Optional, default `true` | No explicit validation | Public asset streaming/range behavior | No | No | Yes |

## Shortcodes

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `shortcodes.start_unibox` | string | Optional, default `https://duckduckgo.com?q=<QUERY>` | Must contain `<QUERY>` and start with `http://` or `https://` | `start-unibox` shortcode search URL | No | No | Yes |

## Rendering

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rendering` | object | Optional, default `{}` | Reserved section; content width is fully manual via the page sidecar | None (no settings remain under this section) | No | No | Yes |

## Search

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `search.max_memory_mb` | u64 | Optional, default `128` | Must be greater than `0` | Tantivy writer/index memory budget | No config management; search query/invalidate/reset operations exist | No | Yes |
| `search.worker_count` | usize | Optional, default `1` | Must be greater than `0`; values above `16` are clamped to `16` with a warning | Search ingestion partition count | No config management; search query/invalidate/reset operations exist | No | Yes |

## Settings

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `settings.name` | string | Optional, default `NoPressure` | Trimmed; must be non-empty; max `120` chars; ASCII control characters rejected | Public navbar brand, public/error page fallback titles, admin/login/profile shell app name, admin SPA `appName`, login/profile SPA `appName`, startup logs; successful management changes bump website-wide epoch with reason `settings.name` | Read/write through Settings domain, CLI, and admin Settings UI | No | No when changed through management |
| `settings.title` | string or null | Optional, default `null` | Trimmed; empty clears; max `120` chars; ASCII control characters rejected | Public HTML title suffix and app shell HTML title; successful management changes bump website-wide epoch with reason `settings.title` | Read/write through Settings domain, CLI, and admin Settings UI | No | No when changed through management |
| `settings.description` | string or null | Optional, default `null` | Trimmed; empty clears; max `240` chars; ASCII control characters rejected | Public-page-only meta description; successful management changes bump website-wide epoch with reason `settings.description` | Read/write through Settings domain, CLI, and admin Settings UI | No | No when changed through management |
| `settings.website_title` | string or null | Deprecated compatibility alias for `settings.title` | Same as `settings.title`; persisted back as `settings.title` | Config file compatibility only | No direct management surface | No | No after migration |

## Dev Mode

| Path | Type | Required / default | Validation | Consumer / interface exposure | Management | Sensitive | Restart |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dev_mode` | enum or null | Optional, default `null` | `localhost` or `dangerous`; release builds ignore and log a warning | Debug-only access-control bypass in IAM/security middleware | No | Security-sensitive | Yes |

## Live Management Coverage

| Config path | Domain / action | Read | Write | Surfaces |
| --- | --- | --- | --- | --- |
| `settings.name` | `settings.get`, `settings.set_name` | Yes | Yes | Management bus, socket/WebSocket codec, admin Settings UI, CLI |
| `settings.title` | `settings.get`, `settings.set_title` | Yes | Yes | Management bus, socket/WebSocket codec, admin Settings UI, CLI |
| `settings.description` | `settings.get`, `settings.set_description` | Yes | Yes | Management bus, socket/WebSocket codec, admin Settings UI, CLI |
| `logging.rotation.max_size_mb` | `system.logging_get`, `system.logging_set` | Yes | Yes | Management bus, socket/WebSocket codec, admin System UI, CLI |
| `logging.rotation.max_files` | `system.logging_get`, `system.logging_set` | Yes | Yes | Management bus, socket/WebSocket codec, admin System UI, CLI |
| `logging.level` | `system.logging_get` response only | Yes | No | Management bus, socket/WebSocket codec, admin System UI, CLI |

## Secret And Redaction Requirements

If any of these paths are ever exposed through management, CLI, admin UI, API, or diagnostics,
they must be write-only or redacted on read:

- `users.local.jwt.secret`
- `users.oidc.client_secret`
- `tls.acme.dns.api_token`

These paths are not secrets, but changes can weaken deployment security and should be treated as
security-sensitive in UI copy and review:

- `users.local.jwt.force_secure_cookie`
- `users.local.password_complexity_disabled`
- `users.oidc.verify_ssl`
- `security.*`
- `tls.*`
- `dev_mode`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
