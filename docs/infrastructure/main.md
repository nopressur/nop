# Runtime Bootstrap (`nop/src/main.rs`)

This document walks through the NoPressure entrypoint so contributors understand exactly what happens between process start and the first HTTP request being served.

## Startup Sequence

1. **Parse CLI flags and requested run mode** (`-C <root>`, `-F` foreground override, order-insensitive). When no subcommands are provided and `-F` is absent, the server requests daemon mode on Unix (double-fork); on non-Unix builds it warns and stays in the foreground.
2. **Resolve runtime root** from CLI flags (`-C <root>`, default: current directory).
3. **PID file guard** (server modes only):
   - If `<runtime-root>/nop.pid` exists and the PID is running, exit with an "already running" error before daemonization.
   - If the PID is stale, remove the file and continue.
   - Foreground runs never create a PID file; daemon runs create it after daemonizing.
4. **Bootstrap runtime root** via `bootstrap::bootstrap_runtime` (before daemonization):
   - Fails fast if the runtime root contains unexpected top-level entries.
   - Creates missing `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/` (plus `state/sys`, `state/sc`) without overwriting existing files.
   - Writes `content/index.md` and `themes/default.html` when missing.
   - Loads and validates the config, then constructs `RuntimePaths`.
5. **Determine final run mode**:
   - If bootstrap created `config.yaml` or `users.yaml`, force foreground for that run.
   - Otherwise, honor the requested run mode (`-F` and platform daemon support).
6. **Daemonize if needed** (server modes only):
   - On Unix, double-fork and detach when final run mode is daemon.
   - If daemonization is requested on non-Unix builds, warn and continue in foreground mode.
   - Create `<runtime-root>/nop.pid` only after daemonizing.
7. **Resolve log level** from `config.logging.level`, defaulting to `info`. Logging targets stdout in foreground mode and rotating log files in daemon mode.
8. **Install custom logger** via `util::init_logger`, which applies rule-based level overrides (currently bumping `html5ever` trace noise down to debug).
9. **Emit startup telemetry** through `log_startup_info`, including canonical runtime paths and the resolved admin URL.
10. **Initialize `AppState`** (templates + error renderer) using the app name and runtime paths.
11. **Create `UserServices`** using the validated config and `users.yaml` path. This wires auth backends (local users or OIDC) and will later mediate RBAC checks.
12. **Instantiate the page metadata cache** (`public::page_meta_cache::PageMetaCache`) pointed at the canonical content directory, then inject it into `UserServices`.
13. **Ensure `.mime-types` manifests** exist under every content directory using `initialize_mime_types_files`. If generation fails, the process aborts.
14. **Warm the page metadata cache** by calling `PageMetaCache::rebuild_cache()`. Any error is fatal.
15. **Prepare ancillary singletons**:
    - Clone the admin base path and server listener configuration.
    - Build the shortcode registry via `public::shortcode::create_default_registry_with_config`.
    - Ensure shortcode state subdirectories exist under `state/sc/<shortcode>`.
    - Instantiate the CSRF token store (`util::CsrfTokenStore::new`), seeding exempt endpoints from configuration.

Everything above happens before binding sockets so failures are visible immediately.

## HTTP Server Construction

`HttpServer::new` captures Arcs to the config and long-lived services, then builds the Actix `App` with these characteristics:

- **App data** injected as `web::Data`:
  - `ValidatedConfig`
  - `AppState`
  - `Arc<UserServices>`
  - `Arc<PageMetaCache>`
  - `Arc<ShortcodeRegistry>`
  - `Arc<CsrfTokenStore>`
  - `Arc<ReleaseTracker>`

- **Middleware stack (outermost first)**:
  1. `Logger` using Apache-style access logs (`%a "%r" %s ... %T`).
  2. `headers::Headers` – centralizes security header injection (CSP, Referrer-Policy, Permissions-Policy) and cache directives, with per-route CSP overrides for login/admin shells.
  3. `JwtAuthMiddlewareFactory` – enforces JWT auth for protected routes via `iam`.
  4. `CsrfValidationMiddlewareFactory` – validates CSRF tokens for state-changing requests, consulting the shared token store.

- **Route configuration order**:
  1. `admin::configure(cfg, &admin_path_clone, &config_for_admin)` – mounts the admin UI under the configured base path.
  2. `login::configure(cfg, &config_for_login)` – exposes login/logout and OIDC callbacks.
  3. `builtin::configure(cfg)` – serves embedded admin assets in dev and release modes.
  4. `public::configure(cfg)` – registers public site handlers, static asset serving, and error fallbacks.

Finally the server sets the worker pool size from `config.server.workers` and binds listeners from the `servers` list:

- **TLS disabled**: bind `main` servers using `protocol: http` (typically a single listener).
- **TLS enabled**: bind `main` servers using `protocol: https` and `well-known` servers using `protocol: http`.
  - HTTP well-known listeners serve only registered `/.well-known/*` handlers (in memory) and redirect all other paths.

## Failure and Shutdown Behaviour

- Any initialization failure before `HttpServer::new` results in a logged error and hard exit. There is no partial startup.
- `initialize_mime_types_files` and `PageMetaCache::rebuild_cache` run before binding sockets to avoid serving stale or incomplete content.
- Bind failures (port in use, permissions) bubble up through the `?` operator and return an `std::io::Result`, which Actix logs before terminating.

## Maintenance Notes

- New cross-cutting services should be created before `HttpServer::new` and injected via `web::Data`. This keeps runtime wiring explicit.
- Middleware ordering matters: headers must precede auth and CSRF so they can observe post-auth state, while auth must precede admin/public route registration.
- Keep fatal error messages concise and actionable; they surface directly to operators.
- A guarded Actix test (`tests::test_awc_tls_connectivity`) verifies TLS support for the `awc` client. It runs opportunistically and logs a skip message if outbound HTTPS is unavailable.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
