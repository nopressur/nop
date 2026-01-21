# Coding Standards

These guidelines keep the codebase consistent and approachable for both AI assistants and human contributors. Treat them as the contract for new modules, refactors, and reviews.

## Language & Tooling

- **Rust 2024 edition**. Always run `scripts/cargo.sh fmt --all` and `scripts/cargo.sh clippy -- -D warnings` before shipping.
- Target **stable Rust**. Avoid nightly-only features unless signed off and guarded behind feature flags.
- Use `actix_web::Result` in handlers and map errors with `actix_web::error::Error*` helpers. Avoid `unwrap()` in production paths; panics are acceptable only in tests or clearly unreachable branches with comments.

## Project Structure

- Group functionality by domain (e.g., `public/`, `admin/`, `iam/`, `security/`, `util/`). Keep modules small and focused.
- Each domain has a `mod.rs` that re-exports public entry points and wires submodules (e.g., `admin::configure`).
- When creating new capabilities:
  1. Create a directory (`nop/src/<area>/<feature>/`) with `mod.rs`, `handlers.rs` or equivalent, `templates/` if needed.
  2. Add a `configure` function to register routes or services.
  3. Update the parent module (`admin::handlers`, `public::configure`, etc.) to include the new feature.
- Keep business logic in Rust; templates should be thin presentation layers.

## Naming & Style

- **snake_case** for files/functions/variables, **CamelCase** for types, **SCREAMING_SNAKE_CASE** for constants.
- One concept per file whenever possible (e.g., `pages/index.rs`, `pages/edit.rs`). Split large handlers into helpers.
- Keep function sizes small (<100 lines is a good heuristic). Extract helpers when complexity grows.
- Use descriptive names (`validate_new_file_path`, not `check_dir`) to ease AI comprehension.
- Log messages should include actionable context (user, path, error). Use emoji markers (`🔧`, `🚨`, `🚫`) consistently for dev-mode/info/warnings.

## Error Handling

- Never return raw IO or serde errors to clients. Wrap with domain-specific messages via `shared::json_error_response` or HTTP error responses.
- Validate inputs early using helper functions (security, path normalization, config). Return 400/404 for user mistakes; 500 only for server issues.
- For async background tasks, log errors but avoid panicking—these failures should not crash the server.

## Concurrency & State

- Shared state (config, services, caches) is injected via `actix_web::web::Data`. Use `Arc<T>` only when the service maintains interior mutability.
- `std::sync::Mutex` and `tokio::sync::Mutex` are prohibited. Use single-writer registry workers (channel + owned state) or snapshot reads instead. If a lock is unavoidable (for example, `RwLock`), always recover from poisoning (`into_inner`), log critical errors, and continue—never use `.expect`/`.unwrap` on production locks. Verify with `scripts/check-no-mutex.sh`.
- Long-running operations should run in background tasks (`tokio::spawn` or `actix_web::rt::spawn`). Avoid blocking the Actix worker threads with CPU-heavy work.

## Security Practices

- Always pass paths through `security::*` validators.
- Sanitize or escape user-provided strings before rendering templates (`Value::from_safe_string` only for trusted HTML).
- Gate admin endpoints with `RequireAdminMiddleware` and CSRF protection—new routes under `/admin` receive this automatically; avoid shortcuts.
- Log suspicious behaviour using the existing pattern so threat analysis remains consistent.

## Configuration

- Use strongly typed structs in `config.rs`. Add defaults via `#[serde(default = "fn_name")]`.
- All new config must be validated in `Config::load_and_validate`.
- Never embed secrets in source files or templates; read them from `config.yaml`/`users.yaml` or secret managers.

## Templates & Assets

- Add templates under `nop/src/<area>/templates/` and register them in `embedded_template_loader`.
- Serve static assets from `/builtin/` (development reads files; release embeds them). Don’t read directly from `content/` in admin code.
- Admin UI code lives under `nop/ts/admin/`; build outputs to `nop/builtin/admin/` and is served via `/builtin/admin/admin-spa.{js,css}`.

## Logging & Telemetry

- Use `log::{debug, info, warn, error}`. Avoid `println!`.
- Include enough context for tracing without exposing sensitive data (e.g., never log raw passwords).
- Keep success logs at `info`, expected warnings at `warn`, security-relevant events at `warn`/`error`.

## Documentation & Comments

- Add doc comments (`///`) for public structs/functions describing their role.
- Reserve inline comments for non-obvious logic. Avoid restating code (“Increment counter”).
- Update doc files under `docs/` when adding new modules or changing behaviour; AI assistants rely on them.

## AI Assistant Tips

- Before making large edits:
  - Read the relevant doc in `docs/`.
  - Inspect existing patterns (e.g., how `admin/pages` handles validation).
  - Mirror naming and logging styles.
- When uncertain, add TODO comments tagged with `// TODO:` and summarize the open question in PR notes.
- Keep PR-sized changes scoped; avoid mixing refactors with feature changes unless necessary.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
