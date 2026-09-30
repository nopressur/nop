# Coding Standards

These guidelines keep the codebase consistent and approachable for both AI assistants and human contributors. Treat them as the contract for new modules, refactors, and reviews.

## Language & Tooling

- **Rust 2024 edition**. Always run `scripts/crg.sh nop fmt --all` and `scripts/crg.sh nop clippy -- -D warnings` before shipping.
- Target **stable Rust**. Avoid nightly-only features unless signed off and guarded behind feature flags.
- Use `actix_web::Result` in handlers and map errors with `actix_web::error::Error*` helpers. Avoid `unwrap()` in production paths; panics are acceptable only in tests or clearly unreachable branches with comments.

## Project Structure

- Group functionality by domain (e.g., `public/`, `admin/`, `iam/`, `security/`, `logging/`). Keep modules small and focused.
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

## Crates and Libraries

- Limit crate and library use to the minimum, always provide a rationale for using new libraries
- Vendoring and build-time patching is not permitted, only mature and stable libraries are permitted
- Prefer libraries that preserve compatibility across all supported platforms whenever possible
- Target platform compatibility for the command-line build: macOS, Linux, and Windows
- Stop and flag at design and implementation time if a selected library proves to be unfit for purpose

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

## Front-End Browser Compatibility & Build

The public site must work on legacy Safari, down to a hard floor of **iOS 12 (Safari 12)**. These are real, supported devices — not theoretical. Treat this floor as a contract: a change that breaks it is a regression, not a "nice to have".

### Why this is fragile

The public bundle ships as a **single classic IIFE script** (`nop/builtin/site.js`, sources in `nop/ts/site/`, loaded via `<script src="{site_js}" defer>` in `main_layout.html`). It wires up *every* interactive control — search overlay, hamburger/mobile menu, nav dropdowns, user menu, code-copy. Because it is one classic script, **a single unsupported token anywhere causes a parse error that disables the entire file** — every button goes dead at once, not just the feature that used the new syntax. There is no per-feature isolation and no `type="module"` fallback. `?.` and `??` are unsupported by Safari 12 and must never reach the shipped bundle unlowered; the remaining syntax in the table below ships natively.

### Building the public bundle

- **Author normally in TypeScript.** Do not hand-write ES5. The build is responsible for lowering syntax; your job is to respect the *runtime API* constraints below (which the build cannot fix on its own).
- **Bundler lowering alone is insufficient and must not be relied on for the floor.** Keep `build.target: 'esnext'` so the bundler defers lowering, and lower with Babel instead.
- **Lower the final bundle with Babel driven by browserslist.** The Vite lib build emits the classic IIFE, then `npm run build:legacy` runs Babel CLI over `nop/builtin/site.js` using `nop/ts/site/babel.legacy.config.cjs`, followed by terser with `ecma=2019`. This final-bundle pass is required because Vite-generated wrapper code must be lowered too. Note: `@vitejs/plugin-legacy` does **not** support `lib` mode, so it is not an option here.
- **Pin the target via browserslist** (in `package.json` or `.browserslistrc`), so Babel and the lint gate read one source of truth:
  ```
  iOS >= 12
  Safari >= 12
  ```
- **No runtime ECMAScript polyfills.** `fetch`, `AbortController`/`AbortSignal`, `Promise`, collections, and `async`/`await` are native at this floor. Do not reintroduce `core-js` (not even `core-js/stable`), `regenerator-runtime`, `whatwg-fetch`, or `abortcontroller-polyfill` without a documented Safari 12 gap.
- **Bundle prelude:** the emitted public and login classic scripts must start with the repo-owned legacy browser prelude that defines `globalThis` and a usable `EventTarget` right-hand side before any framework/runtime code executes. This covers Svelte/runtime helper output and old WebKit builds where `EventTarget` is missing or not a constructor (`EventTarget()` needs Safari 14; `globalThis` needs 12.1, so the prelude stays as belt-and-braces for 12.0/12.1).
- **Minify with terser** (`build.minify: 'terser'` and the post-Babel terser CLI pass with `ecma=2019`) so minification does not reintroduce syntax above the target.
- **CSS is currently safe at this floor.** Bulma v1.0.4 (`nop/builtin/bulma.min.css`) and the theme presets rely on CSS custom properties (`var()`), supported since Safari 9.1.

### Adding or changing front-end features

- **Stay inside the single IIFE.** Never introduce a separate `type="module"` script or dynamic `import()` for the public site; both are unsupported on the floor and break the no-module model.
- **Do not use a Web API newer than the floor without a polyfill or feature-detected fallback.** The build lowers *syntax* but cannot conjure missing *APIs*. Check support before using anything beyond the table below.
- **Feature-detect optional capabilities and degrade gracefully**, as `codeCopy.ts` already does for `navigator.clipboard` (falls back to `document.execCommand('copy')`). Never assume a capability newer than Safari 12 exists.
- **DOM convenience methods are native.** `replaceWith`, `append`, `prepend`, `before`, and `after` (Safari 10+) may be used directly; the login SPA keeps its feature-detected shims as belt-and-braces.
- **Network calls** go through native `fetch`; cancellation through native `AbortController`. `URLSearchParams` (Safari 10.3+) is available.
- **Lint gate:** wire `eslint-plugin-compat` (reading the browserslist above) into `npm run check`. It flags use of unsupported runtime APIs at lint time — the one thing the transpile step cannot catch. A failing compat lint is a build failure.
- **Verify on a real device.** Any change touching public site JS or CSS (buttons, search, menu, code-copy, theming) must be smoke-tested on a physical iOS 12 device before shipping. Modern Playwright cannot drive legacy iOS Safari, so device testing is mandatory and is not replaceable by the E2E suite.

### Feature support quick reference (floor = Safari 12)

| Capability | Safari floor | On iOS 12? | Action |
| --- | --- | --- | --- |
| `?.`, `??` | 13.1 | No | Lower with Babel — never ship raw |
| arrow fns, `class`, `let`/`const`, template literals, destructuring | 10 | **Yes** | Native |
| `async`/`await` | 10.1 | **Yes** | Native |
| `fetch` | 10.3 | **Yes** | Native |
| `AbortController` | 11.3 | **Yes** | Native |
| `globalThis` | 12.1 | Partial (12.0/12.1) | Bundle prelude stays as belt-and-braces |
| `EventTarget()` constructor | 14 | No | Bundle prelude before all runtime code |
| `ChildNode.replaceWith` / `append` / `prepend` | 10 | **Yes** | Native (login keeps shims) |
| `URLSearchParams` | 10.3 | **Yes** | Native |
| `navigator.clipboard` | 13.1 | No | Feature-detect; fall back to `execCommand('copy')` |
| `IntersectionObserver` | 12.1 | Partial | Avoid, or feature-detect (no lazy-observer patterns) |
| `Promise.finally` | 11.1 | **Yes** | Native |
| CSS custom properties `var()` | 9.1 | **Yes** | Allowed; keeps Bulma v1 working |
| CSS `color-mix()`, `:where()`/`:is()`, `oklch()` | 16.2 / 14 / 15.4 | No | Do not use (Bulma 1.0.4 avoids them — keep it that way) |
| CSS `aspect-ratio`, `backdrop-filter` | 15 / 9 (`-webkit-`) | Partial | Progressive enhancement only; must degrade cleanly |

### Login SPA Legacy Compatibility

The login SPA has the same hard **iOS 12 (Safari 12)** JavaScript floor as the public site. It is
served as a classic script from the versioned `/builtin/login-<hash>/` directory; do not ship it as
`type="module"` or add dynamic imports to the login shell. The login build must lower the final
generated bundle with Babel, minify with terser `ecma=2019`, and pass the login bundle compatibility
checker before release embedding.

The login SPA may prefer WebAssembly for Argon2id when available, but browsers without WebAssembly
must use the validated `argon2id.asm.js` classic-script fallback. Browser APIs newer than Safari
12 require explicit polyfills or feature-detected fallbacks before they are used; the login SPA
keeps feature-detected `queueMicrotask`, DOM convenience-method, and `String.prototype.replaceAll`
(compiled Svelte output needs it below Safari 13.1) shims. The emitted
login bundle must use the same legacy prelude and runtime smoke coverage as the public site.

The login shell must pass runtime config as escaped inert data on the `#login-app` mount element,
not through an inline executable script. The SPA reads `data-login-config` first and only keeps
`window.nopLoginConfig` as a test/development fallback.

## Logging & Telemetry

- Use `log::{debug, info, warn, error}`. Avoid `println!`.
- Include enough context for tracing without exposing sensitive data (e.g., never log raw passwords).
- Keep success logs at `info`, expected warnings at `warn`, security-relevant events at `warn`/`error`.
- A new log file or logging session must identify the process: product, binary path, PID, and package version.

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
