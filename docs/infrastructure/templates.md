# Template System

NoPressure renders HTML through a mix of MiniJinja templates and lightweight placeholder substitution. Everything lives in `nop/src/templates.rs` and template files under `nop/src/*/templates/`.

## Rendering Paths

- **MiniJinja** (preferred):
  - `render_minijinja_template(engine, name, context)` looks up the template from an embedded loader (`embedded_template_loader`) and renders it with a `minijinja::Value` context.
  - `TEMPLATE_ENV` is a global `Lazy<Environment>` with the loader preconfigured.
  - Templates are embedded at compile time via `include_str!`, so no runtime I/O occurs.
  - The loader recognises:
    - Public layout/errors (`public/templates/*`).
    - Admin SPA shell template.
    - Login/profile SPA shell templates (SPA shells, not form-rendering templates).
    - Shortcode fragments (`public/shortcode/templates/*`).
- **Simple substitution**:
  - `render_template(template_content, vars)` performs `{key}` replacement using a `HashMap<&str, String>`.
  - Used for legacy scenarios; prefer MiniJinja for new code.

## Context Builders

Helper functions produce ready-to-render contexts:

- `AdminSpaShellContext` – Provides the admin SPA shell with runtime config and optional bootstrap JSON.
- `LoginSpaShellContext` – Provides the login/profile SPA shell with runtime config JSON and asset URLs.
- Public user menus are no longer server-rendered. The public layout includes a placeholder
  container only; the client fetches `GET /api/profile` to build the dropdown menu at runtime.
  The dropdown title uses the `display_name` field from the profile response.
- Each context sets asset URLs (`/builtin/...`), ensuring dev-mode and release builds use the same paths (served by `builtin.rs`).
- Login SPA shells should receive the versioned login asset directory name and inject stable
  filenames under that directory (see `docs/iam/modular-login.md`).

## Asset Conventions

- Templates reference CSS/JS under `/builtin/` (admin SPA bundles and the login/profile SPA bundle).
  The build script embeds these into release binaries.
- Public layout behavior (navbar toggles/dropdowns) is provided by `/builtin/site.js`, generated
  from `nop/ts/site` and injected by `public/templates/main_layout.html`.
- Login/profile SPA assets live under a versioned directory (for example `/builtin/login-<hash>/`)
  with stable filenames that the login shell injects.
  `build.rs` writes `login-spa-version.txt` and a compiled `LOGIN_SPA_DIR` constant so the context
  can resolve the correct versioned path at runtime.
- When adding new templates, add corresponding assets to `nop/builtin/` (or `public/`) and reference them via absolute `/builtin/...` paths.
- Keep logic inside Rust; templates focus on markup and minimal control flow.

## Fallbacks

- `load_template(name)` exposes a direct string loader for select templates (`public/main_layout`). It returns `std::io::Error` if the template name is unknown.
- Public theme failures fall back to `get_fallback_theme()` (defined in `public::markdown`), not the template layer.

## Adding Templates

1. Place the `.html` file under the appropriate module directory (e.g., `public/reports/templates/...`).
2. Extend `embedded_template_loader` with a `Some(include_str!(...))` match arm for the new file.
3. Create context helpers if repeated across handlers.
4. Call `render_minijinja_template(engine, "path/to/template.html", context)` from handlers.
5. For reusable contexts, expose functions returning `minijinja::Value` to keep controllers thin.

## Safety & Escaping

- MiniJinja auto-escapes HTML/XML templates (and JSON/JS/YAML contexts) via the `MiniJinjaEngine`
  auto-escape callback.
- Use `Value::from_safe_string` or `|safe` only for trusted HTML/URLs or JSON payloads intended to
  be embedded in `<script>` tags. The login `return_path` field is rendered verbatim for redirect
  handling.
- Avoid embedding user-provided HTML directly; instead, sanitise in Rust and pass as safe strings
  only when the input is explicitly trusted.
- Keeping templates embedded ensures deterministic builds and prevents runtime dependency on filesystem paths.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
