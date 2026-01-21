# Automatic Runtime Bootstrap (Working Site Defaults)

Status: Developed

## Objectives

- Ensure a clean runtime root can start and serve a basic site without manual setup.
- Auto-create missing config, users, and directory structure on every startup without overwriting existing data.
- Log every automatic action with clear remediation guidance (notably for default credentials).
- Respect `-C <root>` so bootstrap works for any runtime root.

## Technical Details

### Runtime Root Validation

- Bootstrap validates the runtime root contains only these top-level entries:
  - `config.yaml`
  - `users.yaml`
  - `content/`
  - `themes/`
  - `state/`
  - `logs/`
  - `nop.pid`
- Any other top-level file or directory is treated as a fatal bootstrap error to prevent running in a non-dedicated data directory.

### Well-Known Handling

- Bootstrap must not create or require `state/sys/well-known`.
- Auto-generated `config.yaml` must not include `tls.well_known.root_dir`.
- Well-known responses are in-memory handlers owned by the TLS subsystem (and future modules), so no well-known directory is part of the runtime root contract.

### Startup Integration

Bootstrap runs immediately after resolving the runtime root (`-C <root>` or CWD) and before normal startup flow, with this sequence:

1. **Runtime root check**:
   - If the runtime root does not exist, create it.
   - If it contains any unexpected top-level entries (not in the required list), fail fast with a clear error.
2. **Config file check**:
   - If `config.yaml` exists, validate it as today. Any validation error is fatal (fail fast).
   - If `config.yaml` is missing, generate defaults (see below), write it, and continue.
3. **Users file check**:
   - If `users.auth_method` resolves to `local`, then:
     - If `users.yaml` exists, validate it as today.
     - If `users.yaml` is missing, generate it with a default admin account (see below), log the password with a warning to change it, and continue.
   - If `users.auth_method` resolves to `oidc`, do not create `users.yaml`.
4. **Runtime paths check**:
   - Ensure `content/`, `themes/`, `state/` (plus `state/sys`, `state/sc`) exist; create only what is missing.
   - If `content/` or `themes/` were missing, create a default home object (blob + sidecar) and `themes/default.html` using the embedded red theme template.
5. **Run mode decision**:
   - If bootstrap created `config.yaml` or `users.yaml`, the server stays in the foreground for that run to keep credentials visible.
6. **Normal startup flow**:
   - Proceed with the existing flow (`Config::load_and_validate`, `RuntimePaths::from_root`, TLS bootstrapping, etc.).
   - TLS material handling follows current behavior: self-signed generates on demand, user-provided fails fast if missing, ACME attempts issuance.

Bootstrap errors are fatal and should surface as concise, actionable log messages. The bootstrap step must be idempotent and never overwrite existing files.

### Required Runtime Root Layout

The bootstrap step ensures all required root-level components exist (or are created if missing). Any additional top-level entries are rejected.

- `config.yaml`
- `users.yaml`
- `content/`
  - Default home object blob + sidecar (created if missing and `content/` was created or if required file is missing)
- `themes/`
  - `themes/default.html` (created if missing; content sourced from embedded red theme)
- `state/`
  - `state/sys/`
  - `state/sc/`
  - `state/sys/tls/` (when TLS is configured or auto-configured)
- `logs/` (created when daemon logging is enabled)
- `nop.pid` (created only while the daemon is running)

### Auto-Generated `config.yaml`

If `config.yaml` is missing, bootstrap writes a minimal, working configuration that passes validation and enables TLS with self-signed certificates.

Required defaults:

- HTTP port: `7080` (well-known only, when TLS is enabled)
- HTTPS port: `7443` (main listener when TLS is enabled)
- TLS mode: `self-signed`
- TLS domains: `localhost` (or another safe default for SANs)
- Admin path: `/admin`
- Local auth enabled with a generated JWT secret
- TLS is always enabled for auto-generated config (HTTPS main + HTTP well-known).

Proposed template (exact keys to match validation rules):

```yaml
server:
  host: "0.0.0.0"
  port: 7443
  http_port: 7080
  workers: 4

admin:
  path: "/admin"

tls:
  mode: "self-signed"
  domains:
    - "localhost"

users:
  auth_method: "local"
  local:
    jwt:
      secret: "<generated>"

logging:
  level: "info"
  rotation:
    max_size_mb: 16
    max_files: 10

app:
  name: "NoPressure"
  description: "A lightweight web content management system"
```

Notes:
- The JWT `secret` must be generated at bootstrap time and not reused across installs.

### Auto-Generated `users.yaml`

If `users.yaml` is missing, bootstrap creates a local admin account:

- Username/key: `admin@example.com`
- Name: `Administrator`
- Roles: `admin`
- Password: 16 characters, ASCII alphanumeric only (`A-Za-z0-9`)
- Password generation must be cryptographically strong (`OsRng` or equivalent).
- The plaintext password is logged once with a warning to change it immediately.
- The stored password in `users.yaml` must follow the password provider format described in
  `docs/iam/password-login.md`.
- Auto-bootstrap uses the backend two-phase hashing helpers on the plaintext password before
  writing the user record.
- `password_version` starts at `1` to support JWT invalidation on password changes.

Example output structure:

```yaml
admin@example.com:
  name: "Administrator"
  password: "<password provider block>"
  password_version: 1
  roles:
    - "admin"
```

### Auto-Generated `roles.yaml`

If `state/sys/roles.yaml` is missing, bootstrap creates a minimal role set:

- Always include `admin`.
- Roles follow the same validation rules documented in `docs/content/role-management.md`.

Example output structure:

```yaml
- admin
```

### Default Content and Theme

When required content/theme files are missing:

- The default home object should be created with a minimal, working page that renders in the default theme. Keep it simple and include a short notice that the site was auto-generated.
- The home object sidecar should include the canonical alias (default `index`) and a title unless
  the home route is configured to `/id/<hex>`.
- `themes/default.html` should be created from an embedded template:
  - Use the existing red theme styling (distinctive warning red to prompt change).
  - Embed the template as a static string in code (no external file dependency at runtime).
  - Write the embedded template into `themes/default.html` only when the file is missing.

### Logging and Safety

- Log each created item individually (config, users, directories, content, theme, TLS dirs).
- If an admin user is auto-created, log an explicit warning: the password must be changed.
- Never overwrite user-supplied files or directories; only create when missing.
- If an existing file is unreadable or invalid, keep current behavior (fail fast with a clear error) rather than overwriting.

### Testing Scope

- Unit tests for bootstrap logic using temporary runtime roots:
  - Missing `config.yaml` creates expected defaults (ports 7080/7443, self-signed TLS, local auth).
  - Missing `users.yaml` creates admin with a 16-char alphanumeric password and a password
    provider block (see `docs/iam/password-login.md`).
  - Missing `content/` and `themes/` create the home object (blob + sidecar) and `themes/default.html` from embedded red theme.
  - Idempotency: re-running bootstrap does not modify existing files.
  - `-C <root>` path handling uses the provided directory.
- Add tests to ensure TLS directories (`state/sys/tls`) are created when TLS is configured.
- Assert bootstrap fails fast when unexpected top-level entries exist in the runtime root.
- Assert bootstrap does not create or require `state/sys/well-known`.

### Documentation Updates

- Update `docs/infrastructure/main.md` to include the bootstrap step before config loading.
- Update `docs/devops/configuration.md` with the new auto-generation behavior and defaults.
- Add a brief note in deployment docs if required to explain default ports and TLS material location.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
