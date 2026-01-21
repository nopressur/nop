# NoPressure Documentation Guide

This file is the entry point for contributors and AI assistants. It explains where documentation belongs and provides a map of the current docs.

## System Snapshot

- **Runtime**: Rust + Actix Web, packaged as a single binary with embedded admin/static assets in release builds.
- **Content Model**: Markdown + sidecar metadata stored in `content/`; IDs are canonical, aliases are optional for routing, and navbar metadata drives navigation.
- **Interfaces**: Public site, admin UI, and JSON endpoints guarded by JWT-backed RBAC.
- **Key Services**: Authentication (`iam`, `login`), security middleware (`security`, CSRF), templating (`templates` + MiniJinja), admin tooling (`admin/*`), management bus (`management/*`), rendering pipeline (`public/*`), shared helpers (`util/*`), configuration (`config`), entrypoint (`docs/infrastructure/main.md`).

## Documentation Placement

Choose the home that matches the primary purpose of the document and avoid duplicating content across sections.

- admin: Admin-facing behavior and requirements, covering the admin UI plus the CLI and management bus requirements that support admin features. Exception: content administration lives under `content/` for end-to-end coverage.
- content: The public-facing content experience and the content model the system serves, including content rules, rendering, public RBAC rules, and end-to-end content administration behavior.
- iam: Authentication, authorization, login flows, and IAM-specific security behavior (lockouts, return-path validation).
- management: The plumbing behind administration. This is the management bus, domain/action contracts, connectors, and protocols that power admin and CLI interactions.
- infrastructure: Core runtime wiring and underlying technical capabilities used across the system (storage, templates, TLS, internal utilities, network and filesystem security).
- devops: How to build, test, release, configure, and run the system. This is about operating the product, not the product itself.
- standards: Coding and testing conventions, style rules, and contribution practices.
- modules: Self-contained feature modules shared across the system (for example, shortcodes).
- Do not create a `features` directory at any level. Feature documents live in the owning domain directory.

## Module Boundaries

The `public` module owns the core content model, including `PageMetaCache` as the systemwide source of content metadata and access rules. IAM depends on that cache by design to make authorization decisions about which users can view public content.

## Documentation Map

### Content Storage and Public Model
- `docs/infrastructure/storage.md` - On-disk content contract, sidecar metadata, and write expectations.
- `docs/content/content-model.md` - Routing, rendering, navigation, and public access control rules.
- `docs/modules/shortcodes.md` - Parser syntax, built-in handlers, extension workflow.
- `docs/content/public-rbac.md` - Public RBAC rules and access outcomes.
- `docs/content/role-management.md` - Role storage, validation, CRUD, and cascades.
- `docs/content/file-migration.md` - Legacy migration into flat storage.

### Admin Experience
- `docs/content/content-management.md` - Admin content operations, uploads, metadata edits, and cache updates.
- `docs/admin/ui.md` - Admin SPA architecture, UX requirements, and UI integration details.
- `docs/admin/list-control-guideline.md` - Admin list interaction pattern and keyboard navigation guidelines.
- `docs/admin/user-management.md` - User management UI and management bus integration.

### CLI
- `CLI.md` - End-user CLI usage for the `nop` binary (runtime roots, commands, and examples).

### Management Bus
- `docs/management/architecture.md` - Domain boundaries, message routing, and error flow.
- `docs/management/domains.md` - Domain registry, handlers, and auth decisions.
- `docs/management/operations.md` - Operation contracts for page, theme, and user actions.
- `docs/management/connector-socket.md` - Management connector protocol and framing (socket + WebSocket).
- `docs/management/wire-serialization.md` - Wire serialization spec for management connectors.
- `docs/management/connector-cli-bypass.md` - CLI connector and bypass details.
- `docs/management/troubleshooting.md` - Diagnostics, logs, and failure modes.
- `docs/management/cli-architecture.md` - CLI wiring and auth flow.
- `docs/admin/user-management.md` - Management bus user operations.

### DevOps & Platform
- `docs/devops/build-and-release.md` - Build modes, asset embedding, multi-target release process.
- `docs/devops/configuration.md` - Config schema, defaults, validation, secrets handling.
- `docs/devops/tooling.md` - Helper scripts (`scripts/cargo.sh`, `scripts/bump-version.sh`) plus Bulma (`scripts/update-bulma.sh`) and Ace (`scripts/update-ace.sh`) updaters.

### Infrastructure Support Modules
- `docs/infrastructure/csrf-protection.md` - CSRF protection architecture and behavior.
- `docs/infrastructure/templates.md` - MiniJinja environment, context helpers, asset conventions.
- `docs/infrastructure/network-security.md` - Request routing guards and well-known handling.
- `docs/infrastructure/filesystem-security.md` - Canonical path enforcement and safe file creation.
- `docs/infrastructure/daemonization.md` - Daemonized startup behavior, PID guards, and logging.
- `docs/infrastructure/internal-utilities.md` - CSRF store, streaming ranges, MIME detection, logging helpers, color utilities.

### IAM
- `docs/iam/authz-authn.md` - Login flow, provider overview, role aggregation, config knobs.
- `docs/iam/auth-middleware.md` - JWT issuance, cookie rules, and request-time auth behavior.
- `docs/iam/modular-login.md` - Modular login SPA architecture and provider framework.
- `docs/iam/modular-profile.md` - Modular profile SPA architecture and provider modules.
- `docs/iam/password-login.md` - Argon2id password login flow requirements.
- `docs/iam/security.md` - Login lockouts, IP tracking, and return-path validation.

### Features and Test Suites
- `docs/standards/api-test-suite.md` - API test coverage and harness details.
- `docs/devops/playwright-ui-tests.md` - UI test harness and workflows.
- `docs/content/tags.md` - Tag model, access rules, and listing behavior.
- `docs/infrastructure/tls.md` - TLS feature behavior and validation rules.
- `docs/infrastructure/tantivy.md` - Tantivy in-memory directory example and notes.

### Core Runtime
- `docs/infrastructure/main.md` - Startup flow, middleware wiring, and failure behavior.

### Standards
- `docs/standards/coding.md` - Style conventions, module structure, error handling, security, logging.
- `docs/standards/testing.md` - Unit/integration patterns, hermetic principles, and test layout.

### Security
- `docs/threat-modeling.md` - Non-exhaustive threat modeling notes.


## How to Use This Library

1. **Start with Standards**: Read `coding.md` and `testing.md` before writing code.
2. **Follow Storage and Public Model**: Use `docs/infrastructure/storage.md` and `docs/content/content-model.md` for core behavior.
3. **Check Domain Docs**: Apply the DevOps/Admin/IAM/Infrastructure docs for the area you are touching.
4. **Follow Runtime Flow**: Use `docs/infrastructure/main.md` to understand startup and middleware ordering.
5. **Review & Iterate**: Update this file when the documentation map changes.

## Quick Reference for New Work

- **Adding a Page/Edit Feature** -> `docs/content/content-management.md`, `docs/content/content-model.md`.
- **Modifying Auth or RBAC** -> `docs/iam/authz-authn.md`, `docs/iam/auth-middleware.md`,
  `docs/iam/modular-login.md`, `docs/iam/password-login.md`,
  `docs/infrastructure/csrf-protection.md`, `docs/content/public-rbac.md`,
  `docs/content/role-management.md`.
- **Adding Security Guards** -> `docs/iam/security.md`, `docs/infrastructure/network-security.md`,
  `docs/infrastructure/filesystem-security.md`, `docs/infrastructure/csrf-protection.md`, `docs/standards/coding.md`.
- **Changing Build/Deployment** -> `docs/devops/build-and-release.md`, `docs/devops/configuration.md`.
- **Introducing Templates/Assets** -> `docs/infrastructure/templates.md`, `docs/content/content-model.md`.
- **Changing Storage Layout** -> `docs/infrastructure/storage.md`, `docs/content/file-migration.md`, `docs/content/content-model.md`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
