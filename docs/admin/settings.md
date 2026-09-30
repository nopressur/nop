# Admin Settings

Status: Developed

## Objectives

- Add a dedicated admin Settings section in the left navigation between Users and System.
- Keep the settings management contract explicit across the management bus, socket/WebSocket wire protocol, TypeScript codecs, CLI, and tests.
- Store website identity fields under the top-level `settings` section in `config.yaml`.
- Provide editable Website Name, Website Title, and Website Description settings through admin, CLI, and management surfaces.
- Use Website Name for user-visible site/app labels.
- Use Website Title for HTML `<title>` composition.
- Render Website Description as a public-page-only `<meta name="description">` value.

## Technical Details

### Website Identity

Website identity settings live in the existing top-level `settings` section:

```yaml
settings:
  name: "NoPressure"
  title: null
  description: "The AI native tiny little website system"
```

`settings.name` is the user-visible name. It is used for public navbar branding, public error-page branding, admin shell labels, and login/profile shell labels.

`settings.title` is the HTML title suffix for public pages. Public page title composition remains:

```text
<page title> | <website title>
```

When `settings.title` is unset, public pages use only the resolved page title.

`settings.description` is rendered only on public pages as:

```html
<meta name="description" content="...">
```

Admin, login, and profile shells must not render the website description meta tag.

The legacy top-level `app` section is compatibility input for existing installations. New generated and example configs use `settings.name`, `settings.title`, and `settings.description`.

### Auto-Migration

Existing `config.yaml` files that still contain:

```yaml
app:
  name: "NoPressure"
  description: "The AI native tiny little website system"
```

load successfully. During validated load, missing `settings.name` is populated from `app.name`, and missing `settings.description` is populated from `app.description`. If both old and new values are present, the new `settings.*` values take precedence.

The first successful config persistence after loading an old config writes the canonical shape:

```yaml
settings:
  name: "NoPressure"
  title: null
  description: "The AI native tiny little website system"
```

and does not reintroduce the top-level `app` identity section. Management updates to any website identity setting are also migration points: they preserve unrelated config values, write all website identity under `settings`, and omit old `app` identity output.

Auto-migration tests cover:

- Old `app.name` and `app.description` loading into runtime settings.
- Old config persistence writing `settings.name` and `settings.description`.
- New `settings.name` and `settings.description` taking precedence when old `app` is also present.
- Management settings updates migrating old config files while applying the requested update.
- Generated bootstrap and example configs containing only the canonical `settings` identity keys.

Validation rules for all three settings:

- Trim leading and trailing whitespace before validation and persistence.
- Empty `name` is invalid.
- Empty `title` clears the title and is stored as unset.
- Empty `description` clears the description and is stored as unset.
- Non-empty values must not contain ASCII control characters.
- `name` and `title` must be at most 120 characters.
- `description` must be at most 240 characters.
- Values are treated as plain text and HTML-escaped at render time.

Configuration persistence preserves unrelated config values. Runtime updates also update the in-memory settings snapshot used by public rendering so management changes take effect without a server restart for newly rendered public pages.

### Configuration

Settings live in the top-level `settings` section:

```yaml
settings:
  name: "NoPressure"
  title: null
  description: "The AI native tiny little website system"
```

`settings.name` is the required user-visible website name after normalization. Missing `settings.name` defaults to `NoPressure`, or to legacy `app.name` when an old config is migrated.

`settings.title` is optional. Missing `settings.title` means no suffix is appended to public HTML page titles. Empty or whitespace-only input clears the setting and is stored as unset. Legacy `settings.website_title` is accepted as a config-file alias and is persisted back as `settings.title`.

`settings.description` is optional. It renders as a public-page-only meta description when set. Empty or whitespace-only input clears the setting and is stored as unset.

Validation rules:

- Trim leading and trailing whitespace before validation and persistence.
- `name` must not be empty.
- `name` and `title` must be at most 120 characters.
- `description` must be at most 240 characters.
- ASCII control characters are rejected.
- Values are treated as plain text and HTML-escaped at render time.

Configuration persistence preserves unrelated config values. Runtime updates also update an in-memory settings snapshot used by public rendering so admin and CLI changes take effect without a server restart for newly rendered public pages.

### Management Domain

Settings use a dedicated management domain instead of the System domain. System remains reserved for operational daemon controls such as ping, logging, and log cleanup.

Domain:

- Name: `settings`
- Domain ID: `22`

Actions:

| Action | ID | Direction | Payload |
| --- | ---: | --- | --- |
| `settings_get` | `1` | request | `SettingsGetRequest {}` |
| `settings_set_name` | `2` | request | `SettingsSetNameRequest { name: String }` |
| `settings_set_title` | `3` | request | `SettingsSetTitleRequest { title: Option<String> }` |
| `settings_set_description` | `4` | request | `SettingsSetDescriptionRequest { description: Option<String> }` |
| `settings_get_ok` | `101` | response | `SettingsResponse { name: String, title: Option<String>, description: Option<String> }` |
| `settings_get_err` | `102` | response | `MessageResponse { message }` |
| `settings_set_name_ok` | `201` | response | `SettingsResponse { name: String, title: Option<String>, description: Option<String> }` |
| `settings_set_name_err` | `202` | response | `MessageResponse { message }` |
| `settings_set_title_ok` | `301` | response | `SettingsResponse { name: String, title: Option<String>, description: Option<String> }` |
| `settings_set_title_err` | `302` | response | `MessageResponse { message }` |
| `settings_set_description_ok` | `401` | response | `SettingsResponse { name: String, title: Option<String>, description: Option<String> }` |
| `settings_set_description_err` | `402` | response | `MessageResponse { message }` |

Wire encoding:

- Empty request payloads encode as zero bytes.
- Optional `title` and `description` fields use the standard optional-field bitset.
- `None` means unset/clear.
- String field limits match the validated configuration limits.

The Rust management contract, Rust codecs, TypeScript codecs, and shared vector fixtures include every Settings action.

### Admin SPA

The admin left navigation includes:

1. Content
2. Tags
3. Roles
4. Themes
5. Users, when local user management is enabled
6. Settings
7. System

The Settings route is `/settings`. The screen contains Website Name, Website Title, and Website Description controls with:

- Text inputs labelled `Website Name`, `Website Title`, and `Website Description`.
- Save and Cancel controls disabled until local changes exist.
- Client-side validation matching backend validation.
- Loading, saving, and error states using existing notification and form patterns.

The Settings route uses the existing admin WebSocket transport and CSRF/ticket flow. It must not call raw `fetch` for management operations.

### CLI

Settings commands are registered as a new CLI domain:

| Command | Purpose |
| --- | --- |
| `settings show` | Show Website Name, Website Title, and Website Description. |
| `settings name set --name <name>` | Set Website Name. |
| `settings title set --title <title>` | Set or replace Website Title. |
| `settings title clear` | Clear Website Title. |
| `settings description set --description <description>` | Set or replace Website Description. |
| `settings description clear` | Clear Website Description. |

CLI commands use the same management connector selection as other domains: socket first when available, then the in-process bypass when appropriate. The CLI must report validation errors as usage errors and connector/runtime errors as connector errors.

### Website-Wide Epoch

Successful management mutations to `settings.name`, `settings.title`, or `settings.description`
bump the website-wide release epoch through `ReleaseTracker`. The bump happens only after the
canonical config write succeeds and the in-memory runtime settings snapshot is updated. Rejected
updates and no-op updates do not bump the epoch.

The bump reasons map directly to the config keys:

| Config key | Epoch bump reason |
| --- | --- |
| `settings.name` | `settings.name` |
| `settings.title` | `settings.title` |
| `settings.description` | `settings.description` |

### Public HTML Title Rendering

Public HTML title composition uses the page title as the base title. When Website Title is set, the rendered `<title>` value becomes:

```text
<page title> | <website title>
```

When Website Title is unset, the current page title output is preserved. Both components are plain text and must be escaped before insertion into HTML.

### Testing Scope

Coverage includes:

- `nop-config` unit tests for missing settings, unset title, valid title, trimming, length rejection, and control-character rejection.
- Management domain tests for get, set, clear, validation error, config persistence, and runtime snapshot update.
- Wire vector tests in Rust and TypeScript for every Settings action.
- Admin SPA tests for navigation placement, route validation, service decoding, and Settings form behavior.
- CLI tests for `settings show`, `settings title set`, and `settings title clear`.
- Public rendering tests for title composition, escaping, navbar name, description meta rendering, and absent description.
- Playwright coverage validates the rendered browser title after updating Website Title.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
