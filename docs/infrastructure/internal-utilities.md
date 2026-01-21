# Internal Utilities and System Logging

Status: Developed

## Objectives

- Provide reusable helpers in `nop/src/util/` for CSRF, streaming, MIME detection, logging, daemonization, and color utilities.
- Capture daemon-mode logs in a canonical runtime `logs/` directory with configurable rotation while keeping foreground logging on stdout only.
- Expose logging rotation settings through config, the management bus, CLI, and the admin UI system settings screen.
- Keep utilities documented, stable, and aligned with platform conventions (security, logging, MIME correctness).

## Technical Details

### CSRF Helpers

- `csrf_helper.rs` defines `CsrfTokenStore` (see `docs/infrastructure/csrf-protection.md`), providing token issuance, renewal, and cleanup. Tokens are UUID strings mapped to JWT IDs and expire after one hour.
- `CsrfTokenStore` runs as a single-writer channel worker so token mutations do not share locks.
- `csrf_validation.rs` exposes mid-level utilities:
  - `CSRF_HEADER_NAME` (`X-CSRF-Token`) – required header for mutating requests.
  - `validate_csrf_token(store, token, jwt_id)` – delegates to the store (renewing timestamps).
  - `mark_csrf_validated(req)` – stores a marker in request extensions so downstream handlers know CSRF succeeded.
- `csrf_middleware.rs` wires the validation into Actix. It respects the exemption list generated from templates (`/login`, `/admin/csrf-token-api`, etc.) and supports dev-mode bypass (uses `"localhost"` as JWT ID) in debug builds only; release builds ignore dev-mode.

### Streaming Helpers

- `streaming_helper.rs` parses and evaluates HTTP `Range` headers to support partial content delivery:
  - `parse_range_header` → `Vec<HttpRange>` (`Closed`, `Open`, `Suffix`).
  - `calculate_range_bounds(range, file_size)` → `(start, end)` if satisfiable.
  - `format_content_range_header` builds the `Content-Range` response value.
- Public asset handlers use these helpers when `config.streaming.enabled` is true, ensuring requests for large videos/audio are served efficiently.

### MIME Helpers

- `mime_helper.rs` contains MIME detection helpers:
  - `detect_mime_type(path, content)` with `infer` fallback to `mime_guess`.
- The flat storage model stores MIME types in sidecar metadata. There are no `.mime-types` manifests.

### Logging Helpers

- `log_level_changer.rs` wraps an `env_logger::Logger` and allows per-target level rewriting (`init_logger(rules, logger)`).
  - Currently bumps `html5ever` trace noise down to debug.
  - Use this hook when integrating noisy dependencies that should be quieter in production.
- Log formatting remains aligned with the existing `env_logger` setup in `main.rs` (UTC timestamp, level, target, message).
- Log rotation uses a single-writer worker behind a channel to avoid shared-lock state.

### Logging Configuration

- `config.yaml` retains `logging.level` and adds:
  - `logging.rotation.max_size_mb` (default 16).
  - `logging.rotation.max_files` (default 10).
- Validation rules:
  - `max_size_mb` must be >= 1 and <= 1024.
  - `max_files` must be >= 1 and <= 100.
- Configuration updates from the management bus must persist to `config.yaml` and update the in-memory config for future rotations.
- Foreground runs honor the config for persistence only; they continue to log to stdout and do not create files.

### Daemon Log Files and Rotation

- Runtime roots accept a canonical `logs/` directory alongside `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/`.
- Foreground runs (including CLI subcommands) continue to log to stdout only and must not create log files.
- Daemon runs write logs to `<runtime-root>/logs/nopressure.log` with size-based rotation:
  - Rotation uses `logging.rotation.max_size_mb` and `logging.rotation.max_files`.
  - Default maximum size per file: 16 MiB.
  - Default total files retained: 10 (active file plus 9 rotated files).
  - Rotated files are named `nopressure.log.1` through `nopressure.log.9`, with `.1` as the most recent rollover.
- The `logs/` directory is created on demand when daemon logging is enabled; it must be writable or startup fails with a clear, actionable error.
- Log rotation uses a `Write` target compatible with `env_logger::Target::Pipe`, keeping the existing `log_level_changer` wrapper in place.
- Rotation semantics:
  - Changing `max_size_mb` affects only new log files. Existing log files are not truncated or resized.
  - Increasing `max_files` does not restore deleted logs.
  - Decreasing `max_files` deletes the oldest rotated logs immediately to meet the new limit.
- Log cleanup removes only log files within `logs/` (no recursion) and keeps the `logs/` directory intact.

### Management Bus: System Logging Settings

- Extend the System domain (ID 0) with logging configuration and cleanup actions.
- Action IDs:
  - `GetLoggingConfig` (request): 4
  - `GetLoggingConfigOk` (response): 5
  - `GetLoggingConfigErr` (response): 6
  - `SetLoggingConfig` (request): 7
  - `SetLoggingConfigOk` (response): 8
  - `SetLoggingConfigErr` (response): 9
  - `ClearLogs` (request): 10
  - `ClearLogsOk` (response): 11
  - `ClearLogsErr` (response): 12
- Request/response payloads:
  - `GetLoggingConfigRequest {}` (empty).
  - `GetLoggingConfigResponse { level, rotation_max_size_mb, rotation_max_files, run_mode, file_logging_active }`.
  - `SetLoggingConfigRequest { rotation_max_size_mb, rotation_max_files }`.
  - `SetLoggingConfigResponse { level, rotation_max_size_mb, rotation_max_files, file_logging_active }`.
  - `ClearLogsResponse { deleted_files, deleted_bytes }` (optional counters) plus `message`.
- Field limits:
  - `level` and `run_mode` max 16 chars.
  - `rotation_max_size_mb` and `rotation_max_files` use `FieldLimit::Range`.
- Behavior:
  - `GetLoggingConfig` returns the current config plus runtime `run_mode` (`foreground` or `daemon`) and whether file logging is active.
  - `SetLoggingConfig` updates config and persists to `config.yaml`; it does not change log level.
  - `ClearLogs` deletes log files in `logs/` and returns counts; it is a no-op if the directory is missing or empty.

### CLI: System Logging Commands

- Add System commands under `nop system`:
  - `nop system logging show` (alias `log show`): prints `level`, `max_size_mb`, `max_files`, and `file_logging_active`.
  - `nop system logging set --max-size-mb <n> --max-files <n>`: updates rotation config, requiring both values.
  - `nop system logging clear`: clears all log files.
- CLI output should be a single-line message on success plus any structured fields on stderr/stdout as appropriate for existing CLI patterns.

### Admin UI: System Settings

- Add a new top-level "System" section in the admin SPA navigation.
- The System screen contains independent subsections, each with its own Save and Cancel buttons:
  - Save/Cancel buttons are disabled until the subsection has local changes.
  - Cancel restores fields to the last loaded values from the server.
- Logging subsection requirements:
  - Fields for `max_size_mb` and `max_files`.
  - Display the current `run_mode` and whether file logging is active.
  - Include inline messaging: when running in foreground, warn that file logging is inactive and changes take effect only when daemonized.
  - Provide a "Clear Logs" button with a confirmation prompt.
  - Clear Logs operates independently from Save/Cancel and is disabled while a clear request is in-flight.
- System subsections submit through the management WebSocket connector using the System domain actions above.

### WebSocket and Protocol Updates

- Extend the management registry to include the new System action IDs and codecs.
- Update WebSocket protocol bindings in `nop/ts/admin/src/protocol/` to include the new request/response payloads and action IDs.
- Ensure the WebSocket coordinator and CLI connector share the same codec validation for `rotation_max_size_mb` and `rotation_max_files`.

### Daemonization Helper

- `daemon.rs` provides `daemonize_or_warn`, which double-forks on Unix to detach the server process and falls back to a foreground warning on non-Unix builds.
- The helper redirects stdin/stdout/stderr to `/dev/null` and clears the umask before startup, so daemon logging must not rely on stdio.

### Color Utilities

- `color_hsv.rs` offers RGB↔HSV conversion and `increase_saturation`, used by shortcodes (link cards) to derive palette-friendly backgrounds.
- Helpful for generating on-the-fly color variants without bringing in heavier graphics crates.

### Module Re-exports

- `util/mod.rs` re-exports the most common helpers (`CsrfTokenStore`, `CsrfValidationMiddlewareFactory`, MIME functions, range helpers, color conversions) so callers can import `crate::util::*`.
- When adding new utilities, export them here only if they are broadly applicable.

### Usage Guidance

- Prefer these utilities over ad-hoc implementations to stay aligned with platform conventions (security, logging, MIME correctness).
- When introducing new helpers, consider concurrency requirements (many existing helpers recover from poisoned locks by clearing state) and add tests alongside the module.

### Testing Scope

- Verify root guard acceptance of `logs/` and ensure unexpected entries still fail fast.
- Validate that daemon mode selects the file logger while foreground mode keeps stdout logging and does not create log files.
- Exercise log rotation with a small test size limit to confirm rollover naming, retention count, and size caps.
- Add management bus + CLI + WebSocket tests for `GetLoggingConfig`, `SetLoggingConfig`, and `ClearLogs`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
