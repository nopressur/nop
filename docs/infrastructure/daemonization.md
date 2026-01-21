# Daemonized Server Startup

Status: Developed

## Objectives

- Default the server process to a daemonized (double-fork) run mode when no CLI subcommands are provided.
- Provide a foreground opt-out flag (`-F`) for development and container workloads.
- Keep CLI subcommands in the foreground and reject `-F` when subcommands are present.
- Warn and fall back to foreground mode on builds that cannot daemonize (non-Unix).
- Enforce single-instance startup with a runtime-root PID file that is honored in both daemon and foreground runs.

## Technical Details

- **CLI behavior**:
  - `nop -C <root>` with no subcommands daemonizes by default (double-fork).
  - `nop -C <root> -F` runs in the foreground.
  - `-C <root>` and `-F` are order-insensitive when no subcommands are provided.
  - `nop <subcommand> ...` always runs in the foreground.
  - `-F` is rejected when subcommands are present to avoid ambiguity.
  - If bootstrap creates `config.yaml` or `users.yaml`, the server stays in the foreground for that run.
- **PID file guard**:
  - Store the PID file at `<runtime-root>/nop.pid`; only daemon runs create it, foreground runs never do.
  - Check the PID file before daemonizing or starting the foreground server; if the PID is running, fail fast with an "already running" error and do not daemonize.
  - Treat missing, empty, unparsable, or non-running PIDs as stale; delete the file before continuing.
  - Remove `nop.pid` on graceful shutdown; forced termination (for example `SIGKILL`) can leave a stale file.
  - CLI subcommands do not check or create the PID file.
  - Runtime root validation allows `nop.pid` as a top-level entry.
  - **Process state detection**:
    - macOS: use `sysctl` with `KERN_PROC_PID`, read `kinfo_proc.kp_proc.p_stat`, and treat `SZOMB` as not running.
    - Linux: parse `/proc/<pid>/stat` and treat state `Z` as not running; fall back to `kill(pid, 0)` when parsing is unavailable.
    - Other Unix: use `kill(pid, 0)`; treat `ESRCH` as not running and `EPERM` as running.
- **Daemonization (Unix)**:
  - Use `libc` to `fork`, `setsid`, and `fork` again to detach from the controlling terminal.
  - Set `umask(0)` and redirect stdin/stdout/stderr to `/dev/null`.
  - Ensure the runtime root is made absolute before daemonizing so bootstrap is unaffected by `chdir`.
- **Daemon logging**:
  - When daemonized, logs are written to `<runtime-root>/logs/` with size-based rotation.
  - Foreground runs continue to log to stdout and do not create log files.
- **Non-Unix behavior**:
  - If daemonization is requested on non-Unix builds, print a warning and continue in foreground mode.
- **Entrypoint structure**:
  - Convert the binary entrypoint to a sync `fn main()` that runs bootstrap, decides the final run mode, and daemonizes before the async runtime starts.
  - Move the server startup into an `async fn run_server(bootstrap, daemon_requested)` invoked via `actix_web::rt::System::new().block_on`.
- **Tests**:
  - Add unit tests for argument parsing to validate `-F` handling and subcommand rejection.
  - Ensure Playwright harness and CLI tests keep the server in the foreground by using `-F`.
  - Cover PID file parsing, stale cleanup, and bootstrap acceptance of `nop.pid`.
  - Run the full suite: `scripts/cargo.sh fmt`, `scripts/cargo.sh clippy -- -D warnings`, `scripts/cargo.sh test`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
