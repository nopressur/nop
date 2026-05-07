#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/rust-crates.sh"

ADMIN_DIR="$NOP_DIR/ts/admin"
LOGIN_DIR="$NOP_DIR/ts/login"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$NOP_DIR/target/full-testing-scope}"

GENERATED_LOCKFILES=()

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 1
  fi
}

ensure_node_modules() {
  local dir="$1"
  if [[ ! -d "$dir/node_modules" || ! -x "$dir/node_modules/.bin/vitest" ]]; then
    (cd "$dir" && npm install)
  fi
}

cleanup_generated_lockfiles() {
  local lockfile
  for lockfile in "${GENERATED_LOCKFILES[@]}"; do
    rm -f "$lockfile"
  done
}

track_generated_lockfile() {
  local lockfile="$1"
  if [[ -f "$lockfile" ]]; then
    return
  fi
  GENERATED_LOCKFILES+=("$lockfile")
}

run_cargo_scope() {
  local label="$1"
  local dir="$2"
  local lockfile="$dir/Cargo.lock"

  if [[ ! -f "$dir/Cargo.toml" ]]; then
    echo "Rust crate manifest not found for $label: $dir/Cargo.toml" >&2
    exit 1
  fi

  track_generated_lockfile "$lockfile"

  echo "Formatting Rust crate: $label"
  (cd "$dir" && cargo fmt --all)

  echo "Testing Rust crate: $label"
  (cd "$dir" && cargo test)

  echo "Linting Rust crate: $label"
  (cd "$dir" && cargo clippy --all-targets -- -D warnings)
}

run_rust_full_testing_scope() {
  local entry
  local label
  local dir

  echo "Running Rust full testing scope..."
  echo "Rust scope: format, test, and clippy for dependency crates first, then nop."
  for entry in "${RUST_CRATES[@]}"; do
    label="${entry%%:*}"
    dir="${entry#*:}"
    run_cargo_scope "$label" "$dir"
  done
}

trap cleanup_generated_lockfiles EXIT

require_tool cargo
require_tool npm

if [[ ! -d "$ADMIN_DIR" ]]; then
  echo "Admin SPA directory not found: $ADMIN_DIR" >&2
  exit 1
fi
if [[ ! -d "$LOGIN_DIR" ]]; then
  echo "Login SPA directory not found: $LOGIN_DIR" >&2
  exit 1
fi

run_rust_full_testing_scope

echo "Ensuring admin SPA dependencies..."
ensure_node_modules "$ADMIN_DIR"
echo "Running admin SPA checks..."
(cd "$ADMIN_DIR" && npm run check)
echo "Running admin SPA tests..."
(cd "$ADMIN_DIR" && npm run test)

echo "Ensuring login SPA dependencies..."
ensure_node_modules "$LOGIN_DIR"
echo "Running login SPA checks..."
(cd "$LOGIN_DIR" && npm run check)
echo "Running login SPA tests..."
(cd "$LOGIN_DIR" && npm run test)
