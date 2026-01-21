#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOP_DIR="$ROOT_DIR/nop"
ADMIN_DIR="$NOP_DIR/ts/admin"
LOGIN_DIR="$NOP_DIR/ts/login"

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

echo "Running Rust tests..."
"$ROOT_DIR/scripts/cargo.sh" test

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

echo "Running Playwright E2E tests..."
"$ROOT_DIR/scripts/run-playwright.sh"
