#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PW_DIR="$ROOT_DIR/tests/playwright"
BROWSERS_DIR="$PW_DIR/.cache/playwright-browsers"

if [[ ! -d "$PW_DIR" ]]; then
  echo "Playwright directory not found: $PW_DIR" >&2
  exit 1
fi

for tool in node npm npx; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 1
  fi
done

echo "Installing Playwright dependencies..."
(cd "$PW_DIR" && npm install --no-package-lock)
echo "Installing Playwright browsers..."
(cd "$PW_DIR" && PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_DIR" npx playwright install)

mkdir -p "$BROWSERS_DIR"

export PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_DIR"
export PW_RUN_ID="${PW_RUN_ID:-$(date +%s)}"

cd "$PW_DIR"

npx playwright test --project=e2e
