#!/bin/bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_SCRIPT="${SCRIPT_DIR}/update-rust-vendor.sh"

if [ ! -x "$VENDOR_SCRIPT" ]; then
  echo "Missing vendor update script: $VENDOR_SCRIPT" >&2
  exit 1
fi

"$VENDOR_SCRIPT" --ensure

CARGO_DIR="${CARGO_DIR:-}"
if [ -n "$CARGO_DIR" ]; then
  if [ ! -f "$CARGO_DIR/Cargo.toml" ]; then
    echo "CARGO_DIR does not contain Cargo.toml: $CARGO_DIR" >&2
    exit 1
  fi
elif [ -f "${PWD}/Cargo.toml" ]; then
  CARGO_DIR="$PWD"
elif [ -f "${REPO_ROOT}/nop/Cargo.toml" ]; then
  CARGO_DIR="${REPO_ROOT}/nop"
else
  echo "No Cargo.toml found; set CARGO_DIR or run from a crate directory." >&2
  exit 1
fi

if [ "$CARGO_DIR" = "$PWD" ]; then
  exec cargo "$@"
fi

cd "$CARGO_DIR"
exec cargo "$@"
