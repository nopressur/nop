#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/rust-crates.sh"

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/crg.sh <crate> <cargo args...>

Examples:
  scripts/crg.sh nop test --tests
  scripts/crg.sh rt-well-known test
  scripts/crg.sh management-bus clippy --all-targets -- -D warnings

Known crates:
USAGE
  list_crates >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -lt 2 ]]; then
  usage
  exit 2
fi

selector="$1"
shift

crate_dir="$(resolve_crate_dir "$selector")"
cd "$crate_dir"
exec cargo "$@"
