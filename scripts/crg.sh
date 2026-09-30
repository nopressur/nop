#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Share the cargo registry cache across checkouts and VMs: default CARGO_HOME
# to a directory on the workspace root (the parent of this checkout) instead of
# the VM-local ~/.cargo, so downloaded crates are reused. An explicitly set
# CARGO_HOME always wins. Note the workspace root typically lives on a shared
# filesystem: avoid running cargo concurrently from multiple VMs, as file
# locking there may be unreliable.
if [[ -z "${CARGO_HOME:-}" ]]; then
  shared_cargo_home="$(cd "${SCRIPT_DIR}/../.." && pwd)/.cargo-home"
  if mkdir -p "${shared_cargo_home}" 2>/dev/null; then
    export CARGO_HOME="${shared_cargo_home}"
  fi
fi

source "${SCRIPT_DIR}/lib/rust-crates.sh"

# Shared compilation cache on shared storage (never root fs or home).
# An explicitly set SCCACHE_DIR or RUSTC_WRAPPER always wins.
if [[ -z "${SCCACHE_DIR:-}" ]]; then
  SCCACHE_DIR="/mnt/shared/cache"
  export SCCACHE_DIR
fi
mkdir -p "${SCCACHE_DIR}" 2>/dev/null || SCCACHE_DIR=""
if [[ -z "${RUSTC_WRAPPER:-}" && -n "${SCCACHE_DIR}" && -x /usr/bin/sccache ]]; then
  export RUSTC_WRAPPER=/usr/bin/sccache
fi

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
if cargo "$@"; then
  status=0
else
  status=$?
fi
if [[ -n "${SCCACHE_DIR:-}" && -d "${SCCACHE_DIR}" ]]; then
  echo "sccache cache: $(du -sh "${SCCACHE_DIR}" 2>/dev/null | cut -f1) in ${SCCACHE_DIR}"
fi
exit "$status"
