#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "scripts/lib/rust-crates.sh requires bash." >&2
  return 1 2>/dev/null || exit 1
fi

RUST_CRATE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_REPO_ROOT="$(cd "${RUST_CRATE_LIB_DIR}/../.." && pwd)"
NOP_DIR="${RUST_REPO_ROOT}/nop"

RUST_CRATES=(
  "nop-config:${NOP_DIR}/crates/nop-config"
  "nop-library:${NOP_DIR}/crates/nop-library"
  "nop-content-store:${NOP_DIR}/crates/nop-content-store"
  "nop-iam-passwords:${NOP_DIR}/crates/nop-iam-passwords"
  "nop-management-contract:${NOP_DIR}/crates/nop-management-contract"
  "nop-management-errors:${NOP_DIR}/crates/nop-management-errors"
  "nop-roles:${NOP_DIR}/crates/nop-roles"
  "nop-rt-page-cache:${NOP_DIR}/crates/nop-rt-page-cache"
  "nop-rt-paths:${NOP_DIR}/crates/nop-rt-paths"
  "nop-rt-release:${NOP_DIR}/crates/nop-rt-release"
  "nop-rt-search-service:${NOP_DIR}/crates/nop-rt-search-service"
  "nop-management-workflows:${NOP_DIR}/crates/nop-management-workflows"
  "nop-security-paths:${NOP_DIR}/crates/nop-security-paths"
  "nop-management-content:${NOP_DIR}/crates/nop-management-content"
  "nop-management-yaml:${NOP_DIR}/crates/nop-management-yaml"
  "nop-management-roles:${NOP_DIR}/crates/nop-management-roles"
  "nop-management-search:${NOP_DIR}/crates/nop-management-search"
  "nop-rt-logging:${NOP_DIR}/crates/nop-rt-logging"
  "nop-management-system:${NOP_DIR}/crates/nop-management-system"
  "nop-management-tags:${NOP_DIR}/crates/nop-management-tags"
  "nop-management-users:${NOP_DIR}/crates/nop-management-users"
  "nop-rt-bootstrap:${NOP_DIR}/crates/nop-rt-bootstrap"
  "nop-testing:${NOP_DIR}/crates/nop-testing"
  "nop-rt-iam:${NOP_DIR}/crates/nop-rt-iam"
  "nop-management-bus:${NOP_DIR}/crates/nop-management-bus"
  "nop-rt-builtin:${NOP_DIR}/crates/nop-rt-builtin"
  "nop-rt-templates:${NOP_DIR}/crates/nop-rt-templates"
  "nop-rt-security:${NOP_DIR}/crates/nop-rt-security"
  "nop-rt-csrf:${NOP_DIR}/crates/nop-rt-csrf"
  "nop-rt-headers:${NOP_DIR}/crates/nop-rt-headers"
  "nop-admin:${NOP_DIR}/crates/nop-admin"
  "nop-api:${NOP_DIR}/crates/nop-api"
  "nop-public:${NOP_DIR}/crates/nop-public"
  "nop-rt-login:${NOP_DIR}/crates/nop-rt-login"
  "nop-rt-tls:${NOP_DIR}/crates/nop-rt-tls"
  "nop-rt-well-known:${NOP_DIR}/crates/nop-rt-well-known"
  "nop:${NOP_DIR}"
)

rust_crate_name() {
  local entry="$1"
  printf '%s\n' "${entry%%:*}"
}

rust_crate_dir() {
  local entry="$1"
  printf '%s\n' "${entry#*:}"
}

rust_crate_short_name() {
  local name="$1"
  if [[ "$name" == "nop" ]]; then
    printf '%s\n' "$name"
  else
    printf '%s\n' "${name#nop-}"
  fi
}

list_crates() {
  local entry
  local name
  local short_name
  local dir

  for entry in "${RUST_CRATES[@]}"; do
    name="$(rust_crate_name "$entry")"
    short_name="$(rust_crate_short_name "$name")"
    dir="$(rust_crate_dir "$entry")"
    if [[ "$name" == "$short_name" ]]; then
      printf '  %-28s %s\n' "$name" "$dir"
    else
      printf '  %-28s %s\n' "${name} (${short_name})" "$dir"
    fi
  done
}

resolve_crate_dir() {
  local selector="${1:-}"
  local entry
  local name
  local short_name
  local dir
  local matches=()

  if [[ -z "$selector" ]]; then
    echo "Missing Rust crate selector." >&2
    echo "Usage: scripts/crg.sh <crate> <cargo args...>" >&2
    echo "Known crates:" >&2
    list_crates >&2
    return 2
  fi

  for entry in "${RUST_CRATES[@]}"; do
    name="$(rust_crate_name "$entry")"
    short_name="$(rust_crate_short_name "$name")"
    if [[ "$selector" == "$name" || "$selector" == "$short_name" ]]; then
      matches+=("$entry")
    fi
  done

  if [[ "${#matches[@]}" -eq 0 ]]; then
    echo "Unknown Rust crate selector: $selector" >&2
    echo "Known crates:" >&2
    list_crates >&2
    return 2
  fi

  if [[ "${#matches[@]}" -gt 1 ]]; then
    echo "Ambiguous Rust crate selector: $selector" >&2
    echo "Matches:" >&2
    for entry in "${matches[@]}"; do
      name="$(rust_crate_name "$entry")"
      dir="$(rust_crate_dir "$entry")"
      printf '  %-28s %s\n' "$name" "$dir" >&2
    done
    return 2
  fi

  dir="$(rust_crate_dir "${matches[0]}")"
  if [[ ! -f "${dir}/Cargo.toml" ]]; then
    echo "Rust crate manifest not found: ${dir}/Cargo.toml" >&2
    return 1
  fi

  printf '%s\n' "$dir"
}
