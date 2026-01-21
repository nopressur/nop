#!/bin/bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: update-rust-vendor.sh [--ensure]

Downloads pinned Rust crates from crates.io, applies local patches, and writes
into nop/target/vendor.

Options:
  --ensure   Only update if the vendor directory or marker is missing/stale.
USAGE
}

mode="update"
case "${1:-}" in
  --ensure)
    mode="ensure"
    shift
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac

if [ $# -gt 0 ]; then
  echo "Unexpected argument: $1" >&2
  usage >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NOP_DIR="${REPO_ROOT}/nop"
VENDOR_ROOT="${NOP_DIR}/target/vendor"
PATCH_DIR="${SCRIPT_DIR}/vendor-patches"
MARKER_FILE="${VENDOR_ROOT}/.ready"

LERS_VERSION="0.4.0"
TRUST_DNS_PROTO_VERSION="0.23.2"
LERS_PATCH="${PATCH_DIR}/lers.patch"
TRUST_DNS_PATCH="${PATCH_DIR}/trust-dns-proto.patch"

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 1
  fi
}

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  echo "Missing required tool: sha256sum or shasum" >&2
  exit 1
}

render_marker() {
  printf "lers %s %s\ntrust-dns-proto %s %s\n" \
    "$LERS_VERSION" "$(hash_file "$LERS_PATCH")" \
    "$TRUST_DNS_PROTO_VERSION" "$(hash_file "$TRUST_DNS_PATCH")"
}

vendor_ready() {
  if [ ! -d "${VENDOR_ROOT}/lers" ]; then
    return 1
  fi
  if [ ! -d "${VENDOR_ROOT}/trust-dns-proto" ]; then
    return 1
  fi
  if [ ! -f "$MARKER_FILE" ]; then
    return 1
  fi
  local expected
  expected="$(render_marker)"
  if [ "$(cat "$MARKER_FILE")" != "$expected" ]; then
    return 1
  fi
  return 0
}

download_crate() {
  local name="$1"
  local version="$2"
  local dest="$3"
  local url="https://crates.io/api/v1/crates/${name}/${version}/download"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$dest"
    return
  fi
  echo "Missing required tool: curl or wget" >&2
  exit 1
}

apply_patch_file() {
  local dest="$1"
  local patch_file="$2"
  if [ ! -f "$patch_file" ]; then
    echo "Missing patch file: $patch_file" >&2
    exit 1
  fi
  patch -p1 -d "$dest" < "$patch_file"
}

if [ "$mode" = "ensure" ] && vendor_ready; then
  echo "Rust vendor already present; skipping download."
  exit 0
fi

require_tool tar
require_tool patch

if [ ! -d "$NOP_DIR" ]; then
  echo "Missing nop directory: $NOP_DIR" >&2
  exit 1
fi

mkdir -p "$VENDOR_ROOT"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

LERS_TARBALL="${TMP_DIR}/lers.tar.gz"
TRUST_TARBALL="${TMP_DIR}/trust-dns-proto.tar.gz"

download_crate "lers" "$LERS_VERSION" "$LERS_TARBALL"
download_crate "trust-dns-proto" "$TRUST_DNS_PROTO_VERSION" "$TRUST_TARBALL"

mkdir -p "${TMP_DIR}/extract"
tar -xzf "$LERS_TARBALL" -C "${TMP_DIR}/extract"
tar -xzf "$TRUST_TARBALL" -C "${TMP_DIR}/extract"

LERS_SRC="${TMP_DIR}/extract/lers-${LERS_VERSION}"
TRUST_SRC="${TMP_DIR}/extract/trust-dns-proto-${TRUST_DNS_PROTO_VERSION}"

if [ ! -d "$LERS_SRC" ]; then
  echo "Expected lers source missing: $LERS_SRC" >&2
  exit 1
fi
if [ ! -d "$TRUST_SRC" ]; then
  echo "Expected trust-dns-proto source missing: $TRUST_SRC" >&2
  exit 1
fi

rm -rf "${VENDOR_ROOT}/lers" "${VENDOR_ROOT}/trust-dns-proto"
mkdir -p "${VENDOR_ROOT}/lers" "${VENDOR_ROOT}/trust-dns-proto"

cp -a "${LERS_SRC}/." "${VENDOR_ROOT}/lers/"
cp -a "${TRUST_SRC}/." "${VENDOR_ROOT}/trust-dns-proto/"

apply_patch_file "${VENDOR_ROOT}/lers" "$LERS_PATCH"
apply_patch_file "${VENDOR_ROOT}/trust-dns-proto" "$TRUST_DNS_PATCH"

render_marker > "$MARKER_FILE"

echo "Rust vendor updated in ${VENDOR_ROOT}."
