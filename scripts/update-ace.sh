#!/bin/bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat <<'USAGE'
Usage: update-ace.sh [--ensure]

Downloads the pinned Ace editor assets from scripts/ace-version.txt into
nop/builtin/.

Options:
  --ensure   Only download if the Ace assets are missing.
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
        echo -e "${RED}Unknown option: $1${NC}" >&2
        usage >&2
        exit 2
        ;;
esac

if [ $# -gt 0 ]; then
    echo -e "${RED}Unexpected argument: $1${NC}" >&2
    usage >&2
    exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/.." && pwd)

version_file="${script_dir}/ace-version.txt"
builtin_dir="${repo_root}/nop/builtin"

if [ ! -f "$version_file" ]; then
    echo -e "${RED}Version file not found: $version_file${NC}" >&2
    exit 1
fi

version=$(tr -d '[:space:]' < "$version_file")
if [ -z "$version" ]; then
    echo -e "${RED}Version file is empty: $version_file${NC}" >&2
    exit 1
fi

ace_files=(
    "ace.js"
    "ext-language_tools.js"
    "mode-html.js"
    "mode-markdown.js"
    "theme-github.js"
    "theme-github_dark.js"
    "theme-github_light_default.js"
    "theme-monokai.js"
)

if [ "$mode" = "ensure" ]; then
    missing=()
    for file in "${ace_files[@]}"; do
        if [ ! -f "${builtin_dir}/${file}" ]; then
            missing+=("$file")
        fi
    done
    if [ ${#missing[@]} -eq 0 ]; then
        echo -e "${GREEN}Ace assets already present: ${builtin_dir}${NC}"
        exit 0
    fi
fi

base_url="https://cdn.jsdelivr.net/npm/ace-builds@${version}/src-min-noconflict"

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
        return 0
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dest"
        return 0
    fi
    return 1
}

temp_dir=$(mktemp -d)
backup_dir=""

cleanup() {
    if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
        rm -rf "$temp_dir"
    fi
    if [ -n "$backup_dir" ] && [ -d "$backup_dir" ]; then
        rm -rf "$backup_dir"
    fi
}

restore_backup() {
    if [ -z "$backup_dir" ] || [ ! -d "$backup_dir" ]; then
        return
    fi
    echo -e "${YELLOW}Restoring previous Ace assets.${NC}" >&2
    for file in "${ace_files[@]}"; do
        if [ -f "${backup_dir}/${file}" ]; then
            cp "${backup_dir}/${file}" "${builtin_dir}/${file}"
        else
            rm -f "${builtin_dir}/${file}"
        fi
    done
}

trap cleanup EXIT

echo "Downloading Ace assets ${version} from ${base_url}"
for file in "${ace_files[@]}"; do
    url="${base_url}/${file}"
    dest="${temp_dir}/${file}"
    echo "  - ${file}"
    if ! download_file "$url" "$dest"; then
        echo -e "${RED}Failed to download ${url} (need curl or wget).${NC}" >&2
        exit 1
    fi
    if [ ! -s "$dest" ]; then
        echo -e "${RED}Downloaded file is empty: ${file}${NC}" >&2
        exit 1
    fi
done

mkdir -p "$builtin_dir"

backup_dir=$(mktemp -d)
for file in "${ace_files[@]}"; do
    if [ -f "${builtin_dir}/${file}" ]; then
        cp "${builtin_dir}/${file}" "${backup_dir}/${file}"
    fi
done

trap restore_backup ERR

for file in "${ace_files[@]}"; do
    cp "${temp_dir}/${file}" "${builtin_dir}/${file}"
done

trap - ERR

echo -e "${GREEN}Ace assets updated to version ${version}.${NC}"
