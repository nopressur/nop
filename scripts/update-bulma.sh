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
Usage: update-bulma.sh [--ensure]

Downloads the pinned Bulma CSS version from scripts/bulma-version.txt into
nop/builtin/bulma.min.css.

Options:
  --ensure   Only download if the CSS file is missing.
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

version_file="${script_dir}/bulma-version.txt"
css_file="${repo_root}/nop/builtin/bulma.min.css"

if [ ! -f "$version_file" ]; then
    echo -e "${RED}Version file not found: $version_file${NC}" >&2
    exit 1
fi

version=$(tr -d '[:space:]' < "$version_file")
if [ -z "$version" ]; then
    echo -e "${RED}Version file is empty: $version_file${NC}" >&2
    exit 1
fi

if [ "$mode" = "ensure" ] && [ -f "$css_file" ]; then
    echo -e "${GREEN}Bulma CSS already present: $css_file${NC}"
    exit 0
fi

mkdir -p "$(dirname "$css_file")"

cdn_url="https://cdn.jsdelivr.net/npm/bulma@${version}/css/bulma.min.css"

echo "Downloading Bulma CSS ${version} from ${cdn_url}"

backup_file=""
if [ -f "$css_file" ]; then
    backup_file="${css_file}.backup"
    echo "Creating backup: $backup_file"
    cp "$css_file" "$backup_file"
fi

download_css() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$cdn_url" -o "$css_file"
        return 0
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q "$cdn_url" -O "$css_file"
        return 0
    fi
    return 1
}

if download_css; then
    echo -e "${GREEN}Bulma CSS updated to version $version${NC}"
    if [ -n "$backup_file" ]; then
        rm "$backup_file"
    fi
else
    echo -e "${RED}Failed to download Bulma CSS (need curl or wget).${NC}" >&2
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        mv "$backup_file" "$css_file"
        echo -e "${YELLOW}Restored backup file.${NC}"
    fi
    exit 1
fi
