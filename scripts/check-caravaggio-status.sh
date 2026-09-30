#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ "$#" -eq 0 ]; then
    DIRS=("${REPO_ROOT}/docs" "${REPO_ROOT}/private/docs")
else
    DIRS=("$@")
fi

find_open() {
    local dir="$1"
    if command -v rg >/dev/null 2>&1; then
        rg -l --glob '*.md' '^Status: In Progress' "$dir" || true
    else
        grep -rl --include='*.md' '^Status: In Progress' "$dir" || true
    fi
}

OPEN_FILES=()
for dir in "${DIRS[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r file; do
        [ -n "$file" ] && OPEN_FILES+=("$file")
    done < <(find_open "$dir")
done

if [ "${#OPEN_FILES[@]}" -gt 0 ]; then
    echo "Unfinished Caravaggio documents detected:" >&2
    printf '  %s\n' "${OPEN_FILES[@]}" >&2
    echo "" >&2
    echo "master must not receive Status: In Progress documents. Either finish each" >&2
    echo "flagged Caravaggio (complete the remaining items, remove the action plan," >&2
    echo "confirm evergreen technical details, return to Status: Developed) or defer" >&2
    echo "it to Status: Updated Requirement with a new subsection describing what is" >&2
    echo "changing." >&2
    exit 1
fi

echo "No In Progress Caravaggio documents."
