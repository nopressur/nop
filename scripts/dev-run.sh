#!/bin/bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

mkdir -p "${REPO_ROOT}/runtime"

"${REPO_ROOT}/scripts/cargo.sh" build

exec "${REPO_ROOT}/nop/target/debug/nop" -C "${REPO_ROOT}/runtime" -F
