#!/usr/bin/env bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

set -euo pipefail

if rg -n "Mutex" -g "*.rs" .; then
  echo "Mutex usage detected; use channel-backed workers instead." >&2
  exit 1
fi
