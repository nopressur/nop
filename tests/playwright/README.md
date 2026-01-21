# Playwright Harness

## Setup

```bash
cd tests/playwright
npm install
npx playwright install
```

## Run

```bash
cd tests/playwright
npm run test:e2e
```

## Environment Overrides

- `NOP_BINARY`: use a prebuilt `nop` binary instead of `scripts/cargo.sh run`.
- `CARGO_TARGET_DIR`: override where cargo writes build artifacts.
- `PW_RUN_ID`: suffix for temp artifact directories (default: `local`).
- `PW_OUTPUT_DIR`: explicit artifacts directory (defaults to a temp folder).
- `PW_RNG_SEED`: deterministic seed for humanized input (defaults to test title path).

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
