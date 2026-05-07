# Threat Modeling

This document is a non-exhaustive threat modeling log. It collects potential risks, assumptions,
and decisions about them.

## Concerns and Dispositions

- Username enumeration via `fetch_front_end_salt` timing differences is assessed as not a risk.
  The delta between reading a small file and generating random bytes is within real-world network
  jitter, and login lockouts reduce brute-force feasibility.


- Dev mode access bypass is only compiled in debug builds (`cfg!(debug_assertions)`); release
  builds do not allow dev-mode bypass. Keep this constraint in mind when evaluating threat
  scenarios.
- Admin WebSocket connections are authenticated and treated as the authoritative source of actor
  identity; server-side handlers must enforce self-action restrictions (for example, self-delete)
  based on the WS session identity rather than client-supplied fields.

## Risk Register

| ID | Date | Risk | Component | Status | Rationale | Mitigation / Review |
| --- | --- | --- | --- | --- | --- | --- |
| RR-2026-03-09-01 | 2026-03-09 | `lru` `IterMut` soundness bug via `tantivy` (RUSTSEC-2026-0002 / GHSA-rhfx-m35p-ff5j). Potential undefined behavior if the vulnerable iterator is used. | Search subsystem (Tantivy cache). | Resolved | Updated Tantivy to `0.26.1`, which uses `lru` `0.16.4` and is outside the vulnerable `lru` range. | Keep dependency audits in CI and recheck on future Tantivy upgrades. |
| RR-2026-03-18-01 | 2026-03-18 | `rsa` timing side-channel advisory via `jsonwebtoken` (RUSTSEC-2023-0071). | JWT/authentication dependency graph. | Resolved | Local session JWTs use the repo-owned HS256 codec documented in `docs/infrastructure/hs256-jwt-codec.md`; `jsonwebtoken` and `rsa` are absent from the dependency graph. | Keep dependency audits in CI and recheck if JWT algorithms beyond HS256 are introduced. |
| RR-2026-03-18-02 | 2026-03-18 | `clippy::too_many_arguments` suppressions for Actix extractor-heavy handlers may remain. | Actix handler signatures. | Accepted | Actix extractor signatures can legitimately require many parameters; refactoring to satisfy lint warnings can distort the handler design. | Limit suppressions to Actix extractor handlers (and closely related wrapper paths); avoid adding new suppressions for internal helpers. |
| RR-2026-03-18-03 | 2026-03-18 | `lz4_flex` uninitialized buffer advisory via `tantivy` (RUSTSEC-2026-0041 / GHSA-vvp9-7p8x-rfvv). | Search subsystem (Tantivy decompression). | Resolved | Updated `lz4_flex` to `0.11.6`, eliminating the advisory on the search runtime path. | Keep dependency audits in CI and recheck on future Tantivy upgrades. |

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
