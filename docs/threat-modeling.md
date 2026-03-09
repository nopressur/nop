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
| RR-2026-03-09-01 | 2026-03-09 | `lru` `IterMut` soundness bug via `tantivy` (RUSTSEC-2026-0002 / GHSA-rhfx-m35p-ff5j). Potential undefined behavior if the vulnerable iterator is used. | Search subsystem (Tantivy cache). | Accepted | Tantivy 0.25.0 depends on `lru` 0.12.x and does not use `IterMut` in its runtime LRU cache access paths. Risk is low and confined to search. | Monitor Tantivy for a release that upgrades `lru` to 0.16.3 or later; revisit on Tantivy upgrade. |

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
