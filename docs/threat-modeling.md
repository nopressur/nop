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

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
