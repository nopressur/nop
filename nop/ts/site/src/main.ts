// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initSiteNavigation } from './navigation';

const stateKey = '__nopSiteNavigationInit' as const;

function start() {
  const win = window as typeof window & {
    [key in typeof stateKey]?: boolean;
  };
  if (win[stateKey]) {
    return;
  }
  win[stateKey] = true;
  initSiteNavigation(document);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
