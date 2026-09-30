// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initSiteNavigation } from './navigation';
import type { SiteNavigationController } from './navigation';
import { initSearchOverlay } from './search';
import type { SiteSearchOverlayController } from './search';
import { initDrawerSearch } from './search';
import { initUserMenu } from './userMenu';
import { initCodeCopyButtons } from './codeCopy';
import { initAssetReload } from './assetReload';

const stateKey = '__nopSiteNavigationInit' as const;
const controllerKey = '__nopSiteNavigationController' as const;
const overlayKey = '__nopSiteSearchOverlay' as const;
const DESKTOP_SEARCH_BREAKPOINT = 1280;

function syncSearchOverlay() {
  const win = window as typeof window &
    Partial<Record<typeof overlayKey, SiteSearchOverlayController | null>>;
  const wide = window.innerWidth >= DESKTOP_SEARCH_BREAKPOINT;
  if (wide && !win[overlayKey] && document.querySelector('[data-site-search-overlay]')) {
    win[overlayKey] = initSearchOverlay(document);
  } else if (!wide && win[overlayKey]) {
    win[overlayKey]?.destroy();
    win[overlayKey] = null;
  }
}

function start() {
  const win = window as typeof window &
    Partial<Record<typeof stateKey, boolean>> &
    Partial<Record<typeof controllerKey, SiteNavigationController>>;
  if (win[stateKey]) {
    return;
  }
  win[stateKey] = true;
  win[controllerKey] = initSiteNavigation(document);
  syncSearchOverlay();
  window.addEventListener('resize', syncSearchOverlay);
  initDrawerSearch(document);
  initUserMenu();
  initCodeCopyButtons(document);
  initAssetReload(document);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
