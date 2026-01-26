// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initSiteNavigation } from './navigation';
import type { SiteNavigationController } from './navigation';

const PROFILE_ENDPOINT = '/api/profile';
const MENU_ROOT_SELECTOR = '[data-site-user-menu]';

type ProfileMenuItem = {
  key: string;
  label: string;
  href: string;
  method?: string;
};

type ProfileResponse = {
  authenticated: boolean;
  display_name?: string;
  menu_items?: ProfileMenuItem[];
};

type WindowWithSiteNav = Window &
  typeof globalThis & {
    __nopSiteNavigationController?: SiteNavigationController;
  };

function resolveSiteNavigation(): SiteNavigationController {
  const win = window as WindowWithSiteNav;
  if (win.__nopSiteNavigationController) {
    return win.__nopSiteNavigationController;
  }
  const controller = initSiteNavigation(document);
  win.__nopSiteNavigationController = controller;
  return controller;
}

function buildMenu(displayName: string, menuItems: ProfileMenuItem[]): HTMLElement {
  const wrapper = document.createElement('div');
  wrapper.className = 'navbar-item has-dropdown';
  wrapper.dataset.siteDropdown = '';

  const toggle = document.createElement('a');
  toggle.className = 'navbar-link';
  toggle.href = '#';
  toggle.setAttribute('aria-expanded', 'false');
  toggle.dataset.siteDropdownToggle = '';
  toggle.textContent = displayName;
  wrapper.appendChild(toggle);

  const dropdown = document.createElement('div');
  dropdown.className = 'navbar-dropdown is-right';

  menuItems.forEach((item) => {
    const link = document.createElement('a');
    link.className = 'navbar-item';
    link.textContent = item.label;
    link.href = item.href;

    const method = item.method?.toUpperCase();
    if (method && method !== 'GET') {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        void performAction(item.href, method);
      });
    }

    dropdown.appendChild(link);
  });

  wrapper.appendChild(dropdown);
  return wrapper;
}

async function performAction(href: string, method: string) {
  try {
    const response = await fetch(href, {
      method,
      credentials: 'same-origin'
    });
    if (response.ok) {
      window.location.href = '/';
      return;
    }
  } catch (error) {
    console.error('Menu action failed:', error);
  }
  window.location.href = '/';
}

async function refreshUserMenu() {
  const root = document.querySelector<HTMLElement>(MENU_ROOT_SELECTOR);
  if (!root) {
    return;
  }

  try {
    const response = await fetch(PROFILE_ENDPOINT, {
      method: 'GET',
      credentials: 'same-origin'
    });
    if (!response.ok) {
      root.innerHTML = '';
      return;
    }

    const payload = (await response.json()) as ProfileResponse;
    if (!payload.authenticated || !payload.menu_items?.length) {
      root.innerHTML = '';
      return;
    }

    const displayName = payload.display_name?.trim() || 'Account';
    const menu = buildMenu(displayName, payload.menu_items);
    root.innerHTML = '';
    root.appendChild(menu);
    resolveSiteNavigation().registerDropdowns(menu);
  } catch (error) {
    console.error('Failed to load profile menu:', error);
    root.innerHTML = '';
  }
}

let initialized = false;

export function initUserMenu() {
  if (!initialized) {
    initialized = true;
    window.addEventListener('pageshow', (event) => {
      if (event.persisted) {
        void refreshUserMenu();
      }
    });
  }
  void refreshUserMenu();
}
