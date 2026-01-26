// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initUserMenu } from './userMenu';

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('user menu', () => {
  beforeEach(() => {
    document.body.innerHTML = '<div data-site-user-menu></div>';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('clears the menu when unauthenticated', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ authenticated: false })
    }));

    initUserMenu();
    await flush();

    const root = document.querySelector('[data-site-user-menu]');
    expect(root?.children.length).toBe(0);
  });

  it('renders menu items when authenticated', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        authenticated: true,
        display_name: 'Admin User',
        menu_items: [
          { key: 'profile', label: 'Profile', href: '/login/profile' },
          { key: 'admin', label: 'Admin', href: '/admin' },
          { key: 'logout', label: 'Logout', href: '/login/logout-api', method: 'POST' }
        ]
      })
    }));

    initUserMenu();
    await flush();

    const root = document.querySelector('[data-site-user-menu]');
    const dropdown = root?.querySelector('[data-site-dropdown]');
    expect(dropdown).not.toBeNull();

    const toggle = root?.querySelector('.navbar-link');
    expect(toggle?.textContent).toBe('Admin User');

    const links = root?.querySelectorAll('.navbar-dropdown .navbar-item');
    expect(links?.length).toBe(3);
    expect(links?.[0].textContent).toBe('Profile');
    expect(links?.[1].textContent).toBe('Admin');
    expect(links?.[2].textContent).toBe('Logout');
  });
});
