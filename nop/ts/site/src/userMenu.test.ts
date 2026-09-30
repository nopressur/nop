// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initUserMenu } from './userMenu';

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('user menu', () => {
  beforeEach(() => {
    document.body.innerHTML =
      '<div class="navbar-end" data-site-content-id="0000000000000001"><button type="button" class="site-search-trigger site-search-trigger--desktop" data-site-search-button>Search</button><div data-site-user-menu></div></div>';
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

    const root = document.querySelector<HTMLElement>('[data-site-user-menu]');
    expect(root?.children.length).toBe(0);
    const editButton = document.querySelector('[data-site-edit-button]');
    expect(editButton).toBeNull();
    const adminButton = document.querySelector('[data-site-admin-button]');
    expect(adminButton).toBeNull();
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

    const root = document.querySelector<HTMLElement>('[data-site-user-menu]');
    expect(root?.dataset.siteDropdown).toBeDefined();

    const toggle = root?.querySelector('.navbar-link');
    expect(toggle?.textContent).toBe('Admin User');

    const links = root?.querySelectorAll('.navbar-dropdown .navbar-item');
    expect(links?.length).toBe(3);
    expect(links?.[0].textContent).toBe('Profile');
    expect(links?.[1].textContent).toBe('Admin');
    expect(links?.[2].textContent).toBe('Logout');

    const editWrapper = document.querySelector('[data-site-edit-button]');
    expect(editWrapper).not.toBeNull();
    const editLink = editWrapper?.querySelector('a');
    expect(editLink?.getAttribute('href')).toBe('/admin/pages/edit/0000000000000001');
    expect(editLink?.getAttribute('target')).toBeNull();
    expect(editLink?.getAttribute('rel')).toBeNull();

    const adminWrapper = document.querySelector('[data-site-admin-button]');
    expect(adminWrapper).not.toBeNull();
    const adminLink = adminWrapper?.querySelector('a');
    expect(adminLink?.getAttribute('href')).toBe('/admin');

    const parent = root?.parentElement;
    expect(parent?.firstElementChild).toBe(editWrapper);
    expect(parent?.children[1]).toBe(adminWrapper);
    expect(
      (parent?.children[2] as HTMLElement | undefined)?.classList.contains(
        'site-search-trigger--desktop'
      )
    ).toBe(true);
  });

  it('skips the edit button when content id is missing', async () => {
    document.body.innerHTML =
      '<div class="navbar-end"><button type="button" class="site-search-trigger site-search-trigger--desktop" data-site-search-button>Search</button><div data-site-user-menu></div></div>';
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

    const editButton = document.querySelector('[data-site-edit-button]');
    expect(editButton).toBeNull();

    const adminButton = document.querySelector('[data-site-admin-button]');
    expect(adminButton).not.toBeNull();
    const adminLink = adminButton?.querySelector('a');
    expect(adminLink?.getAttribute('href')).toBe('/admin');
  });

  it('populates menu drawer rows in order when authenticated', async () => {
    document.body.innerHTML = `
      <div data-site-menu-drawer>
        <div data-site-drawer-search></div>
        <div data-site-drawer-rows></div>
        <nav data-site-drawer-nav></nav>
      </div>
      <div class="navbar-end" data-site-content-id="0000000000000001"><div data-site-user-menu></div></div>`;
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

    const drawer = document.querySelector<HTMLElement>('[data-site-menu-drawer]')!;
    const order = ["[data-site-edit-button]", "[data-site-admin-button]", "[data-site-drawer-profile]"]
      .map((selector) => drawer.querySelector(selector))
      .filter((element): element is HTMLElement => element !== null);
    expect(order.length).toBe(3);
    const positions = order.map((element) =>
      Array.from(drawer.querySelectorAll('*')).indexOf(element));
    const sorted = [...positions].sort((a, b) => a - b);
    expect(positions).toEqual(sorted);

    const profileToggle = drawer.querySelector('[data-site-drawer-profile] [data-site-expander-toggle]');
    expect(profileToggle?.textContent).toContain('Admin User');
    expect(profileToggle?.getAttribute('aria-expanded')).toBe('false');
  });

  it('places the drawer profile chevron after the display name', async () => {
    document.body.innerHTML = `
      <div data-site-menu-drawer>
        <div data-site-drawer-search></div>
        <div data-site-drawer-rows></div>
        <nav data-site-drawer-nav></nav>
      </div>
      <div class="navbar-end" data-site-content-id="0000000000000001"><div data-site-user-menu></div></div>`;
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        authenticated: true,
        display_name: 'Admin User',
        menu_items: [
          { key: 'profile', label: 'Profile', href: '/login/profile' },
          { key: 'admin', label: 'Admin', href: '/admin' }
        ]
      })
    }));

    initUserMenu();
    await flush();

    const toggle = document.querySelector('[data-site-drawer-profile] [data-site-expander-toggle]');
    const chevron = toggle?.querySelector('[data-site-expander-chevron]');
    expect(chevron).not.toBeNull();
    expect(toggle?.lastChild).toBe(chevron);
    expect(toggle?.firstChild?.textContent).toContain('Admin User');
  });
});
