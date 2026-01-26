// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initSiteNavigation } from './navigation';

describe('site navigation', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('toggles mobile menu state', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <a data-site-mobile-toggle class="navbar-burger" aria-expanded="false"></a>
        <div data-site-mobile-menu class="navbar-menu"></div>
      </div>
    `;

    initSiteNavigation(document);

    const toggle = document.querySelector<HTMLElement>('[data-site-mobile-toggle]');
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]');

    expect(toggle).not.toBeNull();
    expect(menu).not.toBeNull();

    toggle?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(toggle?.classList.contains('is-active')).toBe(true);
    expect(menu?.classList.contains('is-active')).toBe(true);
    expect(toggle?.getAttribute('aria-expanded')).toBe('true');

    toggle?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(toggle?.classList.contains('is-active')).toBe(false);
    expect(menu?.classList.contains('is-active')).toBe(false);
    expect(toggle?.getAttribute('aria-expanded')).toBe('false');
  });

  it('toggles dropdowns and closes others', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-dropdown>
          <a data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></a>
          <div class="navbar-dropdown"></div>
        </div>
        <div data-site-dropdown>
          <a data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></a>
          <div class="navbar-dropdown"></div>
        </div>
      </div>
    `;

    initSiteNavigation(document);

    const toggles = document.querySelectorAll<HTMLElement>('[data-site-dropdown-toggle]');
    const dropdowns = document.querySelectorAll<HTMLElement>('[data-site-dropdown]');

    toggles[0].dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dropdowns[0].classList.contains('is-active')).toBe(true);
    expect(dropdowns[1].classList.contains('is-active')).toBe(false);

    toggles[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dropdowns[0].classList.contains('is-active')).toBe(false);
    expect(dropdowns[1].classList.contains('is-active')).toBe(true);
  });

  it('closes dropdowns from close targets', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-dropdown class="is-active">
          <a data-site-dropdown-toggle class="navbar-link" aria-expanded="true"></a>
          <div class="navbar-dropdown"></div>
        </div>
        <div data-site-close-dropdowns></div>
      </div>
    `;

    initSiteNavigation(document);

    const dropdown = document.querySelector<HTMLElement>('[data-site-dropdown]');
    const closeTarget = document.querySelector<HTMLElement>('[data-site-close-dropdowns]');

    closeTarget?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dropdown?.classList.contains('is-active')).toBe(false);
    expect(
      dropdown?.querySelector('[data-site-dropdown-toggle]')?.getAttribute('aria-expanded')
    ).toBe('false');
  });

  it('opens hover dropdowns on mouseenter', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-dropdown data-site-dropdown-hover="true">
          <a data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></a>
          <div class="navbar-dropdown"></div>
        </div>
      </div>
    `;

    initSiteNavigation(document);

    const dropdown = document.querySelector<HTMLElement>('[data-site-dropdown]');
    dropdown?.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    expect(dropdown?.classList.contains('is-active')).toBe(true);

    dropdown?.dispatchEvent(new MouseEvent('mouseleave', { bubbles: true }));
    expect(dropdown?.classList.contains('is-active')).toBe(false);
  });

  it('registers dropdowns added after initialization', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-close-dropdowns></div>
      </div>
    `;

    const controller = initSiteNavigation(document);

    const root = document.querySelector<HTMLElement>('[data-site-root]');
    const dropdown = document.createElement('div');
    dropdown.dataset.siteDropdown = '';
    const toggle = document.createElement('a');
    toggle.dataset.siteDropdownToggle = '';
    toggle.className = 'navbar-link';
    toggle.setAttribute('aria-expanded', 'false');
    const menu = document.createElement('div');
    menu.className = 'navbar-dropdown';
    dropdown.appendChild(toggle);
    dropdown.appendChild(menu);
    root?.appendChild(dropdown);

    controller.registerDropdowns(dropdown);

    toggle.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dropdown.classList.contains('is-active')).toBe(true);
  });
});
