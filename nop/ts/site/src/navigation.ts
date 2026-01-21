// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const SELECTORS = {
  mobileToggle: '[data-site-mobile-toggle]',
  mobileMenu: '[data-site-mobile-menu]',
  dropdown: '[data-site-dropdown]',
  dropdownToggle: '[data-site-dropdown-toggle]',
  closeTargets: '[data-site-close-dropdowns]'
} as const;

export type SiteNavigationController = {
  closeAllDropdowns: () => void;
  destroy: () => void;
};

function setDropdownActive(dropdown: HTMLElement, active: boolean) {
  dropdown.classList.toggle('is-active', active);
  const toggle = dropdown.querySelector<HTMLElement>(SELECTORS.dropdownToggle);
  if (toggle) {
    toggle.setAttribute('aria-expanded', active ? 'true' : 'false');
  }
}

function setMobileActive(toggle: HTMLElement, menu: HTMLElement, active: boolean) {
  toggle.classList.toggle('is-active', active);
  menu.classList.toggle('is-active', active);
  toggle.setAttribute('aria-expanded', active ? 'true' : 'false');
}

export function initSiteNavigation(root: ParentNode = document): SiteNavigationController {
  const scope = root;
  const cleanup: Array<() => void> = [];

  const dropdowns = Array.from(
    scope.querySelectorAll<HTMLElement>(SELECTORS.dropdown)
  );

  const closeAllDropdowns = () => {
    dropdowns.forEach((dropdown) => setDropdownActive(dropdown, false));
  };

  const mobileToggle = scope.querySelector<HTMLElement>(SELECTORS.mobileToggle);
  const mobileMenu = scope.querySelector<HTMLElement>(SELECTORS.mobileMenu);
  if (mobileToggle && mobileMenu) {
    let isOpen = false;
    const onClick = (event: Event) => {
      event.preventDefault();
      isOpen = !isOpen;
      setMobileActive(mobileToggle, mobileMenu, isOpen);
    };
    mobileToggle.addEventListener('click', onClick);
    cleanup.push(() => mobileToggle.removeEventListener('click', onClick));
  }

  const toggleDropdown = (dropdown: HTMLElement) => {
    const isActive = dropdown.classList.contains('is-active');
    if (isActive) {
      setDropdownActive(dropdown, false);
      return;
    }
    closeAllDropdowns();
    setDropdownActive(dropdown, true);
  };

  dropdowns.forEach((dropdown) => {
    const toggle = dropdown.querySelector<HTMLElement>(SELECTORS.dropdownToggle);
    if (!toggle) {
      return;
    }

    const onClick = (event: Event) => {
      event.preventDefault();
      toggleDropdown(dropdown);
    };
    const onKeydown = (event: KeyboardEvent) => {
      if (event.key !== 'Enter' && event.key !== ' ') {
        return;
      }
      event.preventDefault();
      toggleDropdown(dropdown);
    };

    toggle.addEventListener('click', onClick);
    toggle.addEventListener('keydown', onKeydown);
    cleanup.push(() => toggle.removeEventListener('click', onClick));
    cleanup.push(() => toggle.removeEventListener('keydown', onKeydown));
  });

  dropdowns
    .filter((dropdown) => dropdown.dataset.siteDropdownHover === 'true')
    .forEach((dropdown) => {
      const onEnter = () => {
        closeAllDropdowns();
        setDropdownActive(dropdown, true);
      };
      const onLeave = () => {
        setDropdownActive(dropdown, false);
      };
      dropdown.addEventListener('mouseenter', onEnter);
      dropdown.addEventListener('mouseleave', onLeave);
      cleanup.push(() => dropdown.removeEventListener('mouseenter', onEnter));
      cleanup.push(() => dropdown.removeEventListener('mouseleave', onLeave));
    });

  const closeTargets = Array.from(
    scope.querySelectorAll<HTMLElement>(SELECTORS.closeTargets)
  );
  closeTargets.forEach((target) => {
    const onClick = () => {
      closeAllDropdowns();
    };
    target.addEventListener('click', onClick);
    cleanup.push(() => target.removeEventListener('click', onClick));
  });

  return {
    closeAllDropdowns,
    destroy: () => {
      cleanup.forEach((fn) => fn());
    }
  };
}
