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
  registerDropdowns: (root?: ParentNode) => void;
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
  const cleanup: Array<() => void> = [];
  const dropdowns = new Set<HTMLElement>();

  const closeAllDropdowns = () => {
    dropdowns.forEach((dropdown) => setDropdownActive(dropdown, false));
  };

  const scope = root;
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

  const registerDropdown = (dropdown: HTMLElement) => {
    if (dropdowns.has(dropdown)) {
      return;
    }
    dropdowns.add(dropdown);
    const toggle = dropdown.querySelector<HTMLElement>(SELECTORS.dropdownToggle);
    if (toggle) {
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
    }

    if (dropdown.dataset.siteDropdownHover === 'true') {
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
    }
  };

  const registerDropdowns = (scope: ParentNode = root) => {
    const candidates = Array.from(
      scope.querySelectorAll<HTMLElement>(SELECTORS.dropdown)
    );
    if (scope instanceof HTMLElement && scope.matches(SELECTORS.dropdown)) {
      candidates.unshift(scope);
    }
    candidates.forEach((dropdown) => registerDropdown(dropdown));
  };

  registerDropdowns(scope);

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
    registerDropdowns,
    destroy: () => {
      cleanup.forEach((fn) => fn());
    }
  };
}
