// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const SELECTORS = {
  navbar: '[data-site-navbar]',
  mobileToggle: '[data-site-mobile-toggle]',
  mobileMenu: '[data-site-mobile-menu]',
  dropdown: '[data-site-dropdown]',
  dropdownToggle: '[data-site-dropdown-toggle]',
  closeTargets: '[data-site-close-dropdowns]',
  docStructure: '[data-site-doc-structure]',
  docStructureLink: '[data-site-doc-structure-link]',
  expanderToggle: '[data-site-expander-toggle]',
  topbarMenu: '[data-site-topbar-menu]',
  topbarStructure: '[data-site-topbar-structure]',
  topbar: '[data-site-topbar]',
  menuDrawer: '[data-site-menu-drawer]',
  structureDrawer: '[data-site-structure-drawer]',
  docStructureTop: '[data-site-doc-structure-top]',
  docStructureBottom: '[data-site-doc-structure-bottom]',
  drawerBack: '[data-site-drawer-back]',
  drawerSearchInput: '[data-site-drawer-search-input]'
} as const;

const NAVBAR_REVEALED_CLASS = 'is-site-navbar-revealed';
const NAVBAR_FLOW_SPACER_CLASS = 'site-navbar-flow-spacer';
const NAVBAR_DESKTOP_BREAKPOINT = 1280;
const EXPANDER_OPEN_CLASS = 'is-open';
const DRAWER_OPEN_CLASS = 'is-open';
const DRAWER_HIDE_MS = 180;
const DOC_LINK_ACTIVE_CLASS = 'is-active';
const SCROLL_ACTIVATION_OFFSET = 16;
export const STRUCTURE_PANEL_SCROLL_MS = 650;
const SWIPE_MIN_DISTANCE_PX = 72;
const SWIPE_DIRECTION_RATIO = 2;
const OVERFLOW_TOLERANCE_PX = 1;

export type SiteNavigationController = {
  closeAllDropdowns: () => void;
  closeDocumentStructureMenu: () => void;
  updateDocumentStructureState: () => void;
  updateNavbarRevealState: () => void;
  registerDropdowns: (root?: ParentNode) => void;
  registerExpanders: (root?: ParentNode) => void;
  openMenuDrawer: () => void;
  openStructureDrawer: () => void;
  closeDrawers: (restoreFocus?: boolean) => void;
  destroy: () => void;
};

export function setExpanderState(toggle: HTMLElement, expanded: boolean) {
  toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  const wrapper = toggle.closest('[data-site-expander]');
  if (wrapper instanceof HTMLElement) {
    wrapper.classList.toggle(EXPANDER_OPEN_CLASS, expanded);
  }
  const panel = wrapper?.querySelector('[data-site-expander-panel]');
  if (panel instanceof HTMLElement) {
    if (expanded) {
      panel.removeAttribute('hidden');
    } else {
      panel.setAttribute('hidden', '');
    }
  }
}

type ScheduledTask = {
  request: (callback: () => void) => void;
  cancel: () => void;
};

type StructureTarget = {
  id: string;
  top: number;
};

type StructureLink = {
  id: string;
  element: HTMLElement;
};

function getScrollY(): number {
  if (typeof window.pageYOffset === 'number') {
    return window.pageYOffset;
  }
  if (document.documentElement && typeof document.documentElement.scrollTop === 'number') {
    return document.documentElement.scrollTop;
  }
  return document.body ? document.body.scrollTop : 0;
}

function getPageScrollHeight(): number {
  return Math.max(
    document.documentElement ? document.documentElement.scrollHeight : 0,
    document.body ? document.body.scrollHeight : 0
  );
}

function getMaxScrollY(): number {
  const viewport =
    typeof window.innerHeight === 'number' && window.innerHeight > 0
      ? window.innerHeight
      : document.documentElement
        ? document.documentElement.clientHeight
        : 0;
  return Math.max(getPageScrollHeight() - viewport, 0);
}

function clampScrollY(y: number): number {
  const rounded = Math.round(y);
  if (rounded < 0) {
    return 0;
  }
  const maxY = getMaxScrollY();
  if (rounded > maxY) {
    return maxY;
  }
  return rounded;
}

// Cubic ease-in joined to a longer cubic ease-out at matching velocity, so the
// scroll spends most of its time settling gently instead of braking hard and
// parking early.
const EASE_SPLIT = 0.35;
const EASE_OUT_POWER = 3;
const EASE_IN_SCALE =
  1 /
  (EASE_SPLIT * EASE_SPLIT * EASE_SPLIT +
    (3 * EASE_SPLIT * EASE_SPLIT * (1 - EASE_SPLIT)) / EASE_OUT_POWER);
const EASE_OUT_SCALE =
  (3 * EASE_IN_SCALE * EASE_SPLIT * EASE_SPLIT) /
  (EASE_OUT_POWER * Math.pow(1 - EASE_SPLIT, EASE_OUT_POWER - 1));

export function easeInOut(progress: number): number {
  if (progress <= 0) {
    return 0;
  }
  if (progress >= 1) {
    return 1;
  }
  if (progress < EASE_SPLIT) {
    return EASE_IN_SCALE * progress * progress * progress;
  }
  return 1 - EASE_OUT_SCALE * Math.pow(1 - progress, EASE_OUT_POWER);
}

function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

let pageScrollTimer: number | null = null;
let heldHeadingId: { element: HTMLElement; id: string } | null = null;

function elementPageTop(element: HTMLElement): number {
  const rect = element.getBoundingClientRect();
  if (rect && typeof rect.top === 'number' && Math.abs(rect.top) > 1) {
    return Math.round(getScrollY() + rect.top);
  }
  let y = 0;
  let node: HTMLElement | null = element;
  while (node) {
    y += node.offsetTop;
    const parent: Element | null = node.offsetParent;
    node = parent instanceof HTMLElement ? parent : null;
  }
  return y;
}

function setScrollTop(y: number) {
  if (document.documentElement) {
    document.documentElement.style.scrollBehavior = 'auto';
    document.documentElement.scrollTop = y;
  }
  if (document.body) {
    document.body.style.scrollBehavior = 'auto';
    document.body.scrollTop = y;
  }
  try {
    window.scrollTo(0, y);
  } catch {
    // jsdom implements scrollTo as a throw.
  }
}

function restoreHeldHeadingId() {
  if (!heldHeadingId) {
    return;
  }
  const { element, id } = heldHeadingId;
  heldHeadingId = null;
  if (element.getAttribute('id') !== id) {
    element.setAttribute('id', id);
  }
}

function holdHeadingId(element: HTMLElement) {
  restoreHeldHeadingId();
  const id = element.getAttribute('id');
  if (!id) {
    return;
  }
  heldHeadingId = { element, id };
  element.removeAttribute('id');
}

function stopPageScroll() {
  window.removeEventListener('wheel', cancelPageScroll);
  window.removeEventListener('touchmove', cancelPageScroll);
  if (pageScrollTimer !== null) {
    window.clearTimeout(pageScrollTimer);
    pageScrollTimer = null;
  }
}

function cancelPageScroll() {
  stopPageScroll();
  restoreHeldHeadingId();
}

function finishPageScroll(endY: number) {
  stopPageScroll();
  setScrollTop(endY);
  restoreHeldHeadingId();
}

function animatePageScroll(destination: number) {
  stopPageScroll();
  const startY = getScrollY();
  const endY = clampScrollY(destination);
  if (startY === endY) {
    finishPageScroll(endY);
    return;
  }
  window.addEventListener('wheel', cancelPageScroll);
  window.addEventListener('touchmove', cancelPageScroll);
  const startTime = Date.now();
  const tick = () => {
    const elapsed = Date.now() - startTime;
    if (elapsed >= STRUCTURE_PANEL_SCROLL_MS) {
      pageScrollTimer = null;
      finishPageScroll(endY);
      return;
    }
    setScrollTop(
      Math.round(startY + (endY - startY) * easeInOut(elapsed / STRUCTURE_PANEL_SCROLL_MS))
    );
    pageScrollTimer = window.setTimeout(tick, 16);
  };
  tick();
}

function getElementDocumentTop(element: HTMLElement): number {
  const rect = element.getBoundingClientRect();
  return getScrollY() + rect.top;
}

function getElementHeight(element: HTMLElement): number {
  const rect = element.getBoundingClientRect();
  if (rect.height > 0) {
    return rect.height;
  }
  return element.offsetHeight;
}

function toCssPx(value: number): string {
  return `${value}px`;
}

function getViewportWidth(): number {
  if (typeof window.innerWidth === 'number') {
    return window.innerWidth;
  }
  if (document.documentElement && typeof document.documentElement.clientWidth === 'number') {
    return document.documentElement.clientWidth;
  }
  return document.body ? document.body.clientWidth : 0;
}

function isDesktopNavbarLayout(): boolean {
  return getViewportWidth() >= NAVBAR_DESKTOP_BREAKPOINT;
}

function createScheduledTask(): ScheduledTask {
  let frameId: number | null = null;
  let timerId: number | null = null;

  const clear = () => {
    if (frameId !== null) {
      window.cancelAnimationFrame(frameId);
      frameId = null;
    }
    if (timerId !== null) {
      window.clearTimeout(timerId);
      timerId = null;
    }
  };

  return {
    request: (callback: () => void) => {
      if (frameId !== null || timerId !== null) {
        return;
      }
      if (typeof window.requestAnimationFrame === 'function') {
        frameId = window.requestAnimationFrame(() => {
          frameId = null;
          callback();
        });
        return;
      }
      timerId = window.setTimeout(() => {
        timerId = null;
        callback();
      }, 16);
    },
    cancel: clear
  };
}

function resolveStructureTargetId(link: HTMLElement): string | null {
  const explicitTarget = link.getAttribute('data-site-doc-structure-target');
  if (explicitTarget && explicitTarget.length > 0) {
    return explicitTarget;
  }
  const href = link.getAttribute('href');
  if (!href) {
    return null;
  }
  const hashIndex = href.indexOf('#');
  if (hashIndex < 0 || hashIndex === href.length - 1) {
    return null;
  }
  return href.slice(hashIndex + 1);
}

function setDropdownActive(dropdown: HTMLElement, active: boolean) {
  dropdown.classList.toggle('is-active', active);
  const toggle = dropdown.querySelector<HTMLElement>(SELECTORS.dropdownToggle);
  if (toggle) {
    setExpanderState(toggle, active);
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
  const scrollTask = createScheduledTask();
  const documentStructureTask = createScheduledTask();
  const scope = root;
  const navbar = scope.querySelector<HTMLElement>(SELECTORS.navbar);
  const mobileToggle = scope.querySelector<HTMLElement>(SELECTORS.mobileToggle);
  const mobileMenu = scope.querySelector<HTMLElement>(SELECTORS.mobileMenu);
  let mobileMenuOpen = false;
  let lastScrollY = getScrollY();
  let navbarOriginalBottom = 0;
  let navbarRevealed = false;
  let navbarFlowSpacer: HTMLElement | null = null;
  let lastViewportWidth = getViewportWidth();
  let lastDesktopNavbarLayout = isDesktopNavbarLayout();

  const closeAllDropdowns = () => {
    dropdowns.forEach((dropdown) => setDropdownActive(dropdown, false));
  };

  const closeMobileMenu = () => {
    if (!mobileToggle || !mobileMenu || !mobileMenuOpen) {
      return;
    }
    mobileMenuOpen = false;
    setMobileActive(mobileToggle, mobileMenu, false);
    resizeNavbarFlowSpacerToCurrentHeight();
  };

  const ensureNavbarFlowSpacer = (): HTMLElement | null => {
    if (!navbar || !navbar.parentNode) {
      return null;
    }
    if (navbarFlowSpacer) {
      return navbarFlowSpacer;
    }
    const spacer = navbar.ownerDocument.createElement('div');
    spacer.className = NAVBAR_FLOW_SPACER_CLASS;
    spacer.setAttribute('aria-hidden', 'true');
    spacer.setAttribute('data-site-navbar-flow-spacer', 'true');
    spacer.style.display = 'none';
    spacer.style.height = '0px';
    spacer.style.overflow = 'hidden';
    navbar.parentNode.insertBefore(spacer, navbar.nextSibling);
    navbarFlowSpacer = spacer;
    return spacer;
  };

  const showNavbarFlowSpacer = () => {
    const spacer = ensureNavbarFlowSpacer();
    if (!navbar || !spacer) {
      return;
    }
    spacer.style.display = 'block';
    spacer.style.height = toCssPx(getElementHeight(navbar));
  };

  function resizeNavbarFlowSpacerToCurrentHeight() {
    if (!navbar || !navbarFlowSpacer || !navbarRevealed) {
      return;
    }
    navbarFlowSpacer.style.height = toCssPx(getElementHeight(navbar));
  }

  const hideNavbarFlowSpacer = () => {
    if (!navbarFlowSpacer) {
      return;
    }
    navbarFlowSpacer.style.display = 'none';
    navbarFlowSpacer.style.height = '0px';
  };

  const removeNavbarFlowSpacer = () => {
    if (!navbarFlowSpacer || !navbarFlowSpacer.parentNode) {
      navbarFlowSpacer = null;
      return;
    }
    navbarFlowSpacer.parentNode.removeChild(navbarFlowSpacer);
    navbarFlowSpacer = null;
  };

  const setNavbarRevealed = (revealed: boolean) => {
    if (!navbar || navbarRevealed === revealed) {
      return;
    }
    if (revealed) {
      showNavbarFlowSpacer();
    }
    navbarRevealed = revealed;
    navbar.classList.toggle(NAVBAR_REVEALED_CLASS, revealed);
    if (revealed) {
      navbar.setAttribute('data-site-navbar-revealed', 'true');
    } else {
      navbar.removeAttribute('data-site-navbar-revealed');
      hideNavbarFlowSpacer();
    }
  };

  const measureNavbarOriginalPosition = () => {
    if (!navbar) {
      return;
    }
    if (navbarRevealed) {
      return;
    }
    navbarOriginalBottom = getElementDocumentTop(navbar) + getElementHeight(navbar);
  };

  const updateNavbarRevealState = () => {
    if (!navbar) {
      return;
    }
    const currentScrollY = getScrollY();
    const scrollingUp = currentScrollY < lastScrollY;
    const scrollingDown = currentScrollY > lastScrollY;

    if (currentScrollY <= navbarOriginalBottom) {
      setNavbarRevealed(false);
    } else if (mobileMenuOpen) {
      setNavbarRevealed(true);
    } else if (scrollingUp && currentScrollY > navbarOriginalBottom) {
      setNavbarRevealed(true);
    } else if (scrollingDown) {
      setNavbarRevealed(false);
    }

    lastScrollY = currentScrollY;
  };

  if (navbar) {
    measureNavbarOriginalPosition();
    const onScroll = () => {
      scrollTask.request(updateNavbarRevealState);
    };
    const onResize = () => {
      const viewportWidth = getViewportWidth();
      const desktopNavbarLayout = isDesktopNavbarLayout();
      const layoutChanged =
        viewportWidth !== lastViewportWidth || desktopNavbarLayout !== lastDesktopNavbarLayout;
      lastViewportWidth = viewportWidth;
      lastDesktopNavbarLayout = desktopNavbarLayout;

      if (layoutChanged) {
        closeMobileMenu();
        closeDrawers(false);
        setNavbarRevealed(false);
        measureNavbarOriginalPosition();
      }
      lastScrollY = getScrollY();
      documentStructureTask.request(updateDocumentStructureState);
    };
    window.addEventListener('scroll', onScroll);
    window.addEventListener('resize', onResize);
    cleanup.push(() => window.removeEventListener('scroll', onScroll));
    cleanup.push(() => window.removeEventListener('resize', onResize));
  }

  if (mobileToggle && mobileMenu) {
    const onClick = (event: Event) => {
      event.preventDefault();
      mobileMenuOpen = !mobileMenuOpen;
      setMobileActive(mobileToggle, mobileMenu, mobileMenuOpen);
      if (!mobileMenuOpen) {
        resizeNavbarFlowSpacerToCurrentHeight();
      }
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
      const onLeave = (event: MouseEvent) => {
        const next = event.relatedTarget;
        if (next instanceof Node && dropdown.contains(next)) {
          return;
        }
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

  const expandersBound = new Set<HTMLElement>();
  const registerExpander = (toggle: HTMLElement) => {
    if (expandersBound.has(toggle)) {
      return;
    }
    expandersBound.add(toggle);
    const onClick = () => {
      if (toggle.closest(SELECTORS.dropdown)) {
        return;
      }
      const expanded = toggle.getAttribute('aria-expanded') !== 'true';
      setExpanderState(toggle, expanded);
    };
    toggle.addEventListener('click', onClick);
    cleanup.push(() => toggle.removeEventListener('click', onClick));
  };

  const registerExpanders = (expandScope: ParentNode = root) => {
    const candidates = Array.from(
      expandScope.querySelectorAll<HTMLElement>(SELECTORS.expanderToggle)
    );
    if (expandScope instanceof HTMLElement && expandScope.matches(SELECTORS.expanderToggle)) {
      candidates.unshift(expandScope);
    }
    candidates.forEach((toggle) => registerExpander(toggle));
  };

  registerExpanders(scope);

  let openDrawer: HTMLElement | null = null;
  let drawerInvoker: HTMLElement | null = null;
  let drawerHideTimer: number | null = null;
  let previousBodyOverflow: string | null = null;

  const lockBodyScroll = () => {
    if (previousBodyOverflow !== null || !document.body) {
      return;
    }
    previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
  };

  const unlockBodyScroll = () => {
    if (previousBodyOverflow === null || !document.body) {
      return;
    }
    document.body.style.overflow = previousBodyOverflow;
    previousBodyOverflow = null;
  };

  const finishHideDrawer = (drawer: HTMLElement) => {
    drawer.setAttribute('hidden', '');
  };

  const hideDrawer = (drawer: HTMLElement, restoreFocus: boolean) => {
    if (drawerHideTimer !== null) {
      window.clearTimeout(drawerHideTimer);
      drawerHideTimer = null;
    }
    drawer.classList.remove(DRAWER_OPEN_CLASS);
    unlockBodyScroll();
    if (openDrawer === drawer) {
      openDrawer = null;
    }
    const invoker = drawerInvoker;
    drawerInvoker = null;
    invoker?.setAttribute('aria-expanded', 'false');
    if (prefersReducedMotion()) {
      finishHideDrawer(drawer);
      if (restoreFocus) {
        invoker?.focus();
      }
      return;
    }
    drawerHideTimer = window.setTimeout(() => {
      drawerHideTimer = null;
      finishHideDrawer(drawer);
      if (restoreFocus) {
        invoker?.focus();
      }
    }, DRAWER_HIDE_MS);
  };

  const showDrawer = (drawer: HTMLElement | null, invoker: HTMLElement | null) => {
    if (!(drawer instanceof HTMLElement)) {
      return;
    }
    if (drawerHideTimer !== null) {
      window.clearTimeout(drawerHideTimer);
      drawerHideTimer = null;
    }
    if (openDrawer && openDrawer !== drawer) {
      const previous = openDrawer;
      previous.classList.remove(DRAWER_OPEN_CLASS);
      finishHideDrawer(previous);
    }
    const previousInvoker = drawerInvoker;
    previousInvoker?.setAttribute('aria-expanded', 'false');
    openDrawer = drawer;
    drawerInvoker = invoker;
    drawer.removeAttribute('hidden');
    void drawer.offsetWidth;
    drawer.classList.add(DRAWER_OPEN_CLASS);
    invoker?.setAttribute('aria-expanded', 'true');
    lockBodyScroll();
    drawer.querySelector<HTMLElement>(SELECTORS.drawerBack)?.focus();
  };

  const closeDrawers = (restoreFocus = true) => {
    if (openDrawer) {
      hideDrawer(openDrawer, restoreFocus);
    }
  };

  const openMenuDrawer = () => {
    showDrawer(scope.querySelector<HTMLElement>(SELECTORS.menuDrawer), scope.querySelector<HTMLElement>(SELECTORS.topbarMenu));
  };

  const openStructureDrawer = () => {
    showDrawer(
      scope.querySelector<HTMLElement>(SELECTORS.structureDrawer),
      scope.querySelector<HTMLElement>(SELECTORS.topbarStructure)
    );
  };

  const topbarMenu = scope.querySelector<HTMLElement>(SELECTORS.topbarMenu);
  if (topbarMenu) {
    const onClick = (event: Event) => {
      event.preventDefault();
      openMenuDrawer();
    };
    topbarMenu.addEventListener('click', onClick);
    cleanup.push(() => topbarMenu.removeEventListener('click', onClick));
  }

  const topbarStructure = scope.querySelector<HTMLElement>(SELECTORS.topbarStructure);
  if (topbarStructure) {
    const onClick = (event: Event) => {
      event.preventDefault();
      openStructureDrawer();
    };
    topbarStructure.addEventListener('click', onClick);
    cleanup.push(() => topbarStructure.removeEventListener('click', onClick));
  }

  const menuDrawer = scope.querySelector<HTMLElement>(SELECTORS.menuDrawer);
  if (menuDrawer) {
    const back = menuDrawer.querySelector<HTMLElement>(SELECTORS.drawerBack);
    if (back) {
      const onClick = (event: Event) => {
        event.preventDefault();
        hideDrawer(menuDrawer, true);
      };
      back.addEventListener('click', onClick);
      cleanup.push(() => back.removeEventListener('click', onClick));
    }
  }

  const structureDrawer = scope.querySelector<HTMLElement>(SELECTORS.structureDrawer);
  if (structureDrawer) {
    const back = structureDrawer.querySelector<HTMLElement>(SELECTORS.drawerBack);
    if (back) {
      const onClick = (event: Event) => {
        event.preventDefault();
        hideDrawer(structureDrawer, true);
      };
      back.addEventListener('click', onClick);
      cleanup.push(() => back.removeEventListener('click', onClick));
    }
    const onLinkClick = (event: Event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      const link = target.closest('a[href^="#"]');
      if (!(link instanceof HTMLAnchorElement)) {
        return;
      }
      const id = link.getAttribute('href')?.slice(1) ?? '';
      if (!id) {
        return;
      }
      event.preventDefault();
      hideDrawer(structureDrawer, false);
      window.location.hash = id;
      window.setTimeout(() => adjustAnchorBelowTopbar(id), 0);
    };
    structureDrawer.addEventListener('click', onLinkClick);
    cleanup.push(() => structureDrawer.removeEventListener('click', onLinkClick));
  }

  const scrollToPageTop = () => {
    setScrollTop(0);
  };

  const scrollToPageBottom = () => {
    setScrollTop(getPageScrollHeight());
  };

  const bindPageJumpButton = (button: HTMLElement, jump: () => void) => {
    const onClick = (event: Event) => {
      event.preventDefault();
      if (structureDrawer && structureDrawer.contains(button) && openDrawer === structureDrawer) {
        hideDrawer(structureDrawer, false);
        window.setTimeout(jump, 0);
        return;
      }
      if (button.closest(SELECTORS.docStructure)) {
        const toTop = button.hasAttribute('data-site-doc-structure-top');
        animatePageScroll(toTop ? 0 : getPageScrollHeight());
        return;
      }
      jump();
    };
    button.addEventListener('click', onClick);
    cleanup.push(() => button.removeEventListener('click', onClick));
  };

  Array.from(scope.querySelectorAll<HTMLElement>(SELECTORS.docStructureTop)).forEach((button) => {
    bindPageJumpButton(button, scrollToPageTop);
  });
  Array.from(scope.querySelectorAll<HTMLElement>(SELECTORS.docStructureBottom)).forEach(
    (button) => {
      bindPageJumpButton(button, scrollToPageBottom);
    }
  );

  Array.from(
    scope.querySelectorAll<HTMLElement>(`${SELECTORS.docStructure} ${SELECTORS.docStructureLink}`)
  ).forEach((link) => {
    const onClick = (event: MouseEvent): boolean | void => {
      if (typeof event.button === 'number' && event.button !== 0) {
        return;
      }
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }
      const id = resolveStructureTargetId(link);
      if (!id) {
        return;
      }
      const heading = document.getElementById(id);
      if (!(heading instanceof HTMLElement)) {
        return;
      }
      event.preventDefault();
      event.returnValue = false;
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === 'function') {
        event.stopImmediatePropagation();
      }
      holdHeadingId(heading);
      animatePageScroll(elementPageTop(heading));
      return false;
    };
    link.addEventListener('click', onClick, true);
    link.onclick = onClick;
    cleanup.push(() => {
      link.removeEventListener('click', onClick, true);
      if (link.onclick === onClick) {
        link.onclick = null;
      }
    });
  });

  const adjustAnchorBelowTopbar = (targetId: string) => {
    const target = document.getElementById(targetId);
    const topbar = scope.querySelector<HTMLElement>(SELECTORS.topbar);
    if (!(target instanceof HTMLElement) || !(topbar instanceof HTMLElement)) {
      return;
    }
    if (getElementHeight(topbar) === 0) {
      return;
    }
    const offset = getElementHeight(topbar) + SCROLL_ACTIVATION_OFFSET;
    window.scrollTo(0, Math.max(getElementDocumentTop(target) - offset, 0));
  };

  const isEditableTarget = (target: EventTarget | null): boolean => {
    if (!(target instanceof HTMLElement)) {
      return false;
    }
    if (target.isContentEditable) {
      return true;
    }
    const tag = target.tagName.toUpperCase();
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
  };

  // Opening swipes stay off where a horizontal swipe already means something:
  // pages that scroll sideways, or gestures starting inside a nested
  // horizontal scroller (wide tables, code blocks). Closing swipes are never
  // suppressed; they operate on the drawer DOM.
  const elementScrollsHorizontally = (element: HTMLElement): boolean => {
    if (element.scrollWidth <= element.clientWidth + OVERFLOW_TOLERANCE_PX) {
      return false;
    }
    if (element === document.documentElement || element === document.body) {
      return true;
    }
    const overflowX = getComputedStyle(element).overflowX;
    return overflowX === 'auto' || overflowX === 'scroll';
  };

  const swipeStartsInHorizontalScroller = (target: EventTarget | null): boolean => {
    let node: HTMLElement | null =
      target instanceof HTMLElement ? target : document.documentElement;
    while (node instanceof HTMLElement) {
      if (elementScrollsHorizontally(node)) {
        return true;
      }
      node = node.parentElement;
    }
    return false;
  };

  // Edge swipes open the drawers. Progressive enhancement: when the browser
  // has no touch event constructor the handlers are never attached and nothing
  // else changes, so unsupported browsers stay silent.
  if (typeof window.TouchEvent === 'function') {
    let swipeStartX: number | null = null;
    let swipeStartY: number | null = null;
    let swipeTracking = false;
    const resetSwipe = () => {
      swipeTracking = false;
      swipeStartX = null;
      swipeStartY = null;
    };
    const onTouchStart = (event: TouchEvent) => {
      if (event.touches.length !== 1) {
        resetSwipe();
        return;
      }
      const touch = event.touches[0];
      swipeStartX = touch.clientX;
      swipeStartY = touch.clientY;
      swipeTracking = true;
    };
    const onTouchEnd = (event: TouchEvent) => {
      const startX = swipeStartX;
      const startY = swipeStartY;
      const tracking = swipeTracking;
      resetSwipe();
      if (!tracking || startX === null || startY === null) {
        return;
      }
      if (event.changedTouches.length !== 1) {
        return;
      }
      if (isDesktopNavbarLayout()) {
        return;
      }
      if (isEditableTarget(event.target)) {
        return;
      }
      const touch = event.changedTouches[0];
      const deltaX = touch.clientX - startX;
      const deltaY = touch.clientY - startY;
      if (
        Math.abs(deltaX) < SWIPE_MIN_DISTANCE_PX ||
        Math.abs(deltaX) < SWIPE_DIRECTION_RATIO * Math.abs(deltaY)
      ) {
        return;
      }
      if (openDrawer) {
        // Opposite motion closes: structure drawer swipes back left,
        // menu drawer swipes back right. Anything else does nothing.
        // Closes are never suppressed by horizontal overflow.
        if (openDrawer === structureDrawer && deltaX < 0) {
          closeDrawers(false);
        } else if (openDrawer === menuDrawer && deltaX > 0) {
          closeDrawers(false);
        }
        return;
      }
      if (swipeStartsInHorizontalScroller(event.target)) {
        return;
      }
      if (deltaX > 0) {
        openStructureDrawer();
      } else {
        openMenuDrawer();
      }
    };
    document.addEventListener('touchstart', onTouchStart);
    document.addEventListener('touchend', onTouchEnd);
    document.addEventListener('touchcancel', resetSwipe);
    cleanup.push(() => document.removeEventListener('touchstart', onTouchStart));
    cleanup.push(() => document.removeEventListener('touchend', onTouchEnd));
    cleanup.push(() => document.removeEventListener('touchcancel', resetSwipe));
  }

  const onDocumentKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape' && openDrawer) {
      hideDrawer(openDrawer, true);
      return;
    }
    if (
      event.key === '/' &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey &&
      !event.isComposing &&
      !isDesktopNavbarLayout() &&
      !isEditableTarget(event.target)
    ) {
      event.preventDefault();
      openMenuDrawer();
      scope
        .querySelector<HTMLElement>(SELECTORS.drawerSearchInput)
        ?.focus();
    }
  };
  document.addEventListener('keydown', onDocumentKeydown);
  cleanup.push(() => document.removeEventListener('keydown', onDocumentKeydown));

  const structureLinks: StructureLink[] = Array.from(
    scope.querySelectorAll<HTMLElement>(SELECTORS.docStructureLink)
  )
    .map((link) => {
      const id = resolveStructureTargetId(link);
      if (!id) {
        return null;
      }
      return {
        id,
        element: link
      };
    })
    .filter((link): link is StructureLink => link !== null);

  const structureTargetsById: Record<string, HTMLElement> = {};
  structureLinks.forEach((link) => {
    if (structureTargetsById[link.id]) {
      return;
    }
    const target = document.getElementById(link.id);
    if (target instanceof HTMLElement) {
      structureTargetsById[link.id] = target;
    }
  });

  const updateDocumentStructureState = () => {
    if (structureLinks.length === 0) {
      return;
    }
    const targets: StructureTarget[] = [];
    Object.keys(structureTargetsById).forEach((id) => {
      targets.push({
        id,
        top: getElementDocumentTop(structureTargetsById[id])
      });
    });
    if (targets.length === 0) {
      return;
    }
    targets.sort((a, b) => a.top - b.top);

    const navbarOffset = navbarRevealed && navbar ? getElementHeight(navbar) : 0;
    const activationTop = getScrollY() + navbarOffset + SCROLL_ACTIVATION_OFFSET;
    let activeId = targets[0].id;
    targets.forEach((target) => {
      if (target.top <= activationTop) {
        activeId = target.id;
      }
    });

    structureLinks.forEach((link) => {
      const active = link.id === activeId;
      link.element.classList.toggle(DOC_LINK_ACTIVE_CLASS, active);
      if (active) {
        link.element.setAttribute('aria-current', 'true');
      } else {
        link.element.removeAttribute('aria-current');
      }
    });
  };

  if (structureLinks.length > 0) {
    updateDocumentStructureState();
    const onScroll = () => {
      documentStructureTask.request(updateDocumentStructureState);
    };
    const onResize = () => {
      documentStructureTask.request(updateDocumentStructureState);
    };
    window.addEventListener('scroll', onScroll);
    window.addEventListener('resize', onResize);
    cleanup.push(() => window.removeEventListener('scroll', onScroll));
    cleanup.push(() => window.removeEventListener('resize', onResize));
  }

  const closeDocumentStructureMenu = () => {
    closeMobileMenu();
  };

  return {
    closeAllDropdowns,
    closeDocumentStructureMenu,
    updateDocumentStructureState,
    updateNavbarRevealState,
    registerDropdowns,
    registerExpanders,
    openMenuDrawer,
    openStructureDrawer,
    closeDrawers,
    destroy: () => {
      scrollTask.cancel();
      documentStructureTask.cancel();
      stopPageScroll();
      restoreHeldHeadingId();
      setNavbarRevealed(false);
      closeMobileMenu();
      if (openDrawer) {
        openDrawer.classList.remove(DRAWER_OPEN_CLASS);
        finishHideDrawer(openDrawer);
        openDrawer = null;
      }
      drawerInvoker = null;
      if (drawerHideTimer !== null) {
        window.clearTimeout(drawerHideTimer);
        drawerHideTimer = null;
      }
      unlockBodyScroll();
      removeNavbarFlowSpacer();
      cleanup.forEach((fn) => fn());
    }
  };
}
