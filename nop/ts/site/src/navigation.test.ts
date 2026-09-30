// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  STRUCTURE_PANEL_SCROLL_MS,
  easeInOut,
  initSiteNavigation,
  setExpanderState
} from './navigation';

function setScrollY(value: number) {
  Object.defineProperty(window, 'pageYOffset', {
    value,
    configurable: true
  });
}

function setViewportSize(width: number, height: number) {
  Object.defineProperty(window, 'innerWidth', {
    value: width,
    configurable: true
  });
  Object.defineProperty(window, 'innerHeight', {
    value: height,
    configurable: true
  });
}

function stubRect(element: HTMLElement, top: () => number, height: number) {
  vi.spyOn(element, 'getBoundingClientRect').mockImplementation(
    () =>
      ({
        top: top(),
        bottom: top() + height,
        left: 0,
        right: 100,
        width: 100,
        height,
        x: 0,
        y: top(),
        toJSON: () => ({})
      }) as DOMRect
  );
  Object.defineProperty(element, 'offsetHeight', {
    value: height,
    configurable: true
  });
}

describe('site navigation', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    setScrollY(0);
    setViewportSize(1024, 768);
  });

  afterEach(() => {
    vi.restoreAllMocks();
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
          <a class="navbar-link is-arrowless" href="/one"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></button>
          <div class="navbar-dropdown"></div>
        </div>
        <div data-site-dropdown>
          <a class="navbar-link is-arrowless" href="/two"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></button>
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
          <a class="navbar-link is-arrowless" href="/one"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="true"></button>
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
          <a class="navbar-link is-arrowless" href="/one"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></button>
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

  it('keeps hover dropdowns open while hovering the menu', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-dropdown data-site-dropdown-hover="true">
          <a class="navbar-link is-arrowless" href="/one"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></button>
          <div class="navbar-dropdown"></div>
        </div>
      </div>
    `;

    initSiteNavigation(document);

    const dropdown = document.querySelector<HTMLElement>('[data-site-dropdown]');
    const menu = document.querySelector<HTMLElement>('.navbar-dropdown');

    dropdown?.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    expect(dropdown?.classList.contains('is-active')).toBe(true);

    menu?.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
    expect(dropdown?.classList.contains('is-active')).toBe(true);
  });

  it('does not toggle dropdowns when main link is clicked', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <div data-site-dropdown>
          <a class="navbar-link is-arrowless" href="/main"></a>
          <button data-site-dropdown-toggle class="navbar-link" aria-expanded="false"></button>
          <div class="navbar-dropdown"></div>
        </div>
      </div>
    `;

    initSiteNavigation(document);

    const dropdown = document.querySelector<HTMLElement>('[data-site-dropdown]');
    const mainLink = document.querySelector<HTMLElement>('.navbar-link.is-arrowless');

    mainLink?.addEventListener('click', (event) => event.preventDefault());
    mainLink?.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
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
    const toggle = document.createElement('button');
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

  it('reveals the navbar only when scrolling upward after the original navbar is above the viewport', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar"></nav>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    stubRect(navbar, () => -window.pageYOffset, 63.5);

    const controller = initSiteNavigation(document);

    setScrollY(180);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);

    setScrollY(140);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);
    expect(navbar.getAttribute('data-site-navbar-revealed')).toBe('true');
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.display).toBe(
      'block'
    );
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.height).toBe(
      '63.5px'
    );

    setScrollY(170);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);
    expect(navbar.hasAttribute('data-site-navbar-revealed')).toBe(false);
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.display).toBe(
      'none'
    );
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.height).toBe(
      '0px'
    );

    setScrollY(40);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);
  });

  it('keeps the revealed mobile navbar visible while the hamburger menu is open during scrolling', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar">
        <button type="button" data-site-mobile-toggle aria-expanded="false"></button>
        <div data-site-mobile-menu class="navbar-menu"></div>
      </nav>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    const trigger = document.querySelector<HTMLElement>('[data-site-mobile-toggle]')!;
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    const controller = initSiteNavigation(document);

    setScrollY(180);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);

    setScrollY(140);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);

    trigger.click();
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(menu.classList.contains('is-active')).toBe(true);

    setScrollY(240);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);
    expect(navbar.getAttribute('data-site-navbar-revealed')).toBe('true');
  });

  it('keeps a revealed navbar visible during viewport-height-only mobile resize events', () => {
    setViewportSize(390, 760);
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar"></nav>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    const controller = initSiteNavigation(document);

    setScrollY(180);
    controller.updateNavbarRevealState();
    setScrollY(140);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);

    setScrollY(150);
    setViewportSize(390, 640);
    window.dispatchEvent(new Event('resize'));

    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);
    expect(navbar.getAttribute('data-site-navbar-revealed')).toBe('true');
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.display).toBe(
      'block'
    );

    setScrollY(170);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);
  });

  it('hides a revealed navbar and closes the mobile menu when resize changes width', () => {
    setViewportSize(390, 760);
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar">
        <button type="button" data-site-mobile-toggle aria-expanded="false"></button>
        <div data-site-mobile-menu class="navbar-menu"></div>
      </nav>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    const trigger = document.querySelector<HTMLElement>('[data-site-mobile-toggle]')!;
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    const controller = initSiteNavigation(document);

    setScrollY(180);
    controller.updateNavbarRevealState();
    setScrollY(140);
    controller.updateNavbarRevealState();
    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(true);

    trigger.click();
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(menu.classList.contains('is-active')).toBe(true);

    setViewportSize(1024, 760);
    window.dispatchEvent(new Event('resize'));

    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);
    expect(navbar.hasAttribute('data-site-navbar-revealed')).toBe(false);
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(menu.classList.contains('is-active')).toBe(false);
    expect(document.querySelector<HTMLElement>('[data-site-navbar-flow-spacer]')?.style.display).toBe(
      'none'
    );
  });

  it('does not activate scroll reveal on pages without a navbar', () => {
    document.body.innerHTML = `
      <main>
        <h2 id="section">Section</h2>
      </main>
    `;

    const controller = initSiteNavigation(document);
    setScrollY(120);

    expect(() => controller.updateNavbarRevealState()).not.toThrow();
    expect(document.querySelector('[data-site-navbar-revealed]')).toBeNull();
  });

  it('keeps desktop document structure active links in sync', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar"></nav>
      <aside data-site-doc-structure>
        <a data-site-doc-structure-link data-site-doc-structure-target="intro" href="#intro">Intro</a>
        <a data-site-doc-structure-link data-site-doc-structure-target="details" href="#details">Details</a>
      </aside>
      <div data-site-mobile-menu class="navbar-menu is-active">
      </div>
      <main>
        <h2 id="intro">Intro</h2>
        <h2 id="details">Details</h2>
      </main>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    const intro = document.getElementById('intro')!;
    const details = document.getElementById('details')!;
    stubRect(navbar, () => -window.pageYOffset, 64);
    stubRect(intro, () => 100 - window.pageYOffset, 40);
    stubRect(details, () => 300 - window.pageYOffset, 40);

    const controller = initSiteNavigation(document);
    const links = Array.from(
      document.querySelectorAll<HTMLElement>('[data-site-doc-structure-link]')
    );

    expect(links).toHaveLength(2);
    expect(links[0].classList.contains('is-active')).toBe(true);
    expect(links[0].getAttribute('aria-current')).toBe('true');
    expect(links[1].hasAttribute('aria-current')).toBe(false);

    setScrollY(290);
    controller.updateDocumentStructureState();

    expect(links[0].classList.contains('is-active')).toBe(false);
    expect(links[1].classList.contains('is-active')).toBe(true);
    expect(links[1].getAttribute('aria-current')).toBe('true');
  });

  it('leaves the mobile hamburger menu open after a document structure link click', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar">
        <button type="button" data-site-mobile-toggle aria-expanded="false"></button>
        <div data-site-mobile-menu class="navbar-menu">
        </div>
      </nav>
      <aside data-site-doc-structure>
        <a data-site-doc-structure-link data-site-doc-structure-target="intro" href="#intro">Intro</a>
      </aside>
      <h2 id="intro">Intro</h2>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    initSiteNavigation(document);
    const trigger = document.querySelector<HTMLElement>('[data-site-mobile-toggle]')!;
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]')!;
    const link = document.querySelector<HTMLElement>('[data-site-doc-structure-link]')!;

    trigger.click();
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(menu.classList.contains('is-active')).toBe(true);

    link.click();
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(menu.classList.contains('is-active')).toBe(true);
  });

  it('closeDocumentStructureMenu closes the mobile hamburger menu', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar">
        <button type="button" data-site-mobile-toggle aria-expanded="false"></button>
        <div data-site-mobile-menu class="navbar-menu">
        </div>
      </nav>
      <h2 id="intro">Intro</h2>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    const controller = initSiteNavigation(document);
    const trigger = document.querySelector<HTMLElement>('[data-site-mobile-toggle]')!;
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]')!;

    trigger.click();
    controller.closeDocumentStructureMenu();

    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(menu.classList.contains('is-active')).toBe(false);
  });

  it('removes document structure and scroll listeners during cleanup', () => {
    document.body.innerHTML = `
      <nav data-site-navbar class="navbar">
        <button type="button" data-site-mobile-toggle aria-expanded="false"></button>
        <div data-site-mobile-menu class="navbar-menu">
        </div>
      </nav>
      <h2 id="intro">Intro</h2>
    `;
    const navbar = document.querySelector<HTMLElement>('[data-site-navbar]')!;
    stubRect(navbar, () => -window.pageYOffset, 64);

    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((callback) => {
      callback(0);
      return 1;
    });
    vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {});

    const controller = initSiteNavigation(document);
    const trigger = document.querySelector<HTMLElement>('[data-site-mobile-toggle]')!;
    const menu = document.querySelector<HTMLElement>('[data-site-mobile-menu]')!;

    trigger.click();
    expect(menu.classList.contains('is-active')).toBe(true);

    controller.destroy();
    expect(menu.classList.contains('is-active')).toBe(false);

    setScrollY(180);
    controller.updateNavbarRevealState();
    setScrollY(140);
    window.dispatchEvent(new Event('scroll'));

    expect(navbar.classList.contains('is-site-navbar-revealed')).toBe(false);
  });
});

describe('expander state', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div data-site-expander>
        <button type="button" data-site-expander-toggle aria-expanded="false">
          <span data-site-expander-chevron></span>Parent
        </button>
        <div data-site-expander-panel hidden>
          <a href="/child">Child</a>
        </div>
      </div>
    `;
  });

  it('opens collapsed expander pointing down', () => {
    const toggle = document.querySelector<HTMLElement>('[data-site-expander-toggle]')!;
    setExpanderState(toggle, true);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const wrapper = document.querySelector<HTMLElement>('[data-site-expander]')!;
    expect(wrapper.classList.contains('is-open')).toBe(true);
    const panel = document.querySelector<HTMLElement>('[data-site-expander-panel]')!;
    expect(panel.hasAttribute('hidden')).toBe(false);
  });

  it('collapses open expander pointing right', () => {
    const toggle = document.querySelector<HTMLElement>('[data-site-expander-toggle]')!;
    setExpanderState(toggle, true);
    setExpanderState(toggle, false);
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    const wrapper = document.querySelector<HTMLElement>('[data-site-expander]')!;
    expect(wrapper.classList.contains('is-open')).toBe(false);
    const panel = document.querySelector<HTMLElement>('[data-site-expander-panel]')!;
    expect(panel.hasAttribute('hidden')).toBe(true);
  });
});

function installScrollTop() {
  let y = window.pageYOffset || 0;
  const writes: number[] = [];
  Object.defineProperty(document.documentElement, 'scrollTop', {
    configurable: true,
    get: () => y,
    set: (value: number) => {
      y = value;
      writes.push(value);
      setScrollY(value);
    }
  });
  Object.defineProperty(document.body, 'scrollTop', {
    configurable: true,
    get: () => y,
    set: (value: number) => {
      y = value;
    }
  });
  return writes;
}

describe('page top and bottom jumps', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    setScrollY(0);
    setViewportSize(1024, 768);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('scrolls a title top entry to the absolute page top', () => {
    document.body.innerHTML = `
      <aside data-site-doc-structure>
        <nav><ol>
          <li><button type="button" data-site-doc-structure-top aria-label="Go to top">My Page</button></li>
        </ol></nav>
      </aside>
    `;
    const writes = installScrollTop();
    initSiteNavigation(document);

    setScrollY(400);
    document
      .querySelector<HTMLElement>('[data-site-doc-structure-top]')
      ?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);

    expect(writes[writes.length - 1]).toBe(0);
  });

  it('scrolls the bottom entry to the document bottom', () => {
    document.body.innerHTML = `
      <aside data-site-doc-structure>
        <nav><ol>
          <li><button type="button" data-site-doc-structure-bottom aria-label="Go to bottom"></button></li>
        </ol></nav>
      </aside>
    `;
    Object.defineProperty(document.documentElement, 'scrollHeight', {
      value: 2000,
      configurable: true
    });
    setViewportSize(1024, 768);
    const writes = installScrollTop();
    initSiteNavigation(document);

    document
      .querySelector<HTMLElement>('[data-site-doc-structure-bottom]')
      ?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);

    expect(writes[writes.length - 1]).toBe(1232);
    delete (document.documentElement as unknown as Record<string, unknown>)['scrollHeight'];
  });

  it('dismisses the structure drawer before jumping', () => {
    document.body.innerHTML = `
      <div data-site-root>
        <button type="button" data-site-topbar-structure aria-expanded="false"></button>
        <div data-site-structure-drawer hidden>
          <button type="button" data-site-drawer-back>Back</button>
          <button type="button" data-site-doc-structure-bottom aria-label="Go to bottom"></button>
        </div>
      </div>
    `;
    Object.defineProperty(document.documentElement, 'scrollHeight', {
      value: 2000,
      configurable: true
    });
    const writes = installScrollTop();
    const controller = initSiteNavigation(document);
    const drawer = document.querySelector<HTMLElement>('[data-site-structure-drawer]')!;

    controller.openStructureDrawer();
    expect(drawer.classList.contains('is-open')).toBe(true);

    document
      .querySelector<HTMLElement>('[data-site-doc-structure-bottom]')
      ?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    expect(drawer.classList.contains('is-open')).toBe(false);
    vi.advanceTimersByTime(10);
    expect(writes[writes.length - 1]).toBe(2000);
    delete (document.documentElement as unknown as Record<string, unknown>)['scrollHeight'];
    controller.destroy();
  });
});

describe('visible structure panel scroll', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    setScrollY(0);
    setViewportSize(1400, 800);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    delete (document.documentElement as unknown as Record<string, unknown>)['scrollHeight'];
  });

  function setPageHeight(height: number) {
    Object.defineProperty(document.documentElement, 'scrollHeight', {
      configurable: true,
      value: height
    });
  }

  function visibleHeadingPage() {
    document.body.innerHTML = `
      <aside data-site-doc-structure>
        <a data-site-doc-structure-link data-site-doc-structure-target="intro" href="#intro">Intro</a>
      </aside>
      <h2 id="intro">Intro</h2>
    `;
    const heading = document.getElementById('intro')!;
    Object.defineProperty(heading, 'offsetTop', { configurable: true, value: 900 });
    Object.defineProperty(heading, 'offsetParent', { configurable: true, value: null });
    setPageHeight(5000);
  }

  it('eases a panel heading and leaves the URL alone', () => {
    visibleHeadingPage();
    const writes = installScrollTop();
    initSiteNavigation(document);
    const event = new MouseEvent('click', { bubbles: true, cancelable: true });

    document.querySelector('a')!.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(window.location.hash).toBe('');
    expect(document.querySelector('h2')?.getAttribute('id')).toBeNull();
    expect(document.querySelector('a')?.getAttribute('href')).toBe('#intro');

    vi.advanceTimersByTime(100);
    const early = writes[writes.length - 1];
    expect(early).toBeGreaterThan(0);
    expect(early).toBeLessThan(300);

    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS / 2);
    const mid = writes[writes.length - 1];
    expect(mid).toBeGreaterThan(early);
    expect(mid).toBeGreaterThan(200);
    expect(mid).toBeLessThan(900);
    expect(window.location.hash).toBe('');

    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);
    expect(writes[writes.length - 1]).toBe(900);
    expect(window.location.hash).toBe('');
    expect(document.querySelector('h2')?.id).toBe('intro');
    expect(document.querySelector('a')?.getAttribute('href')).toBe('#intro');
  });

  it('eases even when reduced motion is requested', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query === '(prefers-reduced-motion: reduce)',
      media: query
    }));
    visibleHeadingPage();
    const writes = installScrollTop();
    initSiteNavigation(document);

    document.querySelector('a')!.dispatchEvent(
      new MouseEvent('click', { bubbles: true, cancelable: true })
    );

    expect(writes.length).toBe(1);
    expect(writes[0]).toBeLessThan(900);

    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS * 2);
    expect(writes.length).toBeGreaterThan(2);
    expect(writes[writes.length - 1]).toBe(900);
    expect(window.location.hash).toBe('');
    expect(document.querySelector('h2')?.id).toBe('intro');
  });

  it('does not ease a modified click', () => {
    visibleHeadingPage();
    const writes = installScrollTop();
    initSiteNavigation(document);
    const event = new MouseEvent('click', {
      bubbles: true,
      cancelable: true,
      metaKey: true
    });

    document.querySelector('a')!.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
    expect(writes).toEqual([]);
  });

  it('cancels the ease when the reader wheels', () => {
    visibleHeadingPage();
    const writes = installScrollTop();
    initSiteNavigation(document);

    document.querySelector('a')!.dispatchEvent(
      new MouseEvent('click', { bubbles: true, cancelable: true })
    );
    vi.advanceTimersByTime(100);
    const calls = writes.length;

    window.dispatchEvent(new Event('wheel'));
    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);

    expect(writes.length).toBe(calls);
    expect(window.location.hash).toBe('');
    expect(document.querySelector('h2')?.id).toBe('intro');
  });

  it('eases the panel top and bottom entries to the page ends', () => {
    document.body.innerHTML = `
      <aside data-site-doc-structure>
        <button type="button" data-site-doc-structure-top aria-label="Go to top">Title</button>
        <button type="button" data-site-doc-structure-bottom aria-label="Go to bottom"></button>
      </aside>
    `;
    setPageHeight(2000);
    const writes = installScrollTop();
    initSiteNavigation(document);

    document
      .querySelector<HTMLElement>('[data-site-doc-structure-bottom]')!
      .dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);
    expect(writes[writes.length - 1]).toBe(1200);

    setScrollY(1200);
    document
      .querySelector<HTMLElement>('[data-site-doc-structure-top]')!
      .dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    vi.advanceTimersByTime(STRUCTURE_PANEL_SCROLL_MS);
    expect(writes[writes.length - 1]).toBe(0);
  });

  it('stops an in-flight ease when the controller is destroyed', () => {
    visibleHeadingPage();
    installScrollTop();
    const controller = initSiteNavigation(document);

    document.querySelector('a')!.dispatchEvent(
      new MouseEvent('click', { bubbles: true, cancelable: true })
    );
    expect(document.querySelector('h2')?.getAttribute('id')).toBeNull();
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    controller.destroy();

    expect(vi.getTimerCount()).toBe(0);
    expect(document.querySelector('h2')?.id).toBe('intro');
  });

  it('does not ease a structure drawer heading click', () => {
    document.body.innerHTML = `
      <div data-site-structure-drawer>
        <a data-site-doc-structure-link data-site-doc-structure-target="intro" href="#intro">Intro</a>
      </div>
      <h2 id="intro">Intro</h2>
    `;
    const writes = installScrollTop();
    initSiteNavigation(document);

    document.querySelector('a')!.dispatchEvent(
      new MouseEvent('click', { bubbles: true, cancelable: true })
    );

    expect(window.location.hash).toBe('#intro');
    expect(writes).toEqual([]);
  });
});

describe('structure scroll easing curve', () => {
  it('runs from zero to one without moving backwards', () => {
    expect(easeInOut(0)).toBe(0);
    expect(easeInOut(1)).toBe(1);
    let previous = 0;
    for (let step = 1; step <= 100; step += 1) {
      const value = easeInOut(step / 100);
      expect(value).toBeGreaterThanOrEqual(previous);
      previous = value;
    }
  });

  it('joins the ease-in and ease-out without a jump in position or speed', () => {
    const delta = 1e-6;
    expect(Math.abs(easeInOut(0.35 + delta) - easeInOut(0.35 - delta))).toBeLessThan(1e-5);
    const speedBefore = (easeInOut(0.35) - easeInOut(0.35 - delta)) / delta;
    const speedAfter = (easeInOut(0.35 + delta) - easeInOut(0.35)) / delta;
    expect(Math.abs(speedBefore - speedAfter)).toBeLessThan(1e-3);
  });

  it('decelerates more gently than it accelerates', () => {
    expect(1 - easeInOut(0.8)).toBeLessThan(easeInOut(0.2));
    expect(1 - easeInOut(0.9)).toBeLessThan(0.005);
  });

  it('keeps settling through the tail instead of parking early', () => {
    // The ease is still visibly moving at 90% (no long dead stop) and has
    // nearly landed by 95%.
    expect(1 - easeInOut(0.9)).toBeGreaterThan(0.001);
    expect(1 - easeInOut(0.95)).toBeLessThan(0.001);
  });
});
