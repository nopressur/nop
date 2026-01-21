// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type BrowserTimeoutId = number;

export function getWindow(): Window | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window;
}

export function getDocument(): Document | null {
  if (typeof document === "undefined") {
    return null;
  }
  return document;
}

export function setBrowserTimeout(handler: () => void, timeoutMs: number): BrowserTimeoutId {
  const win = getWindow();
  if (!win) {
    return 0;
  }
  return win.setTimeout(handler, timeoutMs);
}

export function clearBrowserTimeout(id: BrowserTimeoutId | null): void {
  const win = getWindow();
  if (!win || id === null) {
    return;
  }
  win.clearTimeout(id);
}

export function addWindowListener(
  type: string,
  listener: EventListenerOrEventListenerObject,
  options?: AddEventListenerOptions | boolean,
): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.addEventListener(type, listener, options);
}

export function removeWindowListener(
  type: string,
  listener: EventListenerOrEventListenerObject,
  options?: EventListenerOptions | boolean,
): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.removeEventListener(type, listener, options);
}

export function getLocationOrigin(): string {
  const win = getWindow();
  return win ? win.location.origin : "";
}

export function getLocationPathname(): string {
  const win = getWindow();
  return win ? win.location.pathname : "/";
}

export function getLocationSearch(): string {
  const win = getWindow();
  return win ? win.location.search : "";
}

export function setLocationHref(href: string): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.location.href = href;
}

export function reloadWindow(): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.location.reload();
}

export function pushHistoryState(nextPath: string): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.history.pushState({}, "", nextPath);
}

export function replaceHistoryState(nextPath: string): void {
  const win = getWindow();
  if (!win) {
    return;
  }
  win.history.replaceState({}, "", nextPath);
}

export function matchMediaQuery(query: string): MediaQueryList | null {
  const win = getWindow();
  return win ? win.matchMedia(query) : null;
}

export function getLocalStorage(): Storage | null {
  const win = getWindow();
  return win?.localStorage ?? null;
}

export function getSessionStorage(): Storage | null {
  const win = getWindow();
  return win?.sessionStorage ?? null;
}
