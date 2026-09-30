// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const SELECTOR = '[data-site-asset-reload]';

function shouldRefetch(url: string): boolean {
  if (!url) {
    return false;
  }
  const lower = url.toLowerCase();
  return (
    lower.indexOf('data:') !== 0 &&
    lower.indexOf('blob:') !== 0 &&
    lower.indexOf('javascript:') !== 0
  );
}

function addUrl(urls: string[], seen: Record<string, boolean>, url: string) {
  if (!shouldRefetch(url) || seen[url]) {
    return;
  }
  seen[url] = true;
  urls.push(url);
}

export function collectAssetUrls(root: ParentNode = document): string[] {
  const urls: string[] = [];
  const seen: Record<string, boolean> = {};
  const scripts = root.querySelectorAll('script[src]');
  for (let i = 0; i < scripts.length; i += 1) {
    addUrl(urls, seen, (scripts[i] as HTMLScriptElement).src);
  }
  const links = root.querySelectorAll('link[href]');
  for (let i = 0; i < links.length; i += 1) {
    const link = links[i] as HTMLLinkElement;
    const rel = (link.rel || '').toLowerCase();
    if (
      rel === 'stylesheet' ||
      rel === 'icon' ||
      rel === 'shortcut icon' ||
      rel === 'preload' ||
      rel === 'prefetch'
    ) {
      addUrl(urls, seen, link.href);
    }
  }
  return urls;
}

function refetchAssets(urls: string[]): Promise<void> {
  if (urls.length === 0) {
    return Promise.resolve();
  }
  return Promise.all(
    urls.map((url) =>
      fetch(url, { cache: 'reload', credentials: 'same-origin' }).then(
        () => undefined,
        () => undefined
      )
    )
  ).then(() => undefined);
}

function reloadDocument() {
  window.location.reload();
}

export function initAssetReload(root: ParentNode = document) {
  const links = root.querySelectorAll<HTMLAnchorElement>(SELECTOR);
  for (let i = 0; i < links.length; i += 1) {
    const link = links[i];
    if (link.dataset.siteAssetReloadInit === 'true') {
      continue;
    }
    link.dataset.siteAssetReloadInit = 'true';
    let reloading = false;
    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0) {
        return;
      }
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }
      event.preventDefault();
      if (reloading) {
        return;
      }
      reloading = true;
      refetchAssets(collectAssetUrls(document)).then(reloadDocument, reloadDocument);
    });
  }
}
