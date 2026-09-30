// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { collectAssetUrls, initAssetReload } from './assetReload';

function footerHtml() {
  return [
    '<link rel="stylesheet" href="/builtin/bulma.min.css?v=1">',
    '<link rel="icon" href="/favicon.ico">',
    '<script src="/builtin/site.js?v=1"></script>',
    '<footer class="site-page-footer" data-site-page-footer>',
    '<a href="" data-site-asset-reload>reload</a>',
    '</footer>'
  ].join('');
}

type WindowLocation = {
  location?: { reload: ReturnType<typeof vi.fn> } | Location;
};

describe('asset reload', () => {
  let reload: ReturnType<typeof vi.fn>;
  let fetchMock: ReturnType<typeof vi.fn>;
  const originalLocation = window.location;
  const win = window as unknown as WindowLocation;

  beforeEach(() => {
    document.head.innerHTML = '';
    document.body.innerHTML = footerHtml();
    reload = vi.fn();
    fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
    delete win.location;
    win.location = { reload };
  });

  afterEach(() => {
    win.location = originalLocation;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    document.head.innerHTML = '';
    document.body.innerHTML = '';
  });

  it('collects script, stylesheet, and icon URLs', () => {
    const urls = collectAssetUrls(document);
    expect(urls.some((url) => url.includes('/builtin/site.js?v=1'))).toBe(true);
    expect(urls.some((url) => url.includes('/builtin/bulma.min.css?v=1'))).toBe(true);
    expect(urls.some((url) => url.includes('/favicon.ico'))).toBe(true);
  });

  it('refetches collected assets with cache reload then reloads the document', async () => {
    initAssetReload(document);
    const link = document.querySelector<HTMLAnchorElement>('[data-site-asset-reload]');
    link?.click();

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));

    expect(fetchMock).toHaveBeenCalled();
    const reloadCalls = fetchMock.mock.calls.filter(
      (call) => call[1] && call[1].cache === 'reload' && call[1].credentials === 'same-origin'
    );
    expect(reloadCalls.length).toBeGreaterThan(0);
    expect(
      reloadCalls.some((call) => String(call[0]).includes('/builtin/site.js?v=1'))
    ).toBe(true);
    expect(
      reloadCalls.some((call) => String(call[0]).includes('/builtin/bulma.min.css?v=1'))
    ).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('reloads the document when a refetch fails', async () => {
    fetchMock.mockRejectedValue(new Error('network'));
    initAssetReload(document);
    document.querySelector<HTMLAnchorElement>('[data-site-asset-reload]')?.click();

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  });

  it('ignores modified clicks', async () => {
    initAssetReload(document);
    const link = document.querySelector<HTMLAnchorElement>('[data-site-asset-reload]');
    link?.dispatchEvent(
      new MouseEvent('click', { bubbles: true, cancelable: true, ctrlKey: true })
    );

    await Promise.resolve();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it('binds once', async () => {
    initAssetReload(document);
    initAssetReload(document);
    document.querySelector<HTMLAnchorElement>('[data-site-asset-reload]')?.click();

    await vi.waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  });

  it('is a no-op without the footer link', () => {
    document.body.innerHTML = '<p>public page</p>';
    initAssetReload(document);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });
});
