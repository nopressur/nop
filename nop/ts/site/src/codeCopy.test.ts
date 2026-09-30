// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initCodeCopyButtons } from './codeCopy';

describe('code copy', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML =
      '<figure data-site-code-block="true"><figcaption><button type="button" data-site-code-copy="true" aria-label="Copy code block"><img src="/builtin/copy.svg" alt="" width="16" height="16"><span class="site-visually-hidden" data-site-code-copy-status="true"></span></button></figcaption><pre><code>echo hello\n</code></pre></figure>';
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    delete (navigator as any).clipboard;
  });

  it('copies code text via clipboard and updates status preserving the icon', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true
    });

    initCodeCopyButtons(document);

    const button = document.querySelector<HTMLButtonElement>('[data-site-code-copy="true"]');
    const status = () =>
      button?.querySelector('[data-site-code-copy-status="true"]')?.textContent;
    expect(button?.querySelector('img[src="/builtin/copy.svg"]')).not.toBeNull();
    expect(status()).toBe('');

    button?.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledWith('echo hello');
    expect(status()).toBe('Copied');
    expect(button?.querySelector('img[src="/builtin/copy.svg"]')).not.toBeNull();

    vi.advanceTimersByTime(2000);
    await Promise.resolve();
    expect(status()).toBe('');
    expect(button?.getAttribute('aria-label')).toBe('Copy code block');
  });

  it('removes terminal line breaks without trimming code content', async () => {
    document.body.innerHTML =
      '<figure data-site-code-block="true"><figcaption><button type="button" data-site-code-copy="true" aria-label="Copy code block"><span data-site-code-copy-status="true"></span></button></figcaption><pre><code>line one\nline two  \r\n</code></pre></figure>';
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true
    });

    initCodeCopyButtons(document);

    const button = document.querySelector<HTMLButtonElement>('[data-site-code-copy="true"]');
    button?.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledWith('line one\nline two  ');
  });
});
