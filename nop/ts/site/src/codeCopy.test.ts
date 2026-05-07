// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { initCodeCopyButtons } from './codeCopy';

describe('code copy', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML =
      '<figure data-site-code-block="true"><figcaption><button type="button" data-site-code-copy="true" aria-label="Copy code block">Copy</button></figcaption><pre><code>echo hello</code></pre></figure>';
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    delete (navigator as any).clipboard;
  });

  it('copies code text via clipboard and updates label', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true
    });

    initCodeCopyButtons(document);

    const button = document.querySelector<HTMLButtonElement>('[data-site-code-copy="true"]');
    expect(button?.textContent).toBe('Copy');

    button?.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledWith('echo hello');
    expect(button?.textContent).toBe('Copied');

    vi.advanceTimersByTime(2000);
    await Promise.resolve();
    expect(button?.textContent).toBe('Copy');
  });
});
