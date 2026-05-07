// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const SELECTORS = {
  wrapper: '[data-site-code-block="true"]',
  button: '[data-site-code-copy="true"]',
  code: 'pre > code'
} as const;

type ClipboardLike = {
  writeText: (value: string) => Promise<void>;
};

function getClipboard(): ClipboardLike | null {
  const nav = navigator as Navigator & Partial<{ clipboard: ClipboardLike }>;
  return nav.clipboard ?? null;
}

async function copyText(value: string): Promise<boolean> {
  const clipboard = getClipboard();
  if (clipboard) {
    try {
      await clipboard.writeText(value);
      return true;
    } catch {
      // fall through to legacy path
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.top = '0';
  textarea.style.left = '0';
  textarea.style.opacity = '0';
  document.body.append(textarea);
  textarea.select();

  let ok = false;
  try {
    ok = document.execCommand?.('copy') ?? false;
  } catch {
    ok = false;
  }
  textarea.remove();
  return ok;
}

function findCodeForButton(button: HTMLElement): HTMLElement | null {
  const wrapper = button.closest<HTMLElement>(SELECTORS.wrapper);
  if (!wrapper) {
    return null;
  }
  return wrapper.querySelector<HTMLElement>(SELECTORS.code);
}

function setButtonLabel(button: HTMLButtonElement, label: string) {
  button.textContent = label;
  button.setAttribute('aria-label', label);
}

export function initCodeCopyButtons(root: ParentNode = document) {
  const buttons = Array.from(root.querySelectorAll<HTMLButtonElement>(SELECTORS.button));
  buttons.forEach((button) => {
    if (button.dataset.siteCodeCopyInit === 'true') {
      return;
    }
    button.dataset.siteCodeCopyInit = 'true';

    let resetTimer: number | null = null;
    button.addEventListener('click', async () => {
      if (resetTimer) {
        window.clearTimeout(resetTimer);
        resetTimer = null;
      }

      const code = findCodeForButton(button);
      const text = code?.textContent ?? '';
      if (!text.trim()) {
        return;
      }

      const ok = await copyText(text);
      if (!ok) {
        setButtonLabel(button, 'Failed');
        resetTimer = window.setTimeout(() => setButtonLabel(button, 'Copy'), 2000);
        return;
      }

      setButtonLabel(button, 'Copied');
      resetTimer = window.setTimeout(() => setButtonLabel(button, 'Copy'), 2000);
    });
  });
}

