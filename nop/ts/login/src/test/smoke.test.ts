// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from 'vitest';

describe('login spa test harness', () => {
  it('provides a jsdom environment', () => {
    expect(typeof window).toBe('object');
    const node = document.createElement('div');
    expect(node).toBeInstanceOf(HTMLElement);
  });
});
