// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from 'vitest';
import { evaluatePasswordComplexity } from './password_complexity';

describe('evaluatePasswordComplexity', () => {
  it('accepts cased password with number', () => {
    const result = evaluatePasswordComplexity('Abcdefg1');
    expect(result.valid).toBe(true);
    expect(result.caseType).toBe('cased');
  });

  it('rejects cased password missing lowercase', () => {
    const result = evaluatePasswordComplexity('ABCDEFG1');
    expect(result.valid).toBe(false);
    expect(result.caseType).toBe('cased');
  });

  it('accepts uncased password with number', () => {
    const result = evaluatePasswordComplexity('漢字漢字漢字12');
    expect(result.valid).toBe(true);
    expect(result.caseType).toBe('uncased');
  });

  it('accepts mixed password without both cases', () => {
    const result = evaluatePasswordComplexity('A漢字1234B');
    expect(result.valid).toBe(true);
    expect(result.caseType).toBe('mixed');
  });
});
