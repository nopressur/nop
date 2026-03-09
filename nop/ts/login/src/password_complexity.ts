// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type PasswordComplexityCase = 'uncased' | 'cased' | 'mixed';

export type PasswordComplexityResult = {
  caseType: PasswordComplexityCase;
  length: number;
  message: string;
  valid: boolean;
};

const NOTE_UNCASED =
  'Password needs to be at least 8 long with letters and numbers.';
const NOTE_CASED =
  'Password needs to be at least 8 long with lowercase and uppercase letters and numbers.';

const LOWER_RE = /\p{Ll}/u;
const UPPER_RE = /\p{Lu}/u;
const LETTER_RE = /\p{L}/u;
const NUMBER_RE = /\p{Nd}/u;

export function evaluatePasswordComplexity(
  password: string
): PasswordComplexityResult {
  let hasLower = false;
  let hasUpper = false;
  let hasLetter = false;
  let hasUncased = false;
  let hasNumber = false;

  const chars = Array.from(password);
  for (const ch of chars) {
    const isLower = LOWER_RE.test(ch);
    const isUpper = UPPER_RE.test(ch);
    const isLetter = LETTER_RE.test(ch);
    if (isLower) {
      hasLower = true;
      hasLetter = true;
    } else if (isUpper) {
      hasUpper = true;
      hasLetter = true;
    } else if (isLetter) {
      hasLetter = true;
      hasUncased = true;
    }
    if (NUMBER_RE.test(ch)) {
      hasNumber = true;
    }
  }

  let caseType: PasswordComplexityCase = 'uncased';
  if (hasLower || hasUpper) {
    caseType = hasUncased ? 'mixed' : 'cased';
  }

  const length = chars.length;
  const lengthOk = length >= 8;
  const numberOk = hasNumber;
  const letterOk = hasLetter;
  const caseOk = caseType === 'cased' ? hasLower && hasUpper : true;

  const valid = lengthOk && numberOk && letterOk && caseOk;
  const message = caseType === 'cased' ? NOTE_CASED : NOTE_UNCASED;

  return { caseType, length, message, valid };
}
