// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import tsParser from '@typescript-eslint/parser';
import compat from 'eslint-plugin-compat';

export default [
  {
    ignores: ['node_modules/**', 'dist/**']
  },
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: 'module'
      }
    },
    plugins: {
      compat
    },
    settings: {
      polyfills: [
        'AbortController',
        'Array.from',
        'Promise',
        'Set',
        'fetch',
        'requestAnimationFrame'
      ]
    },
    rules: {
      'compat/compat': 'error'
    }
  },
  {
    files: ['src/**/*.test.ts'],
    rules: {
      'compat/compat': 'off'
    }
  }
];
