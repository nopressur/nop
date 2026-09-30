// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import compat from 'eslint-plugin-compat';

export default [
  {
    ignores: ['build/**', 'dist/**', 'vectors/**']
  },
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 5,
      sourceType: 'script'
    },
    plugins: {
      compat
    },
    rules: {
      'compat/compat': 'error'
    }
  }
];
