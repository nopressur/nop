// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { LoginRuntimeConfig } from './types';

declare global {
  interface Window {
    nopLoginConfig?: LoginRuntimeConfig | string;
  }
}

export function getRuntimeConfig(): LoginRuntimeConfig {
  const raw = window.nopLoginConfig;
  if (!raw) {
    throw new Error('Login runtime config is missing');
  }

  const parsed =
    typeof raw === 'string' ? (JSON.parse(raw) as LoginRuntimeConfig) : raw;

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Login runtime config is invalid');
  }

  const initialRoute =
    parsed.initialRoute === 'profile' ? 'profile' : 'login';
  return {
    ...parsed,
    initialRoute,
    returnPath: parsed.returnPath ?? null,
    user: parsed.user ?? null
  };
}
