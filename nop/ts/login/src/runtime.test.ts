// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { afterEach, describe, expect, it } from 'vitest';
import type { LoginRuntimeConfig } from './types';
import { getRuntimeConfig } from './runtime';

const baseConfig: LoginRuntimeConfig = {
  appName: 'Test App',
  loginPath: '/login',
  profilePath: '/login/profile',
  profileApiPath: '/profile',
  csrfTokenPath: '/login/csrf-token-api',
  initialRoute: 'login',
  providers: [],
  passwordFrontEnd: {
    memoryKib: 65536,
    iterations: 2,
    parallelism: 1,
    outputLen: 32,
    saltLen: 16
  },
  returnPath: null,
  user: null
};

describe('getRuntimeConfig', () => {
  const originalConfig = window.nopLoginConfig;

  it('throws when runtime config is missing', () => {
    delete window.nopLoginConfig;
    expect(() => getRuntimeConfig()).toThrow('Login runtime config is missing');
  });

  it('throws when runtime config is invalid', () => {
    window.nopLoginConfig = 'invalid-json';
    expect(() => getRuntimeConfig()).toThrow();
  });

  it('parses JSON runtime config and normalizes fields', () => {
    window.nopLoginConfig = JSON.stringify({
      ...baseConfig,
      initialRoute: 'profile'
    });

    const config = getRuntimeConfig();
    expect(config.initialRoute).toBe('profile');
    expect(config.returnPath).toBeNull();
    expect(config.user).toBeNull();
  });

  it('defaults initialRoute to login for unknown values', () => {
    window.nopLoginConfig = {
      ...baseConfig,
      initialRoute: 'other'
    };

    const config = getRuntimeConfig();
    expect(config.initialRoute).toBe('login');
  });

  afterEach(() => {
    if (originalConfig === undefined) {
      delete window.nopLoginConfig;
    } else {
      window.nopLoginConfig = originalConfig;
    }
  });
});
