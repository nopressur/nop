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
  passwordComplexityEnabled: true,
  returnPath: null,
  user: null
};

describe('getRuntimeConfig', () => {
  const originalConfig = window.nopLoginConfig;

  function setMountConfig(config: unknown) {
    document.body.innerHTML = '';
    const target = document.createElement('div');
    target.id = 'login-app';
    target.setAttribute('data-login-config', JSON.stringify(config));
    document.body.appendChild(target);
  }

  it('throws when runtime config is missing', () => {
    document.body.innerHTML = '';
    delete window.nopLoginConfig;
    expect(() => getRuntimeConfig()).toThrow('Login runtime config is missing');
  });

  it('throws when runtime config is invalid', () => {
    document.body.innerHTML = '';
    window.nopLoginConfig = 'invalid-json';
    expect(() => getRuntimeConfig()).toThrow();
  });

  it('parses mount-node runtime config and normalizes fields', () => {
    delete window.nopLoginConfig;
    setMountConfig({
      ...baseConfig,
      initialRoute: 'profile'
    });

    const config = getRuntimeConfig();
    expect(config.initialRoute).toBe('profile');
    expect(config.returnPath).toBeNull();
    expect(config.user).toBeNull();
  });

  it('keeps window runtime config as a fallback for tests and dev shells', () => {
    document.body.innerHTML = '';
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
    document.body.innerHTML = '';
    window.nopLoginConfig = {
      ...baseConfig,
      initialRoute: 'other'
    };

    const config = getRuntimeConfig();
    expect(config.initialRoute).toBe('login');
  });

  afterEach(() => {
    document.body.innerHTML = '';
    if (originalConfig === undefined) {
      delete window.nopLoginConfig;
    } else {
      window.nopLoginConfig = originalConfig;
    }
  });
});
