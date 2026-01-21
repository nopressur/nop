// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { LoginRuntimeConfig } from './types';
import { clearCsrfCache, csrfFetch, getCsrfToken, postJson } from './api';

const csrfClientMocks = vi.hoisted(() => {
  const tokenPath: () => string = () => '';
  return {
    getToken: vi.fn(),
    csrfFetch: vi.fn(),
    clear: vi.fn(),
    tokenPath
  };
});

vi.mock('../../shared/src/csrf', () => ({
  createCsrfClient: (options: { tokenPath: () => string }) => {
    csrfClientMocks.tokenPath = options.tokenPath;
    return {
      getToken: csrfClientMocks.getToken,
      csrfFetch: csrfClientMocks.csrfFetch,
      clear: csrfClientMocks.clear
    };
  }
}));

const config: LoginRuntimeConfig = {
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

function buildResponse(options: {
  ok: boolean;
  contentType?: string;
  json?: unknown;
}): Response {
  return {
    ok: options.ok,
    headers: new Headers({
      'content-type': options.contentType ?? 'application/json'
    }),
    json: async () => options.json
  } as Response;
}

describe('postJson', () => {
  const fetchMock = vi.fn();
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    fetchMock.mockReset();
    csrfClientMocks.getToken.mockReset();
    csrfClientMocks.csrfFetch.mockReset();
    csrfClientMocks.clear.mockReset();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns response only when content-type is not json', async () => {
    fetchMock.mockResolvedValueOnce(
      buildResponse({ ok: true, contentType: 'text/plain' })
    );

    const result = await postJson('/login/bootstrap', { return_path: '/' });
    expect(result.data).toBeUndefined();
    expect(result.error).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('returns data when response is ok', async () => {
    fetchMock.mockResolvedValueOnce(buildResponse({ ok: true, json: { ok: true } }));

    const result = await postJson<{ ok: boolean }>('/login/bootstrap', {});
    expect(result.data).toEqual({ ok: true });
    expect(result.error).toBeUndefined();
  });

  it('returns error when response is not ok', async () => {
    fetchMock.mockResolvedValueOnce(
      buildResponse({ ok: false, json: { code: 'invalid', message: 'nope' } })
    );

    const result = await postJson('/login/bootstrap', {});
    expect(result.data).toBeUndefined();
    expect(result.error).toEqual({ code: 'invalid', message: 'nope' });
  });
});

describe('csrf client helpers', () => {
  beforeEach(() => {
    csrfClientMocks.getToken.mockReset();
    csrfClientMocks.csrfFetch.mockReset();
    csrfClientMocks.clear.mockReset();
  });

  it('getCsrfToken updates token path and fetches token', async () => {
    csrfClientMocks.getToken.mockResolvedValueOnce('csrf-token');

    const token = await getCsrfToken(config);
    expect(token).toBe('csrf-token');
    expect(csrfClientMocks.getToken).toHaveBeenCalledOnce();
    expect(csrfClientMocks.tokenPath()).toBe(config.csrfTokenPath);
  });

  it('csrfFetch updates token path and forwards request', async () => {
    const response = buildResponse({ ok: true, json: {} });
    csrfClientMocks.csrfFetch.mockResolvedValueOnce(response);

    const result = await csrfFetch(config, '/profile/update', { method: 'POST' });
    expect(result).toBe(response);
    expect(csrfClientMocks.csrfFetch).toHaveBeenCalledWith('/profile/update', {
      method: 'POST'
    });
    expect(csrfClientMocks.tokenPath()).toBe(config.csrfTokenPath);
  });

  it('clearCsrfCache clears the client cache', () => {
    clearCsrfCache();
    expect(csrfClientMocks.clear).toHaveBeenCalledOnce();
  });
});
