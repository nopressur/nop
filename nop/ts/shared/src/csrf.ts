// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface CsrfTokenResponse {
  csrf_token?: string;
  expires_in_seconds?: number;
}

export interface CsrfClientOptions {
  tokenPath: () => string;
  fetchImpl?: FetchLike;
  defaultTtlSeconds?: number;
  refreshBufferSeconds?: number;
  onRetry?: () => void;
}

const DEFAULT_TTL_SECONDS = 60 * 60;
const DEFAULT_REFRESH_BUFFER_SECONDS = 5 * 60;

export function createCsrfClient(options: CsrfClientOptions) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const defaultTtlSeconds = options.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
  const refreshBufferSeconds =
    options.refreshBufferSeconds ?? DEFAULT_REFRESH_BUFFER_SECONDS;

  let csrfTokenCache: string | null = null;
  let csrfTokenExpiry = 0;

  async function fetchToken(): Promise<string> {
    const response = await fetchImpl(options.tokenPath(), {
      method: 'POST',
      credentials: 'same-origin'
    });

    if (!response.ok) {
      throw new Error(`Failed to get CSRF token: ${response.status}`);
    }

    const data = (await response.json()) as CsrfTokenResponse;
    if (!data.csrf_token) {
      throw new Error('CSRF token missing from response');
    }

    const ttlSeconds = data.expires_in_seconds ?? defaultTtlSeconds;
    csrfTokenCache = data.csrf_token;
    csrfTokenExpiry = Date.now() + ttlSeconds * 1000;

    return csrfTokenCache;
  }

  async function getToken(): Promise<string> {
    const now = Date.now();
    const refreshBufferMs = refreshBufferSeconds * 1000;
    if (csrfTokenCache && now < csrfTokenExpiry - refreshBufferMs) {
      return csrfTokenCache;
    }
    return fetchToken();
  }

  function clear(): void {
    csrfTokenCache = null;
    csrfTokenExpiry = 0;
  }

  async function csrfFetch(
    input: RequestInfo | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    const method = (init.method ?? 'GET').toUpperCase();

    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return fetchImpl(input, {
        credentials: init.credentials ?? 'same-origin',
        ...init
      });
    }

    const headers = new Headers(init.headers ?? {});
    headers.set('X-CSRF-Token', await getToken());

    const response = await fetchImpl(input, {
      credentials: init.credentials ?? 'same-origin',
      ...init,
      headers
    });

    if (response.status !== 403) {
      return response;
    }

    clear();
    if (options.onRetry) {
      options.onRetry();
    }
    headers.set('X-CSRF-Token', await getToken());

    return fetchImpl(input, {
      credentials: init.credentials ?? 'same-origin',
      ...init,
      headers
    });
  }

  return {
    getToken,
    clear,
    csrfFetch
  };
}
