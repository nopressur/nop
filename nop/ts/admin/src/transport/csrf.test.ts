// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it, vi } from 'vitest';
import { createCsrfClient } from '../../../shared/src/csrf';

describe('csrf client', () => {
  it('retries on 403 with a refreshed token', async () => {
    const tokenPath = '/login/csrf-token-api';
    const tokens = ['token-1', 'token-2'];
    let tokenIndex = 0;
    let apiCalls = 0;
    const onRetry = vi.fn();

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (input === tokenPath) {
        const token = tokens[tokenIndex++];
        return new Response(
          JSON.stringify({ csrf_token: token, expires_in_seconds: 60 }),
          {
            status: 200,
            headers: {
              'content-type': 'application/json'
            }
          }
        );
      }

      const headers = new Headers(init?.headers ?? {});
      const csrfToken = headers.get('X-CSRF-Token');
      apiCalls += 1;
      if (apiCalls === 1) {
        expect(csrfToken).toBe('token-1');
        return new Response(null, { status: 403 });
      }
      expect(csrfToken).toBe('token-2');
      return new Response(null, { status: 200 });
    });

    const client = createCsrfClient({
      tokenPath: () => tokenPath,
      fetchImpl,
      refreshBufferSeconds: 0,
      onRetry
    });

    const response = await client.csrfFetch('/profile/update', { method: 'POST' });
    expect(response.status).toBe(200);
    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(tokenIndex).toBe(2);
  });
});
