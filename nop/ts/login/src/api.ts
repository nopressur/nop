// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { createCsrfClient } from '../../shared/src/csrf';
import type { LoginErrorResponse, LoginRuntimeConfig } from './types';

let csrfTokenPath = '';
const csrfClient = createCsrfClient({
  tokenPath: () => csrfTokenPath
});

export async function postJson<T>(
  url: string,
  payload: unknown,
  init: RequestInit = {}
): Promise<{ response: Response; data?: T; error?: LoginErrorResponse }>
{
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers ?? {})
    },
    body: JSON.stringify(payload),
    ...init
  });

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return { response };
  }

  const data = (await response.json()) as T | LoginErrorResponse;
  if (response.ok) {
    return { response, data: data as T };
  }
  return { response, error: data as LoginErrorResponse };
}

export async function getCsrfToken(config: LoginRuntimeConfig): Promise<string> {
  csrfTokenPath = config.csrfTokenPath;
  return csrfClient.getToken();
}

export async function csrfFetch(
  config: LoginRuntimeConfig,
  input: RequestInfo,
  init: RequestInit = {}
): Promise<Response> {
  csrfTokenPath = config.csrfTokenPath;
  return csrfClient.csrfFetch(input, init);
}

export function clearCsrfCache() {
  csrfClient.clear();
}
