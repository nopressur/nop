// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { csrfFetch } from "./csrf";

export class RestError extends Error {
  constructor(
    message: string,
    public status: number,
    public response?: Response,
  ) {
    super(message);
    this.name = "RestError";
  }
}

export async function restRequest(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<Response> {
  const response = await csrfFetch(input, init);
  if (!response.ok) {
    throw new RestError(`Request failed (${response.status})`, response.status, response);
  }
  return response;
}

export async function restJson<T>(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<T> {
  const response = await restRequest(input, init);
  return (await response.json()) as T;
}
