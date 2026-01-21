// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { ResponseFrame } from "../protocol/ws-protocol";

type MessagePayload = { message: string };

export function handleResponse<T>(params: {
  response: ResponseFrame;
  domainId: number;
  okActionId: number;
  errActionId: number;
  okDecoder: (payload: Uint8Array) => T;
  errDecoder: (payload: Uint8Array) => MessagePayload;
  domainLabel: string;
  actionLabel?: string;
}): T {
  const { response } = params;
  const actionLabel = params.actionLabel ?? params.domainLabel;

  if (response.domainId !== params.domainId) {
    throw new Error(`Unexpected ${params.domainLabel} response domain`);
  }
  if (response.actionId === params.okActionId) {
    return params.okDecoder(response.payload);
  }
  if (response.actionId === params.errActionId) {
    const message = params.errDecoder(response.payload);
    throw new Error(message.message);
  }
  throw new Error(`Unexpected ${actionLabel} response`);
}
