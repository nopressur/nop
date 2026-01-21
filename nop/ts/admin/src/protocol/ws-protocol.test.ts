// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import {
  FRAME_AUTH,
  FRAME_REQUEST,
  decodeFrame,
  encodeFrame,
  WS_MAX_MESSAGE_BYTES,
} from "./ws-protocol";

describe("ws-protocol", () => {
  it("encodes and decodes auth frames", () => {
    const frame = {
      frameType: FRAME_AUTH,
      ticket: "ticket-123",
      csrfToken: "csrf-abc",
    } as const;
    const encoded = encodeFrame(frame);
    const decoded = decodeFrame(encoded);
    expect(decoded).toEqual(frame);
  });

  it("encodes and decodes request frames", () => {
    const payload = new Uint8Array([1, 2, 3]);
    const frame = {
      frameType: FRAME_REQUEST,
      domainId: 12,
      actionId: 3,
      workflowId: 1,
      payload,
    } as const;
    const encoded = encodeFrame(frame);
    const decoded = decodeFrame(encoded);
    if (decoded.frameType !== FRAME_REQUEST) {
      throw new Error("Unexpected frame type");
    }
    expect(decoded.domainId).toBe(frame.domainId);
    expect(decoded.actionId).toBe(frame.actionId);
    expect(decoded.workflowId).toBe(frame.workflowId);
    expect(Array.from(decoded.payload)).toEqual(Array.from(payload));
  });

  it("rejects oversized frames", () => {
    const oversized = new Uint8Array(WS_MAX_MESSAGE_BYTES + 1);
    expect(() =>
      encodeFrame({
        frameType: FRAME_REQUEST,
        domainId: 1,
        actionId: 1,
        workflowId: 1,
        payload: oversized,
      })
    ).toThrow(/maximum size/);
  });

  it("rejects oversized incoming messages", () => {
    const oversized = new Uint8Array(WS_MAX_MESSAGE_BYTES + 1);
    expect(() => decodeFrame(oversized)).toThrow(/maximum size/);
  });
});
