// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAdminRuntimeConfig, setAdminRuntimeConfig } from "../config/runtime";
import {
  FRAME_ACK,
  FRAME_ERROR,
  FRAME_REQUEST,
  FRAME_RESPONSE,
  FRAME_STREAM_CHUNK,
  STREAM_FLAG_COMPRESSED,
  STREAM_FLAG_FINAL,
} from "../protocol/ws-protocol";
import type { WsFrame } from "../protocol/ws-protocol";

const mocks = vi.hoisted(() => ({
  lastConnectArgs: null as
    | null
    | { url: string; ticket: string; csrfToken: string },
  frameHandler: null as null | ((frame: WsFrame) => void),
  sentFrames: [] as WsFrame[],
  nextTimeoutId: 1,
  timeouts: new Map<number, { fn: () => void; ms: number }>(),
}));

vi.mock("./ws-coordinator", () => {
  class WsCoordinator {
    connect = vi.fn(async (url: string, ticket: string, csrfToken: string) => {
      mocks.lastConnectArgs = { url, ticket, csrfToken };
      mocks.frameHandler?.({ frameType: 1, message: "ok" });
    });

    onFrame(handler: (frame: WsFrame) => void): void {
      mocks.frameHandler = handler;
    }

    onClose(): void {}

    onError(): void {}

    send = vi.fn((frame: WsFrame) => {
      mocks.sentFrames.push(frame);
    });
  }

  return { WsCoordinator };
});

vi.mock("../services/browser", () => ({
  getLocationOrigin: () => "http://localhost",
  setBrowserTimeout: (fn: () => void, ms: number) => {
    const id = mocks.nextTimeoutId++;
    mocks.timeouts.set(id, { fn, ms });
    return id;
  },
  clearBrowserTimeout: (id: number) => {
    mocks.timeouts.delete(id);
  },
}));

describe("AdminWsClient", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    mocks.lastConnectArgs = null;
    mocks.frameHandler = null;
    mocks.sentFrames = [];
    mocks.nextTimeoutId = 1;
    mocks.timeouts.clear();
    originalFetch = globalThis.fetch;
    setAdminRuntimeConfig({
      adminPath: "/admin",
      appName: "Admin",
      csrfTokenPath: "/admin/csrf-token-api",
      version: "1.2.3",
      wsPath: "/admin/ws",
      wsTicketPath: "/admin/ws-ticket",
      userManagementEnabled: true,
      passwordFrontEnd: {
        memoryKib: 1,
        iterations: 1,
        parallelism: 1,
        outputLen: 1,
        saltLen: 1,
      },
      passwordComplexityEnabled: true,
    });
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    const { clearCsrfToken } = await import("./csrf");
    clearCsrfToken();
    clearAdminRuntimeConfig();
    vi.restoreAllMocks();
  });

  it("retries ticket fetch on expired CSRF token and uses refreshed token for WS auth", async () => {
    const tokens = ["token-1", "token-2"];
    let tokenIndex = 0;
    let ticketCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;

      if (url === "/admin/csrf-token-api") {
        const token = tokens[tokenIndex++];
        return new Response(
          JSON.stringify({ csrf_token: token, expires_in_seconds: 3600 }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
            },
          },
        );
      }

      if (url === "/admin/ws-ticket") {
        const headers = new Headers(init?.headers ?? {});
        const csrfToken = headers.get("X-CSRF-Token");
        ticketCalls += 1;
        if (ticketCalls === 1) {
          expect(csrfToken).toBe("token-1");
          return new Response(null, { status: 403 });
        }
        expect(csrfToken).toBe("token-2");
        return new Response(JSON.stringify({ ticket: "ticket-123" }), {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    });

    globalThis.fetch = fetchMock as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    await client.connect();

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(ticketCalls).toBe(2);
    expect(tokenIndex).toBe(2);
    expect(mocks.lastConnectArgs).toEqual({
      url: "ws://localhost/admin/ws",
      ticket: "ticket-123",
      csrfToken: "token-2",
    });
  });

  it("assembles registered streamed responses and acks known chunks", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 0x80000000, chunkBytes: 3, sizeBytes: 5 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array([9]),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 0x80000000,
      seq: 0,
      flags: 0,
      payload: new Uint8Array([1, 2, 3]),
    });
    expect(mocks.sentFrames[mocks.sentFrames.length - 1]).toEqual({
      frameType: FRAME_ACK,
      streamId: 0x80000000,
      seq: 0,
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 0x80000000,
      seq: 1,
      flags: STREAM_FLAG_FINAL,
      payload: new Uint8Array([4, 5]),
    });

    const result = await promise;
    expect(result.response).toMatchObject({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
    });
    expect(Array.from(result.streamBytes ?? [])).toEqual([1, 2, 3, 4, 5]);
    expect(mocks.sentFrames[mocks.sentFrames.length - 1]).toEqual({
      frameType: FRAME_ACK,
      streamId: 0x80000000,
      seq: 1,
    });
  });

  it("rejects streamed requests when metadata decoding fails", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(12, 2, new Uint8Array([1]), () => {
      throw new Error("bad content read payload");
    });

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array([9]),
    });

    await expect(promise).rejects.toThrow("bad content read payload");
    expect(mocks.timeouts.size).toBe(0);
  });

  it("does not ack unknown response stream chunks", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    await client.connect();
    const before = mocks.sentFrames.length;
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 99,
      seq: 0,
      flags: STREAM_FLAG_FINAL,
      payload: new Uint8Array([1]),
    });

    expect(mocks.sentFrames.slice(before)).toEqual([]);
  });

  it("preserves inline response behavior for stream-capable requests", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: null, chunkBytes: null, sizeBytes: null }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array([4, 5]),
    });

    await expect(promise).resolves.toEqual({
      response: {
        frameType: FRAME_RESPONSE,
        domainId: 12,
        actionId: 201,
        workflowId: 1,
        payload: new Uint8Array([4, 5]),
      },
      streamBytes: null,
    });
  });

  it("rejects active streamed responses on error frames", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 7, chunkBytes: 4, sizeBytes: 4 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    mocks.frameHandler?.({
      frameType: FRAME_ERROR,
      message: "stream failed",
    });

    await expect(promise).rejects.toThrow("stream failed");
  });

  it("rejects streamed responses when the stream response timeout fires", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 9, chunkBytes: 4, sizeBytes: 4 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });

    const streamTimeout = [...mocks.timeouts.values()].find(
      (timeout) => timeout.ms === 30000,
    );
    expect(streamTimeout).toBeDefined();
    streamTimeout?.fn();

    await expect(promise).rejects.toThrow("Stream response timed out");
  });

  it("treats stream response timeout as an idle timeout", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 10, chunkBytes: 4, sizeBytes: 5 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    const firstTimeout = [...mocks.timeouts.entries()].find(
      ([, timeout]) => timeout.ms === 30000,
    );
    expect(firstTimeout).toBeDefined();

    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 10,
      seq: 0,
      flags: 0,
      payload: new Uint8Array([1, 2]),
    });
    expect(mocks.timeouts.has(firstTimeout?.[0] ?? -1)).toBe(false);

    const secondTimeout = [...mocks.timeouts.values()].find(
      (timeout) => timeout.ms === 30000,
    );
    expect(secondTimeout).toBeDefined();
    secondTimeout?.fn();

    await expect(promise).rejects.toThrow("Stream response timed out");
  });

  it("accepts empty streamed responses", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 11, chunkBytes: 4, sizeBytes: 0 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 11,
      seq: 0,
      flags: STREAM_FLAG_FINAL,
      payload: new Uint8Array(),
    });

    const result = await promise;
    expect(Array.from(result.streamBytes ?? [1])).toEqual([]);
    expect(mocks.sentFrames[mocks.sentFrames.length - 1]).toEqual({
      frameType: FRAME_ACK,
      streamId: 11,
      seq: 0,
    });
  });

  it("accepts short non-final streamed response chunks", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 12, chunkBytes: 4, sizeBytes: 3 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 12,
      seq: 0,
      flags: 0,
      payload: new Uint8Array([1]),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 12,
      seq: 1,
      flags: STREAM_FLAG_FINAL,
      payload: new Uint8Array([2, 3]),
    });

    const result = await promise;
    expect(Array.from(result.streamBytes ?? [])).toEqual([1, 2, 3]);
  });

  it("rejects streamed responses with size mismatches", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 7, chunkBytes: 4, sizeBytes: 3 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 7,
      seq: 0,
      flags: STREAM_FLAG_FINAL,
      payload: new Uint8Array([1, 2]),
    });

    await expect(promise).rejects.toThrow("size mismatch");
    expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_ACK)).toBe(false);
  });

  it("rejects compressed streamed response chunks without acking them", async () => {
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (url === "/admin/csrf-token-api") {
        return new Response(JSON.stringify({ csrf_token: "csrf" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "/admin/ws-ticket") {
        return new Response(JSON.stringify({ ticket: "ticket" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    }) as typeof fetch;

    vi.resetModules();
    const { AdminWsClient } = await import("./wsClient");
    const client = new AdminWsClient("/admin/ws", "/admin/ws-ticket");
    const promise = client.requestWithStream(
      12,
      2,
      new Uint8Array([1]),
      () => ({ streamId: 8, chunkBytes: 4, sizeBytes: 1 }),
    );

    await vi.waitFor(() => {
      expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_REQUEST)).toBe(true);
    });
    mocks.frameHandler?.({
      frameType: FRAME_RESPONSE,
      domainId: 12,
      actionId: 201,
      workflowId: 1,
      payload: new Uint8Array(),
    });
    mocks.frameHandler?.({
      frameType: FRAME_STREAM_CHUNK,
      streamId: 8,
      seq: 0,
      flags: STREAM_FLAG_COMPRESSED | STREAM_FLAG_FINAL,
      payload: new Uint8Array([1]),
    });

    await expect(promise).rejects.toThrow("Compressed response streams");
    expect(mocks.sentFrames.some((frame) => frame.frameType === FRAME_ACK)).toBe(false);
  });
});
