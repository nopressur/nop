// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAdminRuntimeConfig, setAdminRuntimeConfig } from "../config/runtime";

const mocks = vi.hoisted(() => ({
  lastConnectArgs: null as
    | null
    | { url: string; ticket: string; csrfToken: string },
  frameHandler: null as null | ((frame: { frameType: number; message: string }) => void),
}));

vi.mock("./ws-coordinator", () => {
  class WsCoordinator {
    connect = vi.fn(async (url: string, ticket: string, csrfToken: string) => {
      mocks.lastConnectArgs = { url, ticket, csrfToken };
      mocks.frameHandler?.({ frameType: 1, message: "ok" });
    });

    onFrame(handler: (frame: { frameType: number; message: string }) => void): void {
      mocks.frameHandler = handler;
    }

    onClose(): void {}

    onError(): void {}

    send = vi.fn();
  }

  return { WsCoordinator };
});

vi.mock("../services/browser", () => ({
  getLocationOrigin: () => "http://localhost",
  setBrowserTimeout: (_fn: () => void, _ms: number) => 0,
  clearBrowserTimeout: (_id: number) => {},
}));

describe("AdminWsClient", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    mocks.lastConnectArgs = null;
    mocks.frameHandler = null;
    originalFetch = globalThis.fetch;
    setAdminRuntimeConfig({
      adminPath: "/admin",
      appName: "Admin",
      csrfTokenPath: "/admin/csrf-token-api",
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
});
