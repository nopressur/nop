// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  SETTINGS_ACTION_GET,
  SETTINGS_ACTION_GET_ERR,
  SETTINGS_ACTION_GET_OK,
  SETTINGS_ACTION_SET_TITLE,
  SETTINGS_ACTION_SET_TITLE_ERR,
  SETTINGS_ACTION_SET_TITLE_OK,
  SETTINGS_DOMAIN_ID,
  encodeSettingsSetTitleRequest,
} from "../protocol/settings";
import type { ResponseFrame } from "../protocol/ws-protocol";
import { OptionMap, WireWriter } from "../protocol/wire";

const wsMocks = vi.hoisted(() => ({
  request: vi.fn(),
}));

vi.mock("../transport/wsClient", () => ({
  getAdminWsClient: () => ({
    request: wsMocks.request,
  }),
}));

describe("settings service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("fetches settings through the Settings domain", async () => {
    wsMocks.request.mockResolvedValue(
      responseFrame(SETTINGS_ACTION_GET_OK, settingsPayload("Example Site")),
    );

    const { fetchSettings } = await import("./settings");
    const response = await fetchSettings();

    expect(wsMocks.request).toHaveBeenCalledWith(
      SETTINGS_DOMAIN_ID,
      SETTINGS_ACTION_GET,
      new Uint8Array(0),
    );
    expect(response.title).toBe("Example Site");
  });

  it("updates website title and decodes the response", async () => {
    wsMocks.request.mockResolvedValue(
      responseFrame(SETTINGS_ACTION_SET_TITLE_OK, settingsPayload(null)),
    );

    const { updateWebsiteTitle } = await import("./settings");
    const response = await updateWebsiteTitle(null);

    expect(wsMocks.request).toHaveBeenCalledWith(
      SETTINGS_DOMAIN_ID,
      SETTINGS_ACTION_SET_TITLE,
      encodeSettingsSetTitleRequest({ title: null }),
    );
    expect(response.title).toBeNull();
  });

  it("throws settings error messages", async () => {
    wsMocks.request.mockResolvedValue(
      responseFrame(
        SETTINGS_ACTION_SET_TITLE_ERR,
        messagePayload("invalid website title"),
      ),
    );

    const { updateWebsiteTitle } = await import("./settings");
    await expect(updateWebsiteTitle("bad")).rejects.toThrow("invalid website title");
  });

  it("throws on unexpected settings response actions", async () => {
    wsMocks.request.mockResolvedValue(
      responseFrame(SETTINGS_ACTION_GET_ERR + 99, new Uint8Array(0)),
    );

    const { fetchSettings } = await import("./settings");
    await expect(fetchSettings()).rejects.toThrow("Unexpected settings response");
  });
});

function responseFrame(actionId: number, payload: Uint8Array): ResponseFrame {
  return {
    frameType: 4,
    domainId: SETTINGS_DOMAIN_ID,
    actionId,
    workflowId: 1,
    payload,
  };
}

function settingsPayload(websiteTitle: string | null): Uint8Array {
  const writer = new WireWriter();
  writer.writeString("Example");
  OptionMap.write(writer, [websiteTitle !== null, false]);
  if (websiteTitle !== null) {
    writer.writeString(websiteTitle);
  }
  return writer.toUint8Array();
}

function messagePayload(message: string): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(message);
  return writer.toUint8Array();
}
