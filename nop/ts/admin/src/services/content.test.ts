// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONTENT_ACTION_READ_OK,
  CONTENT_DOMAIN_ID,
} from "../protocol/content";
import { FRAME_RESPONSE, type ResponseFrame } from "../protocol/ws-protocol";
import { OptionMap, WireReader, WireWriter } from "../protocol/wire";
import { buildContentPublicPath, defaultAliasForFile, readContent } from "./content";

type StreamMetadataReader = (frame: ResponseFrame) => {
  streamId: number | null;
  chunkBytes: number | null;
  sizeBytes: number | null;
} | null;

const wsMocks = vi.hoisted(() => ({
  requestWithStream: vi.fn(),
}));

vi.mock("../transport/wsClient", () => ({
  getAdminWsClient: () => wsMocks,
}));

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

function encodeReadPayload(params: {
  content: string | null;
  streamId?: number | null;
  chunkBytes?: number | null;
  sizeBytes?: number | null;
}): Uint8Array {
  const writer = new WireWriter();
  OptionMap.write(writer, [
    true,
    false,
    false,
    false,
    false,
    false,
    params.content !== null,
    params.streamId !== null && params.streamId !== undefined,
    params.chunkBytes !== null && params.chunkBytes !== undefined,
    params.sizeBytes !== null && params.sizeBytes !== undefined,
  ]);
  writer.writeString("0000000000000001");
  writer.writeString("docs/setup");
  writer.writeString("Setup");
  writer.writeString("text/markdown");
  writeStringVec(writer, ["docs"]);
  writer.writeBool(false);
  writer.writeBool(false);
  writer.writeString("auto");
  if (params.content !== null) {
    writer.writeString(params.content);
  }
  if (params.streamId !== null && params.streamId !== undefined) {
    writer.writeU32(params.streamId);
  }
  if (params.chunkBytes !== null && params.chunkBytes !== undefined) {
    writer.writeU32(params.chunkBytes);
  }
  if (params.sizeBytes !== null && params.sizeBytes !== undefined) {
    writer.writeU64(params.sizeBytes);
  }
  return writer.toUint8Array();
}

function readResponse(payload: Uint8Array): ResponseFrame {
  return {
    frameType: FRAME_RESPONSE,
    domainId: CONTENT_DOMAIN_ID,
    actionId: CONTENT_ACTION_READ_OK,
    workflowId: 1,
    payload,
  };
}

function expectStreamContentRequest(payload: Uint8Array): void {
  const reader = new WireReader(payload);
  const flags = OptionMap.read(reader, 1);
  expect(reader.readString()).toBe("0000000000000001");
  expect(flags[0]).toBe(true);
  expect(reader.readBool()).toBe(true);
  reader.ensureFullyConsumed();
}

beforeEach(() => {
  wsMocks.requestWithStream.mockReset();
});

describe("buildContentPublicPath", () => {
  it("uses aliases before ID routes", () => {
    expect(buildContentPublicPath({ id: "abc123", alias: "docs/intro" })).toBe("/docs/intro");
  });

  it("maps the index alias to the public root", () => {
    expect(buildContentPublicPath({ id: "abc123", alias: "index" })).toBe("/");
  });

  it("falls back to the ID route when no alias exists", () => {
    expect(buildContentPublicPath({ id: "abc123", alias: "" })).toBe("/id/abc123");
  });
});

describe("defaultAliasForFile", () => {
  it("defaults web font uploads to fonts", () => {
    const file = new File(["font"], "Brand Display.woff2", { type: "font/woff2" });

    expect(defaultAliasForFile(file)).toBe("fonts/brand-display.woff2");
  });

  it("uses font extensions when the browser omits the MIME type", () => {
    const file = new File(["font"], "Brand Text.ttf", { type: "" });

    expect(defaultAliasForFile(file)).toBe("fonts/brand-text.ttf");
  });
});

describe("readContent", () => {
  it("requests stream-capable reads and preserves inline Markdown", async () => {
    const response = readResponse(encodeReadPayload({ content: "# Setup\n" }));
    wsMocks.requestWithStream.mockImplementation(
      async (
        _domain: number,
        _action: number,
        payload: Uint8Array,
        metadata: StreamMetadataReader,
      ) => {
        expectStreamContentRequest(payload);
        expect(metadata(response)).toEqual({
          streamId: null,
          chunkBytes: null,
          sizeBytes: null,
        });
        return { response, streamBytes: null };
      },
    );

    const result = await readContent("0000000000000001");

    expect(result.content).toBe("# Setup\n");
    expect(wsMocks.requestWithStream).toHaveBeenCalledTimes(1);
  });

  it("decodes streamed Markdown as UTF-8 and preserves CRLF", async () => {
    const markdown = "# Setup\r\n\nEuro: EUR -> €\r\n";
    const streamBytes = new TextEncoder().encode(markdown);
    const response = readResponse(
      encodeReadPayload({
        content: null,
        streamId: 0x8000_0001,
        chunkBytes: 1024,
        sizeBytes: streamBytes.byteLength,
      }),
    );
    wsMocks.requestWithStream.mockImplementation(
      async (
        _domain: number,
        _action: number,
        _payload: Uint8Array,
        metadata: StreamMetadataReader,
      ) => {
        expect(metadata(response)).toEqual({
          streamId: 0x8000_0001,
          chunkBytes: 1024,
          sizeBytes: streamBytes.byteLength,
        });
        return { response, streamBytes };
      },
    );

    const result = await readContent("0000000000000001");

    expect(result.content).toBe(markdown);
    expect(result.sizeBytes).toBe(streamBytes.byteLength);
  });

  it("rejects streamed Markdown that is not valid UTF-8", async () => {
    const response = readResponse(
      encodeReadPayload({
        content: null,
        streamId: 0x8000_0002,
        chunkBytes: 1024,
        sizeBytes: 2,
      }),
    );
    wsMocks.requestWithStream.mockResolvedValue({
      response,
      streamBytes: new Uint8Array([0xc3, 0x28]),
    });

    await expect(readContent("0000000000000001")).rejects.toThrow(
      "Streamed Markdown content is not valid UTF-8",
    );
  });
});
