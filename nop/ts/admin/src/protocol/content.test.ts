// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { OptionMap, WireWriter } from "./wire";
import { decodeContentListResponse, decodeContentReadResponse } from "./content";

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

describe("content protocol decode", () => {
  it("decodes content list response with camelCase fields", () => {
    const writer = new WireWriter();
    writer.writeU32(2);
    writer.writeU32(1);
    writer.writeU32(25);
    writer.writeVec([0], (itemWriter) => {
      OptionMap.write(itemWriter, [true, true, true, true, true]);
      itemWriter.writeString("id-1");
      itemWriter.writeString("docs/intro");
      itemWriter.writeString("Intro");
      itemWriter.writeString("text/markdown");
      writeStringVec(itemWriter, ["docs", "intro"]);
      itemWriter.writeString("Docs");
      itemWriter.writeString("parent-id");
      itemWriter.writeI32(3);
      itemWriter.writeString("intro.md");
      itemWriter.writeBool(true);
    });

    const decoded = decodeContentListResponse(writer.toUint8Array());
    expect(decoded.pageSize).toBe(25);
    expect(decoded.items).toHaveLength(1);
    expect(decoded.items[0].navTitle).toBe("Docs");
    expect(decoded.items[0].navParentId).toBe("parent-id");
    expect(decoded.items[0].navOrder).toBe(3);
    expect(decoded.items[0].originalFilename).toBe("intro.md");
    expect(decoded.items[0].isMarkdown).toBe(true);
  });

  it("decodes content read response with camelCase fields", () => {
    const writer = new WireWriter();
    OptionMap.write(writer, [true, true, true, true, true, true, true]);
    writer.writeString("id-2");
    writer.writeString("docs/setup");
    writer.writeString("Setup");
    writer.writeString("text/markdown");
    writeStringVec(writer, ["docs"]);
    writer.writeString("Setup Nav");
    writer.writeString("nav-parent");
    writer.writeI32(2);
    writer.writeString("setup.md");
    writer.writeString("default");
    writer.writeString("# Setup\n");

    const decoded = decodeContentReadResponse(writer.toUint8Array());
    expect(decoded.navTitle).toBe("Setup Nav");
    expect(decoded.navParentId).toBe("nav-parent");
    expect(decoded.navOrder).toBe(2);
    expect(decoded.originalFilename).toBe("setup.md");
    expect(decoded.theme).toBe("default");
    expect(decoded.content).toBe("# Setup\n");
  });
});
