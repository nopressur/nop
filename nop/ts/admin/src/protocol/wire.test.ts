// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import {
  OptionMap,
  WireReader,
  WireWriter,
  WorkflowCounter,
  WorkflowTracker,
} from "./wire";

describe("wire", () => {
  it("roundtrips primitives and collections", () => {
    const writer = new WireWriter();
    writer.writeU8(7);
    writer.writeU16(500);
    writer.writeU32(42);
    writer.writeU64(123456);
    writer.writeI32(-12);
    writer.writeBool(true);
    writer.writeString("hi");
    writer.writeVec(["a", "b"], (w, value) => w.writeString(value));

    const bytes = writer.toUint8Array();
    const reader = new WireReader(bytes);
    expect(reader.readU8()).toBe(7);
    expect(reader.readU16()).toBe(500);
    expect(reader.readU32()).toBe(42);
    expect(reader.readU64Number()).toBe(123456);
    expect(reader.readI32()).toBe(-12);
    expect(reader.readBool()).toBe(true);
    expect(reader.readString()).toBe("hi");
    expect(reader.readVec((r) => r.readString())).toEqual(["a", "b"]);
    reader.ensureFullyConsumed();
  });

  it("roundtrips option maps", () => {
    const writer = new WireWriter();
    OptionMap.write(writer, [true, false, true]);
    const bytes = writer.toUint8Array();
    const reader = new WireReader(bytes);
    expect(OptionMap.read(reader, 3)).toEqual([true, false, true]);
  });

  it("rejects option maps with unknown bits", () => {
    const writer = new WireWriter();
    writer.writeU8(0b0000_0100);
    const reader = new WireReader(writer.toUint8Array());
    expect(() => OptionMap.read(reader, 2)).toThrow("unknown bits");
  });

  it("enforces monotonic workflow IDs", () => {
    const tracker = new WorkflowTracker();
    expect(() => tracker.accept(0)).toThrow("non-zero");
    tracker.accept(1);
    expect(() => tracker.accept(1)).toThrow("strictly increasing");
  });

  it("increments workflow counters", () => {
    const counter = new WorkflowCounter();
    expect(counter.next()).toBe(1);
    expect(counter.next()).toBe(2);
  });
});
