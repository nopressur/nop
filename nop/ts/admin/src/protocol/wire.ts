// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WireError";
  }
}

export interface WireEncode {
  encode(writer: WireWriter): void;
}

export interface WireDecode<T> {
  decode(reader: WireReader): T;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8");

export class WireWriter {
  private chunks: Uint8Array[] = [];
  private length = 0;

  writeU8(value: number): void {
    const buf = new Uint8Array(1);
    buf[0] = value & 0xff;
    this.push(buf);
  }

  writeU16(value: number): void {
    const buf = new Uint8Array(2);
    const view = new DataView(buf.buffer);
    view.setUint16(0, value & 0xffff, true);
    this.push(buf);
  }

  writeU32(value: number): void {
    const buf = new Uint8Array(4);
    const view = new DataView(buf.buffer);
    view.setUint32(0, value >>> 0, true);
    this.push(buf);
  }

  writeU64(value: number | bigint): void {
    const big = this.toU64(value);
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    const low = Number(big & 0xffff_ffffn);
    const high = Number((big >> 32n) & 0xffff_ffffn);
    view.setUint32(0, low >>> 0, true);
    view.setUint32(4, high >>> 0, true);
    this.push(buf);
  }

  writeI32(value: number): void {
    const buf = new Uint8Array(4);
    const view = new DataView(buf.buffer);
    view.setInt32(0, value | 0, true);
    this.push(buf);
  }

  writeBool(value: boolean): void {
    this.writeU8(value ? 1 : 0);
  }

  writeBytes(bytes: Uint8Array): void {
    this.writeU32(bytes.length);
    this.push(bytes);
  }

  writeString(value: string): void {
    const bytes = textEncoder.encode(value);
    this.writeBytes(bytes);
  }

  writeVec<T>(values: readonly T[], writeItem: (writer: WireWriter, value: T) => void): void {
    if (values.length > 0xffff_ffff) {
      throw new WireError("Vector length exceeds u32 limit");
    }
    this.writeU32(values.length);
    for (const value of values) {
      writeItem(this, value);
    }
  }

  toUint8Array(): Uint8Array {
    const result = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  private push(bytes: Uint8Array): void {
    if (bytes.length === 0) {
      return;
    }
    this.chunks.push(bytes);
    this.length += bytes.length;
  }

  private toU64(value: number | bigint): bigint {
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new WireError("Invalid u64 number value");
      }
      return BigInt(value);
    }
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
      throw new WireError("Invalid u64 bigint value");
    }
    return value;
  }
}

export class WireReader {
  private view: DataView;
  private offset = 0;

  constructor(private bytes: Uint8Array) {
    this.view = new DataView(
      bytes.buffer,
      bytes.byteOffset,
      bytes.byteLength,
    );
  }

  readU8(): number {
    this.ensureAvailable(1);
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  readU16(): number {
    this.ensureAvailable(2);
    const value = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return value;
  }

  readU32(): number {
    this.ensureAvailable(4);
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  readU64(): bigint {
    this.ensureAvailable(8);
    const low = BigInt(this.view.getUint32(this.offset, true));
    const high = BigInt(this.view.getUint32(this.offset + 4, true));
    this.offset += 8;
    return (high << 32n) | low;
  }

  readU64Number(): number {
    const value = this.readU64();
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new WireError("Decoded u64 exceeds safe integer range");
    }
    return Number(value);
  }

  readI32(): number {
    this.ensureAvailable(4);
    const value = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return value;
  }

  readBool(): boolean {
    const value = this.readU8();
    if (value === 0) {
      return false;
    }
    if (value === 1) {
      return true;
    }
    throw new WireError("Invalid boolean value");
  }

  readBytes(): Uint8Array {
    const length = this.readU32();
    this.ensureAvailable(length);
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  readString(): string {
    const bytes = this.readBytes();
    return textDecoder.decode(bytes);
  }

  readVec<T>(readItem: (reader: WireReader) => T): T[] {
    const length = this.readU32();
    const values: T[] = [];
    for (let i = 0; i < length; i += 1) {
      values.push(readItem(this));
    }
    return values;
  }

  ensureFullyConsumed(): void {
    if (this.offset !== this.bytes.length) {
      throw new WireError("Trailing bytes after decode");
    }
  }

  private ensureAvailable(length: number): void {
    if (this.offset + length > this.bytes.length) {
      throw new WireError("Unexpected end of buffer");
    }
  }
}

type OptionWidth = "u8" | "u16" | "u32" | "u64";

function optionWidthForCount(count: number): OptionWidth {
  if (count <= 0) {
    throw new WireError("Option map requires at least one field");
  }
  if (count <= 8) {
    return "u8";
  }
  if (count <= 16) {
    return "u16";
  }
  if (count <= 32) {
    return "u32";
  }
  if (count <= 64) {
    return "u64";
  }
  throw new WireError("Option map exceeds 64 fields");
}

export class OptionMap {
  static write(writer: WireWriter, flags: readonly boolean[]): void {
    const width = optionWidthForCount(flags.length);
    let value = 0n;
    flags.forEach((enabled, index) => {
      if (enabled) {
        value |= 1n << BigInt(index);
      }
    });
    switch (width) {
      case "u8":
        writer.writeU8(Number(value));
        break;
      case "u16":
        writer.writeU16(Number(value));
        break;
      case "u32":
        writer.writeU32(Number(value));
        break;
      case "u64":
        writer.writeU64(value);
        break;
      default:
        throw new WireError("Unsupported option map width");
    }
  }

  static read(reader: WireReader, count: number): boolean[] {
    if (count === 0) {
      return [];
    }
    const width = optionWidthForCount(count);
    let value: bigint;
    switch (width) {
      case "u8":
        value = BigInt(reader.readU8());
        break;
      case "u16":
        value = BigInt(reader.readU16());
        break;
      case "u32":
        value = BigInt(reader.readU32());
        break;
      case "u64":
        value = reader.readU64();
        break;
      default:
        throw new WireError("Unsupported option map width");
    }

    const mask =
      count === 64 ? (1n << 64n) - 1n : (1n << BigInt(count)) - 1n;
    if ((value & ~mask) !== 0n) {
      throw new WireError("Option map contains unknown bits");
    }

    const flags: boolean[] = [];
    for (let index = 0; index < count; index += 1) {
      flags.push(((value >> BigInt(index)) & 1n) === 1n);
    }
    return flags;
  }
}

export class WorkflowCounter {
  private nextId = 1;

  next(): number {
    if (this.nextId === 0) {
      throw new WireError("Workflow counter wrapped");
    }
    if (this.nextId === 0xffff_ffff) {
      throw new WireError("Workflow counter exhausted");
    }
    const id = this.nextId;
    this.nextId += 1;
    return id;
  }
}

export class WorkflowTracker {
  private lastId = 0;

  accept(workflowId: number): void {
    if (workflowId === 0) {
      throw new WireError("Workflow ID must be non-zero");
    }
    if (workflowId <= this.lastId) {
      throw new WireError("Workflow ID must be strictly increasing");
    }
    this.lastId = workflowId;
  }
}
