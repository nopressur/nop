// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export type VectorEntry = {
  name: string;
  direction: "request" | "response";
  domain_id: number;
  action_id: number;
  payload: unknown;
  hex: string;
};

type VectorFile = {
  version: number;
  entries: VectorEntry[];
};

export function loadVectorEntries(): VectorEntry[] {
  const filePath = resolve(
    process.cwd(),
    "../../tests/fixtures/management-wire-vectors.json",
  );
  const data = readFileSync(filePath, "utf-8");
  const parsed = JSON.parse(data) as VectorFile;
  return parsed.entries;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) {
    return new Uint8Array(0);
  }
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function assertRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function parseU64(value: unknown, label: string): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a safe u64 number`);
    }
    return value;
  }
  if (typeof value === "string") {
    const parsed = BigInt(value);
    if (parsed < 0n) {
      throw new Error(`${label} must be a positive u64 string`);
    }
    if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${label} exceeds max safe integer`);
    }
    return Number(parsed);
  }
  throw new Error(`${label} must be a u64 number or string`);
}

export function parseBytes(value: unknown, label: string): Uint8Array {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  const bytes = value.map((item) => {
    if (typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255) {
      throw new Error(`${label} must contain byte values`);
    }
    return item;
  });
  return Uint8Array.from(bytes);
}

export function parseNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${label} must be a number`);
  }
  return value;
}

export function parseString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

export function parseBool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${label} must be a boolean`);
  }
  return value;
}

export function parseStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item, index) => {
    if (typeof item !== "string") {
      throw new Error(`${label}[${index}] must be a string`);
    }
    return item;
  });
}

export function parseOptionalString(value: unknown, label: string): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  return parseString(value, label);
}

export function parseOptionalStringArray(value: unknown, label: string): string[] | null {
  if (value === null || value === undefined) {
    return null;
  }
  return parseStringArray(value, label);
}

export function parseOptionalNumber(value: unknown, label: string): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  return parseNumber(value, label);
}

export function parseOptionalBool(value: unknown, label: string): boolean | null {
  if (value === null || value === undefined) {
    return null;
  }
  return parseBool(value, label);
}
