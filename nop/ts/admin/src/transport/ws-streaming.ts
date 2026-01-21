// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  FRAME_STREAM_CHUNK,
  STREAM_FLAG_COMPRESSED,
  STREAM_FLAG_FINAL,
  WS_MAX_STREAM_CHUNK_BYTES,
} from "../protocol/ws-protocol";
import type { StreamChunkFrame } from "../protocol/ws-protocol";

export type CompressionDecision = "skip" | "prefer";

export interface PreparedStream {
  payload: Uint8Array;
  isCompressed: boolean;
}

export function prepareStreamPayload(
  payload: Uint8Array,
  decision: CompressionDecision,
): PreparedStream {
  if (decision === "skip") {
    return { payload, isCompressed: false };
  }
  return { payload, isCompressed: false };
}

export function chunkPayload(
  streamId: number,
  prepared: PreparedStream,
  chunkSize = WS_MAX_STREAM_CHUNK_BYTES,
): StreamChunkFrame[] {
  if (chunkSize <= 0) {
    throw new Error("chunkSize must be positive");
  }
  const chunks: StreamChunkFrame[] = [];
  let seq = 0;
  for (let offset = 0; offset < prepared.payload.length; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, prepared.payload.length);
    let flags = 0;
    if (end === prepared.payload.length) {
      flags |= STREAM_FLAG_FINAL;
    }
    if (prepared.isCompressed) {
      flags |= STREAM_FLAG_COMPRESSED;
    }
    chunks.push({
      frameType: FRAME_STREAM_CHUNK,
      streamId,
      seq,
      flags,
      payload: prepared.payload.slice(offset, end),
    });
    seq += 1;
  }
  return chunks;
}
