// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub mod protocol;
pub mod streaming;

pub use protocol::{
    AuthFrame, AuthResponseFrame, ErrorFrame, RequestFrame, ResponseFrame, STREAM_FLAG_COMPRESSED,
    STREAM_FLAG_FINAL, StreamAckFrame, StreamChunkFrame, WS_MAX_MESSAGE_BYTES,
    WS_MAX_STREAM_CHUNK_BYTES, WsFrame, WsProtocolError, WsProtocolErrorKind, decode_frame,
    encode_frame,
};
pub use streaming::{
    CompressionDecision, PreparedStream, StreamAssembler, StreamError, StreamErrorKind,
    StreamState, StreamTracker, chunk_payload, prepare_stream_payload, should_compress_for_mime,
};
