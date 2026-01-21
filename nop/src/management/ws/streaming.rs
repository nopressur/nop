// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::ws::protocol::{
    STREAM_FLAG_COMPRESSED, STREAM_FLAG_FINAL, StreamChunkFrame, WS_MAX_STREAM_CHUNK_BYTES,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::{HashMap, VecDeque};
use std::io::Write;

const DEFAULT_CHUNK_BYTES: usize = WS_MAX_STREAM_CHUNK_BYTES;
const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDecision {
    Skip,
    Prefer,
}

#[derive(Debug, Clone)]
pub struct PreparedStream {
    pub payload: Vec<u8>,
    pub is_compressed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamErrorKind {
    EmptyPayload,
    ChunkTooSmall,
    ChunkTooLarge,
    CompressionFailed,
    AckMismatch,
    OutOfOrder,
    StreamTooLarge,
    UnknownStream,
}

#[derive(Debug, Clone)]
pub struct StreamError {
    kind: StreamErrorKind,
    message: String,
}

impl StreamError {
    pub fn new(kind: StreamErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> StreamErrorKind {
        self.kind
    }
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stream error: {}", self.message)
    }
}

impl std::error::Error for StreamError {}

pub fn should_compress_for_mime(mime: &str) -> bool {
    let mime = mime.to_ascii_lowercase();
    !(mime.starts_with("image/") || mime.starts_with("audio/") || mime.starts_with("video/"))
}

pub fn prepare_stream_payload(
    payload: &[u8],
    decision: CompressionDecision,
) -> Result<PreparedStream, StreamError> {
    if payload.is_empty() {
        return Err(StreamError::new(
            StreamErrorKind::EmptyPayload,
            "Cannot stream empty payload",
        ));
    }

    if matches!(decision, CompressionDecision::Skip) {
        return Ok(PreparedStream {
            payload: payload.to_vec(),
            is_compressed: false,
        });
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .map_err(|err| StreamError::new(StreamErrorKind::CompressionFailed, err.to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|err| StreamError::new(StreamErrorKind::CompressionFailed, err.to_string()))?;

    if compressed.len() < payload.len() {
        Ok(PreparedStream {
            payload: compressed,
            is_compressed: true,
        })
    } else {
        Ok(PreparedStream {
            payload: payload.to_vec(),
            is_compressed: false,
        })
    }
}

pub fn chunk_payload(
    stream_id: u32,
    prepared: &PreparedStream,
    chunk_size: Option<usize>,
) -> Result<Vec<StreamChunkFrame>, StreamError> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_BYTES);
    if chunk_size == 0 {
        return Err(StreamError::new(
            StreamErrorKind::ChunkTooSmall,
            "Chunk size must be non-zero",
        ));
    }
    if chunk_size > WS_MAX_STREAM_CHUNK_BYTES {
        return Err(StreamError::new(
            StreamErrorKind::ChunkTooLarge,
            "Chunk size exceeds max message size",
        ));
    }
    if prepared.payload.len() > MAX_STREAM_BYTES {
        return Err(StreamError::new(
            StreamErrorKind::StreamTooLarge,
            "Payload exceeds stream maximum",
        ));
    }

    let mut chunks = Vec::new();
    let mut seq = 0;
    let mut offset = 0;
    while offset < prepared.payload.len() {
        let end = std::cmp::min(offset + chunk_size, prepared.payload.len());
        let mut flags = 0u8;
        if end == prepared.payload.len() {
            flags |= STREAM_FLAG_FINAL;
        }
        if prepared.is_compressed {
            flags |= STREAM_FLAG_COMPRESSED;
        }
        let payload = prepared.payload[offset..end].to_vec();
        chunks.push(StreamChunkFrame {
            stream_id,
            seq,
            flags,
            payload,
        });
        offset = end;
        seq += 1;
    }
    Ok(chunks)
}

#[derive(Debug)]
pub struct StreamState {
    stream_id: u32,
    pending_seq: Option<u32>,
    chunks: VecDeque<StreamChunkFrame>,
}

impl StreamState {
    pub fn new(stream_id: u32, chunks: Vec<StreamChunkFrame>) -> Self {
        Self {
            stream_id,
            pending_seq: None,
            chunks: VecDeque::from(chunks),
        }
    }

    pub fn next_chunk(&mut self) -> Option<StreamChunkFrame> {
        if self.pending_seq.is_some() {
            return None;
        }
        let chunk = self.chunks.pop_front();
        if let Some(ref chunk) = chunk {
            self.pending_seq = Some(chunk.seq);
        }
        chunk
    }

    pub fn ack(&mut self, seq: u32) -> Result<(), StreamError> {
        match self.pending_seq {
            Some(expected) if expected == seq => {
                self.pending_seq = None;
                Ok(())
            }
            Some(expected) => Err(StreamError::new(
                StreamErrorKind::AckMismatch,
                format!(
                    "Stream {} expected ack {}, got {}",
                    self.stream_id, expected, seq
                ),
            )),
            None => Err(StreamError::new(
                StreamErrorKind::AckMismatch,
                format!("Stream {} has no pending ack", self.stream_id),
            )),
        }
    }

    pub fn is_done(&self) -> bool {
        self.pending_seq.is_none() && self.chunks.is_empty()
    }
}

#[derive(Debug)]
pub struct StreamAssembler {
    stream_id: u32,
    next_seq: u32,
    buffer: Vec<u8>,
    max_bytes: usize,
}

impl StreamAssembler {
    pub fn new(stream_id: u32, max_bytes: Option<usize>) -> Self {
        Self {
            stream_id,
            next_seq: 0,
            buffer: Vec::new(),
            max_bytes: max_bytes.unwrap_or(MAX_STREAM_BYTES),
        }
    }

    pub fn push(&mut self, chunk: &StreamChunkFrame) -> Result<Option<Vec<u8>>, StreamError> {
        if chunk.stream_id != self.stream_id {
            return Err(StreamError::new(
                StreamErrorKind::UnknownStream,
                "Stream ID mismatch",
            ));
        }
        if chunk.seq != self.next_seq {
            return Err(StreamError::new(
                StreamErrorKind::OutOfOrder,
                format!(
                    "Stream {} expected seq {}, got {}",
                    self.stream_id, self.next_seq, chunk.seq
                ),
            ));
        }
        if self.buffer.len() + chunk.payload.len() > self.max_bytes {
            return Err(StreamError::new(
                StreamErrorKind::StreamTooLarge,
                "Stream exceeded max size",
            ));
        }
        self.buffer.extend_from_slice(&chunk.payload);
        self.next_seq += 1;

        if chunk.is_final() {
            return Ok(Some(std::mem::take(&mut self.buffer)));
        }
        Ok(None)
    }
}

#[derive(Debug, Default)]
pub struct StreamTracker {
    streams: HashMap<u32, StreamState>,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, stream_id: u32, chunks: Vec<StreamChunkFrame>) {
        self.streams
            .insert(stream_id, StreamState::new(stream_id, chunks));
    }

    pub fn next_chunk(&mut self, stream_id: u32) -> Option<StreamChunkFrame> {
        self.streams.get_mut(&stream_id)?.next_chunk()
    }

    pub fn ack(&mut self, stream_id: u32, seq: u32) -> Result<(), StreamError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| StreamError::new(StreamErrorKind::UnknownStream, "Stream not found"))?;
        stream.ack(seq)?;
        if stream.is_done() {
            self.streams.remove(&stream_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_payload_sets_final_flag() {
        let prepared = PreparedStream {
            payload: vec![1, 2, 3, 4, 5],
            is_compressed: false,
        };
        let chunks = chunk_payload(7, &prepared, Some(2)).expect("chunks");
        assert_eq!(chunks.len(), 3);
        assert!(!chunks[0].is_final());
        assert!(!chunks[1].is_final());
        assert!(chunks[2].is_final());
    }

    #[test]
    fn prepare_stream_payload_compresses_when_helpful() {
        let payload = vec![b'a'; 1024];
        let prepared =
            prepare_stream_payload(&payload, CompressionDecision::Prefer).expect("prepare");
        assert!(prepared.is_compressed);
        assert!(prepared.payload.len() < payload.len());
    }

    #[test]
    fn prepare_stream_payload_skip_compression() {
        let payload = vec![1, 2, 3, 4];
        let prepared =
            prepare_stream_payload(&payload, CompressionDecision::Skip).expect("prepare");
        assert!(!prepared.is_compressed);
        assert_eq!(prepared.payload, payload);
    }

    #[test]
    fn stream_state_requires_ack() {
        let prepared = PreparedStream {
            payload: vec![1, 2, 3, 4],
            is_compressed: false,
        };
        let chunks = chunk_payload(1, &prepared, Some(2)).expect("chunks");
        let mut state = StreamState::new(1, chunks);
        let first = state.next_chunk().expect("first");
        assert_eq!(first.seq, 0);
        assert!(state.next_chunk().is_none());

        let err = state.ack(1).expect_err("wrong ack");
        assert_eq!(err.kind(), StreamErrorKind::AckMismatch);

        state.ack(0).expect("ack");
        let second = state.next_chunk().expect("second");
        assert_eq!(second.seq, 1);
    }

    #[test]
    fn stream_assembler_reassembles_payload() {
        let prepared = PreparedStream {
            payload: vec![1, 2, 3, 4, 5],
            is_compressed: false,
        };
        let chunks = chunk_payload(2, &prepared, Some(2)).expect("chunks");
        let mut assembler = StreamAssembler::new(2, Some(1024));
        let mut result = None;
        for chunk in chunks {
            result = assembler.push(&chunk).expect("push");
        }
        let reassembled = result.expect("final payload");
        assert_eq!(reassembled, prepared.payload);
    }
}
