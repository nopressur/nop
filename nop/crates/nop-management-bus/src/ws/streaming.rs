// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::ws::protocol::{STREAM_FLAG_FINAL, StreamChunkFrame, WS_MAX_STREAM_CHUNK_BYTES};
use std::path::Path;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamErrorKind {
    ChunkTooSmall,
    ChunkTooLarge,
    SourceReadFailed,
    SourceSizeMismatch,
    AckMismatch,
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

#[derive(Debug)]
pub struct BlobStreamProducer {
    stream_id: u32,
    chunk_bytes: usize,
    expected_size: u64,
    file: tokio::fs::File,
    seq: u32,
    bytes_sent: u64,
    empty_sent: bool,
}

impl BlobStreamProducer {
    pub async fn open_file(
        stream_id: u32,
        path: &Path,
        expected_size: u64,
        chunk_bytes: u32,
    ) -> Result<Self, StreamError> {
        let chunk_bytes = validate_outbound_chunk_bytes(chunk_bytes)?;
        let metadata = tokio::fs::metadata(path).await.map_err(|err| {
            StreamError::new(
                StreamErrorKind::SourceReadFailed,
                format!("Failed to stat stream source: {}", err),
            )
        })?;
        if metadata.len() != expected_size {
            return Err(StreamError::new(
                StreamErrorKind::SourceSizeMismatch,
                format!(
                    "Stream source size mismatch (expected {}, got {})",
                    expected_size,
                    metadata.len()
                ),
            ));
        }
        let file = tokio::fs::File::open(path).await.map_err(|err| {
            StreamError::new(
                StreamErrorKind::SourceReadFailed,
                format!("Failed to open stream source: {}", err),
            )
        })?;
        Ok(Self {
            stream_id,
            chunk_bytes,
            expected_size,
            file,
            seq: 0,
            bytes_sent: 0,
            empty_sent: false,
        })
    }

    pub async fn next_chunk(&mut self) -> Result<Option<StreamChunkFrame>, StreamError> {
        if self.expected_size == 0 {
            if self.empty_sent {
                return Ok(None);
            }
            self.empty_sent = true;
            return Ok(Some(StreamChunkFrame {
                stream_id: self.stream_id,
                seq: 0,
                flags: STREAM_FLAG_FINAL,
                payload: Vec::new(),
            }));
        }

        let mut buffer = vec![0u8; self.chunk_bytes];
        let read = self.file.read(&mut buffer).await.map_err(|err| {
            StreamError::new(
                StreamErrorKind::SourceReadFailed,
                format!("Failed to read stream source: {}", err),
            )
        })?;
        if read == 0 {
            if self.bytes_sent == self.expected_size {
                return Ok(None);
            }
            return Err(StreamError::new(
                StreamErrorKind::SourceSizeMismatch,
                format!(
                    "Stream source ended early (sent {}, expected {})",
                    self.bytes_sent, self.expected_size
                ),
            ));
        }

        self.bytes_sent = self.bytes_sent.saturating_add(read as u64);
        if self.bytes_sent > self.expected_size {
            return Err(StreamError::new(
                StreamErrorKind::SourceSizeMismatch,
                format!(
                    "Stream source grew during read (sent {}, expected {})",
                    self.bytes_sent, self.expected_size
                ),
            ));
        }
        buffer.truncate(read);
        let mut flags = 0u8;
        if self.bytes_sent == self.expected_size {
            flags |= STREAM_FLAG_FINAL;
        }
        let chunk = StreamChunkFrame {
            stream_id: self.stream_id,
            seq: self.seq,
            flags,
            payload: buffer,
        };
        self.seq = self.seq.saturating_add(1);
        Ok(Some(chunk))
    }
}

pub fn validate_outbound_chunk_bytes(chunk_bytes: u32) -> Result<usize, StreamError> {
    if chunk_bytes == 0 {
        return Err(StreamError::new(
            StreamErrorKind::ChunkTooSmall,
            "Chunk size must be non-zero",
        ));
    }
    if chunk_bytes as usize > WS_MAX_STREAM_CHUNK_BYTES {
        return Err(StreamError::new(
            StreamErrorKind::ChunkTooLarge,
            "Chunk size exceeds max message size",
        ));
    }
    Ok(chunk_bytes as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blob_stream_producer_reads_file_incrementally() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        tokio::fs::write(temp.path(), b"abcdef")
            .await
            .expect("write temp file");
        let mut producer = BlobStreamProducer::open_file(9, temp.path(), 6, 2)
            .await
            .expect("producer");

        let first = producer
            .next_chunk()
            .await
            .expect("first result")
            .expect("first chunk");
        assert_eq!(first.seq, 0);
        assert_eq!(first.payload, b"ab");
        assert!(!first.is_final());

        let second = producer
            .next_chunk()
            .await
            .expect("second result")
            .expect("second chunk");
        assert_eq!(second.seq, 1);
        assert_eq!(second.payload, b"cd");
        assert!(!second.is_final());

        let third = producer
            .next_chunk()
            .await
            .expect("third result")
            .expect("third chunk");
        assert_eq!(third.seq, 2);
        assert_eq!(third.payload, b"ef");
        assert!(third.is_final());
        assert!(producer.next_chunk().await.expect("done").is_none());
    }

    #[tokio::test]
    async fn blob_stream_producer_emits_final_empty_chunk_for_empty_file() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        let mut producer = BlobStreamProducer::open_file(7, temp.path(), 0, 128)
            .await
            .expect("producer");

        let chunk = producer
            .next_chunk()
            .await
            .expect("chunk result")
            .expect("empty chunk");
        assert_eq!(chunk.stream_id, 7);
        assert_eq!(chunk.seq, 0);
        assert!(chunk.payload.is_empty());
        assert!(chunk.is_final());
        assert!(producer.next_chunk().await.expect("done").is_none());
    }

    #[tokio::test]
    async fn blob_stream_producer_rejects_size_mismatch() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        tokio::fs::write(temp.path(), b"abc")
            .await
            .expect("write temp file");

        let err = BlobStreamProducer::open_file(1, temp.path(), 4, 128)
            .await
            .expect_err("size mismatch");
        assert_eq!(err.kind(), StreamErrorKind::SourceSizeMismatch);
    }

    #[tokio::test]
    async fn blob_stream_producer_has_no_total_size_cap() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        let size = 16 * 1024 * 1024 + 1;
        temp.as_file().set_len(size).expect("set sparse length");
        let mut producer =
            BlobStreamProducer::open_file(11, temp.path(), size, WS_MAX_STREAM_CHUNK_BYTES as u32)
                .await
                .expect("producer");

        let mut total = 0u64;
        let mut chunks = 0u32;
        let mut saw_final = false;
        while let Some(chunk) = producer.next_chunk().await.expect("chunk") {
            total += chunk.payload.len() as u64;
            chunks += 1;
            if chunk.is_final() {
                saw_final = true;
            }
        }

        assert_eq!(total, size);
        assert!(chunks > 1);
        assert!(saw_final);
    }

    #[test]
    fn validate_outbound_chunk_bytes_rejects_invalid_sizes() {
        let too_small = validate_outbound_chunk_bytes(0).expect_err("too small");
        assert_eq!(too_small.kind(), StreamErrorKind::ChunkTooSmall);

        let too_large =
            validate_outbound_chunk_bytes(WS_MAX_STREAM_CHUNK_BYTES as u32 + 1).expect_err("large");
        assert_eq!(too_large.kind(), StreamErrorKind::ChunkTooLarge);

        assert_eq!(
            validate_outbound_chunk_bytes(WS_MAX_STREAM_CHUNK_BYTES as u32).expect("max"),
            WS_MAX_STREAM_CHUNK_BYTES
        );
    }
}
