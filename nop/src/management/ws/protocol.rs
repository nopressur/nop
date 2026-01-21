// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::wire::{WireReader, WireWriter};
use serde::{Deserialize, Serialize};

pub const WS_MAX_MESSAGE_BYTES: usize = 63 * 1024;
// StreamChunk frame overhead: frame_type + stream_id + seq + flags + payload_len.
pub const WS_STREAM_CHUNK_OVERHEAD_BYTES: usize = 17;
pub const WS_MAX_STREAM_CHUNK_BYTES: usize = WS_MAX_MESSAGE_BYTES - WS_STREAM_CHUNK_OVERHEAD_BYTES;
pub const STREAM_FLAG_FINAL: u8 = 0b0000_0001;
pub const STREAM_FLAG_COMPRESSED: u8 = 0b0000_0010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsProtocolErrorKind {
    Codec,
    FrameTooLarge,
}

#[derive(Debug, Clone)]
pub struct WsProtocolError {
    kind: WsProtocolErrorKind,
    message: String,
}

impl WsProtocolError {
    pub fn new(kind: WsProtocolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> WsProtocolErrorKind {
        self.kind
    }
}

impl std::fmt::Display for WsProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ws protocol error: {}", self.message)
    }
}

impl std::error::Error for WsProtocolError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WsFrame {
    Auth(AuthFrame),
    AuthOk(AuthResponseFrame),
    AuthErr(AuthResponseFrame),
    Request(RequestFrame),
    Response(ResponseFrame),
    StreamChunk(StreamChunkFrame),
    Ack(StreamAckFrame),
    Error(ErrorFrame),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthFrame {
    pub ticket: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResponseFrame {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestFrame {
    pub domain_id: u32,
    pub action_id: u32,
    pub workflow_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseFrame {
    pub domain_id: u32,
    pub action_id: u32,
    pub workflow_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamChunkFrame {
    pub stream_id: u32,
    pub seq: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl StreamChunkFrame {
    pub fn is_final(&self) -> bool {
        self.flags & STREAM_FLAG_FINAL != 0
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & STREAM_FLAG_COMPRESSED != 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamAckFrame {
    pub stream_id: u32,
    pub seq: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorFrame {
    pub message: String,
}

pub fn encode_frame(frame: &WsFrame) -> Result<Vec<u8>, WsProtocolError> {
    let mut writer = WireWriter::new();
    match frame {
        WsFrame::Auth(frame) => {
            writer.write_u32(0);
            writer
                .write_string(&frame.ticket)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
            writer
                .write_string(&frame.csrf_token)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::AuthOk(frame) => {
            writer.write_u32(1);
            writer
                .write_string(&frame.message)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::AuthErr(frame) => {
            writer.write_u32(2);
            writer
                .write_string(&frame.message)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::Request(frame) => {
            writer.write_u32(3);
            writer.write_u32(frame.domain_id);
            writer.write_u32(frame.action_id);
            writer.write_u32(frame.workflow_id);
            writer
                .write_bytes(&frame.payload)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::Response(frame) => {
            writer.write_u32(4);
            writer.write_u32(frame.domain_id);
            writer.write_u32(frame.action_id);
            writer.write_u32(frame.workflow_id);
            writer
                .write_bytes(&frame.payload)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::StreamChunk(frame) => {
            writer.write_u32(5);
            writer.write_u32(frame.stream_id);
            writer.write_u32(frame.seq);
            writer.write_u8(frame.flags);
            writer
                .write_bytes(&frame.payload)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
        WsFrame::Ack(frame) => {
            writer.write_u32(6);
            writer.write_u32(frame.stream_id);
            writer.write_u32(frame.seq);
        }
        WsFrame::Error(frame) => {
            writer.write_u32(7);
            writer
                .write_string(&frame.message)
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;
        }
    }

    let bytes = writer.into_bytes();
    if bytes.len() > WS_MAX_MESSAGE_BYTES {
        return Err(WsProtocolError::new(
            WsProtocolErrorKind::FrameTooLarge,
            format!(
                "Message length {} exceeds max {}",
                bytes.len(),
                WS_MAX_MESSAGE_BYTES
            ),
        ));
    }
    Ok(bytes)
}

pub fn decode_frame(bytes: &[u8]) -> Result<WsFrame, WsProtocolError> {
    if bytes.len() > WS_MAX_MESSAGE_BYTES {
        return Err(WsProtocolError::new(
            WsProtocolErrorKind::FrameTooLarge,
            format!(
                "Message length {} exceeds max {}",
                bytes.len(),
                WS_MAX_MESSAGE_BYTES
            ),
        ));
    }
    let mut reader = WireReader::new(bytes);
    let variant = reader
        .read_u32()
        .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;

    let frame = match variant {
        0 => WsFrame::Auth(AuthFrame {
            ticket: reader
                .read_string()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            csrf_token: reader
                .read_string()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        1 => WsFrame::AuthOk(AuthResponseFrame {
            message: reader
                .read_string()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        2 => WsFrame::AuthErr(AuthResponseFrame {
            message: reader
                .read_string()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        3 => WsFrame::Request(RequestFrame {
            domain_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            action_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            workflow_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            payload: reader
                .read_bytes()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        4 => WsFrame::Response(ResponseFrame {
            domain_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            action_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            workflow_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            payload: reader
                .read_bytes()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        5 => WsFrame::StreamChunk(StreamChunkFrame {
            stream_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            seq: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            flags: reader
                .read_u8()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            payload: reader
                .read_bytes()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        6 => WsFrame::Ack(StreamAckFrame {
            stream_id: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
            seq: reader
                .read_u32()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        7 => WsFrame::Error(ErrorFrame {
            message: reader
                .read_string()
                .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?,
        }),
        _ => {
            return Err(WsProtocolError::new(
                WsProtocolErrorKind::Codec,
                format!("Unknown frame type {}", variant),
            ));
        }
    };

    reader
        .ensure_fully_consumed()
        .map_err(|err| WsProtocolError::new(WsProtocolErrorKind::Codec, err.to_string()))?;

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = WsFrame::Request(RequestFrame {
            domain_id: 1,
            action_id: 2,
            workflow_id: 3,
            payload: vec![1, 2, 3],
        });
        let encoded = encode_frame(&frame).expect("encode");
        let decoded = decode_frame(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_rejects_oversized_frame() {
        let bytes = vec![0u8; WS_MAX_MESSAGE_BYTES + 1];
        let err = decode_frame(&bytes).expect_err("oversized");
        assert_eq!(err.kind(), WsProtocolErrorKind::FrameTooLarge);
    }

    #[test]
    fn encode_rejects_oversized_frame() {
        let payload = vec![0u8; WS_MAX_MESSAGE_BYTES];
        let frame = WsFrame::Request(RequestFrame {
            domain_id: 1,
            action_id: 1,
            workflow_id: 1,
            payload,
        });
        let err = encode_frame(&frame).expect_err("oversized");
        assert_eq!(err.kind(), WsProtocolErrorKind::FrameTooLarge);
    }

    #[test]
    fn decode_rejects_malformed_frame() {
        let bytes = vec![0xFF];
        let err = decode_frame(&bytes).expect_err("malformed");
        assert_eq!(err.kind(), WsProtocolErrorKind::Codec);
    }
}
