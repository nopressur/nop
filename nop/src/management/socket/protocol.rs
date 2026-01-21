// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{SocketError, SocketErrorKind, SocketResult};
use crate::management::wire::{WireReader, WireWriter};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub domain: u32,
    pub action: u32,
    pub workflow_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub domain: u32,
    pub action: u32,
    pub workflow_id: u32,
    pub payload: Vec<u8>,
}

pub(super) trait EnvelopeRead: Sized {
    fn from_parts(domain: u32, action: u32, workflow_id: u32, payload: Vec<u8>) -> Self;
}

pub(super) trait EnvelopeWrite {
    fn domain(&self) -> u32;
    fn action(&self) -> u32;
    fn workflow_id(&self) -> u32;
    fn payload(&self) -> &[u8];
}

impl EnvelopeRead for RequestEnvelope {
    fn from_parts(domain: u32, action: u32, workflow_id: u32, payload: Vec<u8>) -> Self {
        Self {
            domain,
            action,
            workflow_id,
            payload,
        }
    }
}

impl EnvelopeWrite for RequestEnvelope {
    fn domain(&self) -> u32 {
        self.domain
    }

    fn action(&self) -> u32 {
        self.action
    }

    fn workflow_id(&self) -> u32 {
        self.workflow_id
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl EnvelopeRead for ResponseEnvelope {
    fn from_parts(domain: u32, action: u32, workflow_id: u32, payload: Vec<u8>) -> Self {
        Self {
            domain,
            action,
            workflow_id,
            payload,
        }
    }
}

impl EnvelopeWrite for ResponseEnvelope {
    fn domain(&self) -> u32 {
        self.domain
    }

    fn action(&self) -> u32 {
        self.action
    }

    fn workflow_id(&self) -> u32 {
        self.workflow_id
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub(super) async fn read_envelope<T: EnvelopeRead>(stream: &mut UnixStream) -> SocketResult<T> {
    let frame = read_frame(stream).await?;
    let mut reader = WireReader::new(&frame);
    let domain = reader.read_u32().map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode envelope: {}", err),
        )
    })?;
    let action = reader.read_u32().map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode envelope: {}", err),
        )
    })?;
    let workflow_id = reader.read_u32().map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode envelope: {}", err),
        )
    })?;
    let payload = reader.read_bytes().map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode envelope: {}", err),
        )
    })?;
    reader.ensure_fully_consumed().map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode envelope: {}", err),
        )
    })?;
    Ok(T::from_parts(domain, action, workflow_id, payload))
}

pub(super) async fn write_envelope<T: EnvelopeWrite>(
    stream: &mut UnixStream,
    envelope: &T,
) -> SocketResult<()> {
    let mut writer = WireWriter::new();
    writer.write_u32(envelope.domain());
    writer.write_u32(envelope.action());
    writer.write_u32(envelope.workflow_id());
    writer.write_bytes(envelope.payload()).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to encode envelope: {}", err),
        )
    })?;
    write_frame(stream, &writer.into_bytes()).await
}

async fn read_frame(stream: &mut UnixStream) -> SocketResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|err| {
        SocketError::new(
            SocketErrorKind::Io,
            format!("Failed to read frame length: {}", err),
        )
    })?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(SocketError::new(
            SocketErrorKind::Protocol,
            "Empty frame received",
        ));
    }
    if len > MAX_FRAME_BYTES {
        return Err(SocketError::new(
            SocketErrorKind::Protocol,
            format!("Frame length {} exceeds max {}", len, MAX_FRAME_BYTES),
        ));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.map_err(|err| {
        SocketError::new(
            SocketErrorKind::Io,
            format!("Failed to read frame payload: {}", err),
        )
    })?;
    Ok(payload)
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> SocketResult<()> {
    if payload.is_empty() {
        return Err(SocketError::new(
            SocketErrorKind::Protocol,
            "Attempted to write empty frame",
        ));
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(SocketError::new(
            SocketErrorKind::Protocol,
            format!(
                "Frame length {} exceeds max {}",
                payload.len(),
                MAX_FRAME_BYTES
            ),
        ));
    }
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes()).await.map_err(|err| {
        SocketError::new(
            SocketErrorKind::Io,
            format!("Failed to write frame length: {}", err),
        )
    })?;
    stream.write_all(payload).await.map_err(|err| {
        SocketError::new(
            SocketErrorKind::Io,
            format!("Failed to write frame payload: {}", err),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn envelope_roundtrip() {
        let (mut client, mut server) = UnixStream::pair().expect("pair");
        let send = tokio::spawn(async move {
            let envelope = RequestEnvelope {
                domain: 1,
                action: 2,
                workflow_id: 1,
                payload: vec![1, 2, 3],
            };
            write_envelope(&mut client, &envelope).await.unwrap();
        });

        let recv = tokio::spawn(async move {
            let received: RequestEnvelope = read_envelope(&mut server).await.unwrap();
            assert_eq!(received.domain, 1);
            assert_eq!(received.action, 2);
            assert_eq!(received.workflow_id, 1);
            assert_eq!(received.payload, vec![1, 2, 3]);
        });

        send.await.unwrap();
        recv.await.unwrap();
    }

    #[tokio::test]
    async fn read_envelope_rejects_empty_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("pair");
        client.write_all(&0u32.to_le_bytes()).await.unwrap();
        let err = read_envelope::<RequestEnvelope>(&mut server)
            .await
            .expect_err("empty frame should fail");
        assert_eq!(err.kind(), SocketErrorKind::Protocol);
    }

    #[tokio::test]
    async fn read_envelope_rejects_oversized_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("pair");
        let len = (MAX_FRAME_BYTES + 1) as u32;
        client.write_all(&len.to_le_bytes()).await.unwrap();
        let err = read_envelope::<RequestEnvelope>(&mut server)
            .await
            .expect_err("oversized frame should fail");
        assert_eq!(err.kind(), SocketErrorKind::Protocol);
    }

    #[tokio::test]
    async fn read_envelope_rejects_malformed_payload() {
        let (mut client, mut server) = UnixStream::pair().expect("pair");
        client.write_all(&1u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xFF]).await.unwrap();
        let err = read_envelope::<RequestEnvelope>(&mut server)
            .await
            .expect_err("malformed payload should fail");
        assert_eq!(err.kind(), SocketErrorKind::Codec);
    }
}
