// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::ContentSidecar;
use crate::management::errors::{ManagementError, ManagementErrorKind};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub enum UploadKind {
    Binary(BinaryUploadMeta),
    MarkdownCreate(MarkdownUploadMeta),
    MarkdownUpdate(MarkdownUpdateMeta),
}

#[derive(Debug, Clone)]
pub struct UploadBeginConfig {
    pub connection_id: u32,
    pub kind: UploadKind,
    pub temp_path: PathBuf,
    pub expected_bytes: u64,
    pub max_bytes: u64,
    pub chunk_bytes: u32,
    pub validate_utf8: bool,
}

impl UploadBeginConfig {
    pub fn builder(
        connection_id: u32,
        kind: UploadKind,
        temp_path: PathBuf,
        expected_bytes: u64,
        max_bytes: u64,
        chunk_bytes: u32,
    ) -> UploadBeginConfigBuilder {
        UploadBeginConfigBuilder {
            connection_id,
            kind,
            temp_path,
            expected_bytes,
            max_bytes,
            chunk_bytes,
            validate_utf8: false,
        }
    }
}

#[derive(Debug)]
pub struct UploadBeginConfigBuilder {
    connection_id: u32,
    kind: UploadKind,
    temp_path: PathBuf,
    expected_bytes: u64,
    max_bytes: u64,
    chunk_bytes: u32,
    validate_utf8: bool,
}

impl UploadBeginConfigBuilder {
    pub fn validate_utf8(mut self, validate_utf8: bool) -> Self {
        self.validate_utf8 = validate_utf8;
        self
    }

    pub fn build(self) -> UploadBeginConfig {
        UploadBeginConfig {
            connection_id: self.connection_id,
            kind: self.kind,
            temp_path: self.temp_path,
            expected_bytes: self.expected_bytes,
            max_bytes: self.max_bytes,
            chunk_bytes: self.chunk_bytes,
            validate_utf8: self.validate_utf8,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryUploadMeta {
    pub content_id: u64,
    pub version: u32,
    pub alias: String,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub filename: String,
    pub mime: String,
}

#[derive(Debug, Clone)]
pub struct MarkdownUploadMeta {
    pub content_id: u64,
    pub version: u32,
    pub sidecar: ContentSidecar,
}

#[derive(Debug, Clone)]
pub struct MarkdownUpdateMeta {
    pub content_id: u64,
    pub base_version: u32,
    pub sidecar: ContentSidecar,
    pub clear_children: bool,
    pub nav_changed: bool,
}

#[derive(Debug)]
pub struct UploadInit {
    pub upload_id: u32,
    pub stream_id: u32,
    pub max_bytes: u64,
    pub chunk_bytes: u32,
}

#[derive(Debug)]
pub struct UploadRecord {
    pub kind: UploadKind,
    pub stream_id: u32,
    pub chunk_bytes: u32,
    pub temp_path: PathBuf,
    pub bytes_written: u64,
    pub expected_bytes: u64,
    pub max_bytes: u64,
    pub complete: bool,
    pub connection_id: u32,
    pub utf8: Option<Utf8Validator>,
    pub file: File,
}

#[derive(Debug)]
pub struct UploadRegistry {
    sender: mpsc::Sender<UploadCommand>,
}

impl UploadRegistry {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let worker = UploadRegistryWorker::new();
        let thread = std::thread::Builder::new().name("upload-registry".to_string());
        if let Err(err) = thread.spawn(move || worker.run(receiver)) {
            log::error!("Upload registry worker failed to start: {}", err);
        }
        Self { sender }
    }

    pub async fn begin_upload(
        &self,
        config: UploadBeginConfig,
    ) -> Result<UploadInit, ManagementError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(UploadCommand::BeginUpload {
                config: Box::new(config),
                reply,
            })
            .map_err(|_| registry_unavailable())?;
        response.await.map_err(|_| registry_unavailable())?
    }

    pub async fn append_chunk(
        &self,
        stream_id: u32,
        payload: Vec<u8>,
        is_final: bool,
        is_compressed: bool,
    ) -> Result<(), ManagementError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(UploadCommand::AppendChunk {
                stream_id,
                payload,
                is_final,
                is_compressed,
                reply,
            })
            .map_err(|_| registry_unavailable())?;
        response.await.map_err(|_| registry_unavailable())?
    }

    pub async fn take_upload(&self, upload_id: u32) -> Result<UploadRecord, ManagementError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(UploadCommand::TakeUpload { upload_id, reply })
            .map_err(|_| registry_unavailable())?;
        response.await.map_err(|_| registry_unavailable())?
    }

    pub async fn cleanup_connection(&self, connection_id: u32) -> Result<(), ManagementError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(UploadCommand::CleanupConnection {
                connection_id,
                reply,
            })
            .map_err(|_| registry_unavailable())?;
        response.await.map_err(|_| registry_unavailable())?
    }

    pub async fn abort_stream(&self, stream_id: u32) -> Result<(), ManagementError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(UploadCommand::AbortStream { stream_id, reply })
            .map_err(|_| registry_unavailable())?;
        response.await.map_err(|_| registry_unavailable())?
    }
}

impl Default for UploadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn registry_unavailable() -> ManagementError {
    ManagementError::new(
        ManagementErrorKind::Internal,
        None,
        None,
        "Upload registry unavailable",
    )
}

enum UploadCommand {
    BeginUpload {
        config: Box<UploadBeginConfig>,
        reply: oneshot::Sender<Result<UploadInit, ManagementError>>,
    },
    AppendChunk {
        stream_id: u32,
        payload: Vec<u8>,
        is_final: bool,
        is_compressed: bool,
        reply: oneshot::Sender<Result<(), ManagementError>>,
    },
    TakeUpload {
        upload_id: u32,
        reply: oneshot::Sender<Result<UploadRecord, ManagementError>>,
    },
    CleanupConnection {
        connection_id: u32,
        reply: oneshot::Sender<Result<(), ManagementError>>,
    },
    AbortStream {
        stream_id: u32,
        reply: oneshot::Sender<Result<(), ManagementError>>,
    },
}

#[derive(Debug)]
struct UploadRegistryWorker {
    next_upload_id: u32,
    next_stream_id: u32,
    uploads: HashMap<u32, UploadRecord>,
    streams: HashMap<u32, u32>,
}

impl UploadRegistryWorker {
    fn new() -> Self {
        Self {
            next_upload_id: 1,
            next_stream_id: 1,
            uploads: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    fn run(mut self, receiver: mpsc::Receiver<UploadCommand>) {
        while let Ok(command) = receiver.recv() {
            match command {
                UploadCommand::BeginUpload { config, reply } => {
                    let result = self.handle_begin_upload(*config);
                    let _ = reply.send(result);
                }
                UploadCommand::AppendChunk {
                    stream_id,
                    payload,
                    is_final,
                    is_compressed,
                    reply,
                } => {
                    let result =
                        self.handle_append_chunk(stream_id, payload, is_final, is_compressed);
                    let _ = reply.send(result);
                }
                UploadCommand::TakeUpload { upload_id, reply } => {
                    let result = self.handle_take_upload(upload_id);
                    let _ = reply.send(result);
                }
                UploadCommand::CleanupConnection {
                    connection_id,
                    reply,
                } => {
                    self.handle_cleanup_connection(connection_id);
                    let _ = reply.send(Ok(()));
                }
                UploadCommand::AbortStream { stream_id, reply } => {
                    self.handle_abort_stream(stream_id);
                    let _ = reply.send(Ok(()));
                }
            }
        }
    }

    fn handle_begin_upload(
        &mut self,
        config: UploadBeginConfig,
    ) -> Result<UploadInit, ManagementError> {
        let UploadBeginConfig {
            connection_id,
            kind,
            temp_path,
            expected_bytes,
            max_bytes,
            chunk_bytes,
            validate_utf8,
        } = config;

        if expected_bytes == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload size must be greater than 0",
            ));
        }
        if max_bytes < expected_bytes {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload exceeds maximum size",
            ));
        }
        if chunk_bytes == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload chunk size must be greater than 0",
            ));
        }
        if chunk_bytes as usize > crate::management::ws::WS_MAX_STREAM_CHUNK_BYTES {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload chunk size exceeds protocol message limit",
            ));
        }

        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Failed to create upload dir: {}", err),
                )
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Failed to create upload temp file: {}", err),
                )
            })?;

        let upload_id = self.next_upload_id();
        let stream_id = self.next_stream_id();

        let record = UploadRecord {
            kind,
            stream_id,
            chunk_bytes,
            temp_path,
            bytes_written: 0,
            expected_bytes,
            max_bytes,
            complete: false,
            connection_id,
            utf8: if validate_utf8 {
                Some(Utf8Validator::new())
            } else {
                None
            },
            file,
        };

        self.uploads.insert(upload_id, record);
        self.streams.insert(stream_id, upload_id);

        Ok(UploadInit {
            upload_id,
            stream_id,
            max_bytes,
            chunk_bytes,
        })
    }

    fn handle_append_chunk(
        &mut self,
        stream_id: u32,
        payload: Vec<u8>,
        is_final: bool,
        is_compressed: bool,
    ) -> Result<(), ManagementError> {
        if is_compressed {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Compressed upload chunks are not supported",
            ));
        }

        let upload_id = *self.streams.get(&stream_id).ok_or_else(|| {
            ManagementError::new(
                ManagementErrorKind::NotFound,
                None,
                None,
                "Unknown upload stream",
            )
        })?;

        let record = self.uploads.get_mut(&upload_id).ok_or_else(|| {
            ManagementError::new(
                ManagementErrorKind::NotFound,
                None,
                None,
                "Upload not found",
            )
        })?;

        let new_size = record.bytes_written.saturating_add(payload.len() as u64);
        if payload.len() > record.chunk_bytes as usize {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload chunk exceeds negotiated size",
            ));
        }
        if new_size > record.max_bytes {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Upload exceeded negotiated size",
            ));
        }

        if let Some(validator) = record.utf8.as_mut() {
            validator.push(&payload)?;
        }

        record.file.write_all(&payload).map_err(|err| {
            ManagementError::new(
                ManagementErrorKind::Internal,
                None,
                None,
                format!("Failed to write upload chunk: {}", err),
            )
        })?;
        record.bytes_written = new_size;

        if is_final {
            if record.bytes_written != record.expected_bytes {
                return Err(ManagementError::new(
                    ManagementErrorKind::Validation,
                    None,
                    None,
                    "Upload size mismatch",
                ));
            }
            if let Some(validator) = record.utf8.as_ref() {
                validator.finish()?;
            }
            record.complete = true;
        }

        Ok(())
    }

    fn handle_take_upload(&mut self, upload_id: u32) -> Result<UploadRecord, ManagementError> {
        let record = self.uploads.remove(&upload_id).ok_or_else(|| {
            ManagementError::new(
                ManagementErrorKind::NotFound,
                None,
                None,
                "Upload not found",
            )
        })?;
        self.streams.remove(&record.stream_id);
        Ok(record)
    }

    fn handle_cleanup_connection(&mut self, connection_id: u32) {
        let mut to_remove = Vec::new();
        for (upload_id, record) in self.uploads.iter() {
            if record.connection_id == connection_id {
                to_remove.push(*upload_id);
            }
        }
        for upload_id in to_remove {
            if let Some(record) = self.uploads.remove(&upload_id) {
                self.streams.remove(&record.stream_id);
                let _ = fs::remove_file(&record.temp_path);
            }
        }
    }

    fn handle_abort_stream(&mut self, stream_id: u32) {
        let upload_id = self.streams.get(&stream_id).copied();
        if let Some(upload_id) = upload_id
            && let Some(record) = self.uploads.remove(&upload_id)
        {
            self.streams.remove(&record.stream_id);
            let _ = fs::remove_file(&record.temp_path);
        }
    }

    fn next_upload_id(&mut self) -> u32 {
        next_id(&mut self.next_upload_id)
    }

    fn next_stream_id(&mut self) -> u32 {
        next_id(&mut self.next_stream_id)
    }
}

fn next_id(counter: &mut u32) -> u32 {
    let id = *counter;
    *counter = counter.wrapping_add(1);
    if *counter == 0 {
        *counter = 1;
    }
    id
}

#[derive(Debug, Default)]
pub struct Utf8Validator {
    pending: Vec<u8>,
}

impl Utf8Validator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ManagementError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut buffer = Vec::with_capacity(self.pending.len() + bytes.len());
        buffer.extend_from_slice(&self.pending);
        buffer.extend_from_slice(bytes);
        match std::str::from_utf8(&buffer) {
            Ok(_) => {
                self.pending.clear();
                Ok(())
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                let error_len = err.error_len();
                if error_len.is_some() {
                    return Err(ManagementError::new(
                        ManagementErrorKind::Validation,
                        None,
                        None,
                        "Markdown upload is not valid UTF-8",
                    ));
                }
                let tail = buffer.split_off(valid_up_to);
                self.pending = tail;
                Ok(())
            }
        }
    }

    pub fn finish(&self) -> Result<(), ManagementError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "Markdown upload ended with invalid UTF-8",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;

    fn build_binary_meta() -> BinaryUploadMeta {
        BinaryUploadMeta {
            content_id: 1,
            version: 1,
            alias: "docs/guide".to_string(),
            title: Some("Guide".to_string()),
            tags: vec!["docs".to_string()],
            filename: "guide.pdf".to_string(),
            mime: "application/pdf".to_string(),
        }
    }

    #[tokio::test]
    async fn upload_registry_stream_roundtrip() {
        let registry = UploadRegistry::new();
        let fixture = TestFixtureRoot::new_unique("upload-registry").unwrap();
        let temp_path = fixture.path().join("content").join("upload.bin");
        let payload = b"hello-world".to_vec();

        let init = registry
            .begin_upload(
                UploadBeginConfig::builder(
                    42,
                    UploadKind::Binary(build_binary_meta()),
                    temp_path.clone(),
                    payload.len() as u64,
                    payload.len() as u64,
                    1024,
                )
                .validate_utf8(false)
                .build(),
            )
            .await
            .unwrap();

        registry
            .append_chunk(init.stream_id, payload.clone(), true, false)
            .await
            .unwrap();

        let record = registry.take_upload(init.upload_id).await.unwrap();
        assert!(record.complete);
        assert_eq!(record.bytes_written, payload.len() as u64);
        assert_eq!(record.expected_bytes, payload.len() as u64);
        assert_eq!(record.connection_id, 42);
        drop(record.file);

        let written = fs::read(&record.temp_path).unwrap();
        assert_eq!(written, payload);
    }

    #[tokio::test]
    async fn upload_registry_cleanup_connection_removes_uploads() {
        let registry = UploadRegistry::new();
        let fixture = TestFixtureRoot::new_unique("upload-registry-cleanup").unwrap();
        let temp_path_a = fixture.path().join("content").join("a.bin");
        let temp_path_b = fixture.path().join("content").join("b.bin");

        let init_a = registry
            .begin_upload(
                UploadBeginConfig::builder(
                    10,
                    UploadKind::Binary(build_binary_meta()),
                    temp_path_a.clone(),
                    3,
                    3,
                    1024,
                )
                .validate_utf8(false)
                .build(),
            )
            .await
            .unwrap();
        let init_b = registry
            .begin_upload(
                UploadBeginConfig::builder(
                    20,
                    UploadKind::Binary(build_binary_meta()),
                    temp_path_b.clone(),
                    3,
                    3,
                    1024,
                )
                .validate_utf8(false)
                .build(),
            )
            .await
            .unwrap();

        registry.cleanup_connection(10).await.unwrap();
        assert!(!temp_path_a.exists());

        let missing = registry.take_upload(init_a.upload_id).await.unwrap_err();
        assert_eq!(missing.kind(), ManagementErrorKind::NotFound);

        registry.abort_stream(init_b.stream_id).await.unwrap();
        assert!(!temp_path_b.exists());
    }
}
