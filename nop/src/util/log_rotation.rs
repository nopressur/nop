// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

pub const DEFAULT_LOG_FILE_NAME: &str = "nopressure.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogRunMode {
    Foreground,
    Daemon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotationSettings {
    pub max_size_mb: u64,
    pub max_files: u32,
}

impl LogRotationSettings {
    pub fn max_size_bytes(self) -> u64 {
        self.max_size_mb.saturating_mul(1024 * 1024)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LogCleanupStats {
    pub deleted_files: usize,
    pub deleted_bytes: u64,
}

#[derive(Clone)]
pub struct RotatingLogWriter {
    sender: mpsc::Sender<LogWriterCommand>,
}

struct RotatingLogWriterInner {
    log_dir: PathBuf,
    base_name: String,
    max_bytes: u64,
    max_files: u32,
    file: fs::File,
    size: u64,
}

enum LogWriterCommand {
    Write {
        bytes: Vec<u8>,
        reply: mpsc::Sender<io::Result<usize>>,
    },
    Flush {
        reply: mpsc::Sender<io::Result<()>>,
    },
    UpdateSettings {
        settings: LogRotationSettings,
        reply: mpsc::Sender<io::Result<()>>,
    },
    ClearLogs {
        reply: mpsc::Sender<io::Result<LogCleanupStats>>,
    },
}

impl RotatingLogWriter {
    pub fn new(
        log_dir: PathBuf,
        base_name: impl Into<String>,
        settings: LogRotationSettings,
    ) -> io::Result<Self> {
        let created = !log_dir.exists();
        fs::create_dir_all(&log_dir)?;
        if created {
            ensure_log_dir_permissions(&log_dir)?;
        }
        let base_name = base_name.into();
        let (file, size) = open_log_file(&log_dir, &base_name)?;
        let inner = RotatingLogWriterInner {
            log_dir,
            base_name,
            max_bytes: settings.max_size_bytes(),
            max_files: settings.max_files.max(1),
            file,
            size,
        };
        let sender = start_log_writer(inner)?;
        Ok(Self { sender })
    }

    pub fn update_settings(&self, settings: LogRotationSettings) -> io::Result<()> {
        self.request(|reply| LogWriterCommand::UpdateSettings { settings, reply })
    }

    pub fn clear_logs(&self) -> io::Result<LogCleanupStats> {
        self.request(|reply| LogWriterCommand::ClearLogs { reply })
    }

    fn request<T>(
        &self,
        build: impl FnOnce(mpsc::Sender<io::Result<T>>) -> LogWriterCommand,
    ) -> io::Result<T> {
        let (reply, receive) = mpsc::channel();
        self.sender
            .send(build(reply))
            .map_err(|_| io::Error::other("Log writer channel closed"))?;
        match receive.recv() {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("Log writer channel closed")),
        }
    }
}

impl Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.request(|reply| LogWriterCommand::Write {
            bytes: buf.to_vec(),
            reply,
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.request(|reply| LogWriterCommand::Flush { reply })
    }
}

impl RotatingLogWriterInner {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.rotate_if_needed(buf.len() as u64)?;
        self.file.write_all(buf)?;
        self.size = self.size.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn update_settings(&mut self, settings: LogRotationSettings) -> io::Result<()> {
        let previous_max_files = self.max_files;
        self.max_bytes = settings.max_size_bytes();
        self.max_files = settings.max_files.max(1);
        if self.max_files < previous_max_files {
            prune_rotated_logs(&self.log_dir, &self.base_name, self.max_files)?;
        }
        Ok(())
    }

    fn clear_logs(&mut self) -> io::Result<LogCleanupStats> {
        self.file.flush()?;
        let base_size = self.size;
        self.file.set_len(0)?;
        self.size = 0;
        let mut stats = clear_rotated_logs(&self.log_dir, &self.base_name)?;
        stats.deleted_bytes = stats.deleted_bytes.saturating_add(base_size);
        Ok(stats)
    }

    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<()> {
        if self.max_bytes == 0 {
            return Ok(());
        }
        if self.size > 0 && self.size.saturating_add(incoming) > self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        let max_files = self.max_files.max(1);
        if max_files <= 1 {
            let _ = remove_if_exists(&self.log_path());
            let (file, size) = open_log_file(&self.log_dir, &self.base_name)?;
            self.file = file;
            self.size = size;
            return Ok(());
        }

        let oldest = self.rotated_path(max_files);
        let _ = remove_if_exists(&oldest);

        for index in (1..max_files).rev() {
            let from = self.rotated_path(index);
            let to = self.rotated_path(index + 1);
            if from.exists() {
                let _ = fs::rename(from, to);
            }
        }

        let base_path = self.log_path();
        if base_path.exists() {
            let _ = fs::rename(base_path, self.rotated_path(1));
        }

        let (file, size) = open_log_file(&self.log_dir, &self.base_name)?;
        self.file = file;
        self.size = size;
        Ok(())
    }

    fn log_path(&self) -> PathBuf {
        self.log_dir.join(&self.base_name)
    }

    fn rotated_path(&self, index: u32) -> PathBuf {
        self.log_dir.join(format!("{}.{}", self.base_name, index))
    }
}

fn start_log_writer(inner: RotatingLogWriterInner) -> io::Result<mpsc::Sender<LogWriterCommand>> {
    let (sender, receiver) = mpsc::channel();
    let thread = thread::Builder::new().name("log-rotation".to_string());
    thread
        .spawn(move || run_log_writer(receiver, inner))
        .map_err(|err| io::Error::other(format!("Log writer worker failed to start: {}", err)))?;
    Ok(sender)
}

fn run_log_writer(receiver: mpsc::Receiver<LogWriterCommand>, mut inner: RotatingLogWriterInner) {
    while let Ok(command) = receiver.recv() {
        match command {
            LogWriterCommand::Write { bytes, reply } => {
                let _ = reply.send(inner.write(&bytes));
            }
            LogWriterCommand::Flush { reply } => {
                let _ = reply.send(inner.file.flush());
            }
            LogWriterCommand::UpdateSettings { settings, reply } => {
                let _ = reply.send(inner.update_settings(settings));
            }
            LogWriterCommand::ClearLogs { reply } => {
                let _ = reply.send(inner.clear_logs());
            }
        }
    }
}

#[derive(Clone)]
pub struct LogController {
    snapshot: Arc<LogControllerSnapshot>,
    run_mode: LogRunMode,
    log_dir: PathBuf,
    base_name: String,
    writer: Option<RotatingLogWriter>,
}

struct LogControllerSnapshot {
    rotation_max_size_mb: AtomicU64,
    rotation_max_files: AtomicU32,
}

impl LogController {
    pub fn new(
        run_mode: LogRunMode,
        log_dir: PathBuf,
        base_name: impl Into<String>,
        rotation: LogRotationSettings,
        writer: Option<RotatingLogWriter>,
    ) -> Self {
        let base_name = base_name.into();
        Self {
            snapshot: Arc::new(LogControllerSnapshot {
                rotation_max_size_mb: AtomicU64::new(rotation.max_size_mb),
                rotation_max_files: AtomicU32::new(rotation.max_files.max(1)),
            }),
            run_mode,
            log_dir,
            base_name,
            writer,
        }
    }

    pub fn run_mode(&self) -> LogRunMode {
        self.run_mode
    }

    pub fn file_logging_active(&self) -> io::Result<bool> {
        Ok(self.writer.is_some())
    }

    pub fn rotation(&self) -> io::Result<LogRotationSettings> {
        Ok(LogRotationSettings {
            max_size_mb: self.snapshot.rotation_max_size_mb.load(Ordering::SeqCst),
            max_files: self.snapshot.rotation_max_files.load(Ordering::SeqCst),
        })
    }

    pub fn update_rotation(&self, rotation: LogRotationSettings) -> io::Result<()> {
        let max_files = rotation.max_files.max(1);
        let previous_max_files = self
            .snapshot
            .rotation_max_files
            .swap(max_files, Ordering::SeqCst);
        self.snapshot
            .rotation_max_size_mb
            .store(rotation.max_size_mb, Ordering::SeqCst);
        let rotation = LogRotationSettings {
            max_size_mb: rotation.max_size_mb,
            max_files,
        };
        if let Some(writer) = &self.writer {
            writer.update_settings(rotation)?;
        } else if max_files < previous_max_files {
            prune_rotated_logs(&self.log_dir, &self.base_name, max_files)?;
        }
        Ok(())
    }

    pub fn clear_logs(&self) -> io::Result<LogCleanupStats> {
        if let Some(writer) = &self.writer {
            return writer.clear_logs();
        }
        clear_log_files(&self.log_dir, &self.base_name)
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }
}

pub fn clear_log_files(log_dir: &Path, base_name: &str) -> io::Result<LogCleanupStats> {
    let mut stats = LogCleanupStats::default();
    if !log_dir.exists() {
        return Ok(stats);
    }
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !is_log_file_name(name, base_name) {
            continue;
        }
        if let Ok(metadata) = entry.metadata() {
            stats.deleted_bytes = stats.deleted_bytes.saturating_add(metadata.len());
        }
        if fs::remove_file(&path).is_ok() {
            stats.deleted_files += 1;
        }
    }
    Ok(stats)
}

pub fn clear_rotated_logs(log_dir: &Path, base_name: &str) -> io::Result<LogCleanupStats> {
    let mut stats = LogCleanupStats::default();
    if !log_dir.exists() {
        return Ok(stats);
    }
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if rotated_index(name, base_name).is_none() {
            continue;
        }
        if let Ok(metadata) = entry.metadata() {
            stats.deleted_bytes = stats.deleted_bytes.saturating_add(metadata.len());
        }
        if fs::remove_file(&path).is_ok() {
            stats.deleted_files += 1;
        }
    }
    Ok(stats)
}

pub fn prune_rotated_logs(log_dir: &Path, base_name: &str, max_files: u32) -> io::Result<()> {
    if !log_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if let Some(index) = rotated_index(name, base_name)
            && index >= max_files
        {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn open_log_file(log_dir: &Path, base_name: &str) -> io::Result<(fs::File, u64)> {
    let file = open_log_file_handle(log_dir, base_name)?;
    let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    Ok((file, size))
}

fn open_log_file_handle(log_dir: &Path, base_name: &str) -> io::Result<fs::File> {
    let path = log_dir.join(base_name);
    fs::OpenOptions::new().create(true).append(true).open(path)
}

fn is_log_file_name(name: &str, base_name: &str) -> bool {
    if name == base_name {
        return true;
    }
    rotated_index(name, base_name).is_some()
}

fn rotated_index(name: &str, base_name: &str) -> Option<u32> {
    let suffix = name.strip_prefix(base_name)?;
    let suffix = suffix.strip_prefix('.')?;
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<u32>().ok()
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn ensure_log_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;
    use std::io::Write;

    fn write_bytes(writer: &mut RotatingLogWriter, total: usize) {
        let chunk = vec![b'a'; 64 * 1024];
        let mut remaining = total;
        while remaining > 0 {
            let to_write = remaining.min(chunk.len());
            writer.write_all(&chunk[..to_write]).unwrap();
            remaining -= to_write;
        }
        writer.flush().unwrap();
    }

    #[test]
    fn rotating_writer_rotates_and_prunes() {
        let fixture = TestFixtureRoot::new_unique("log-rotate").unwrap();
        let log_dir = fixture.path().join("logs");
        let settings = LogRotationSettings {
            max_size_mb: 1,
            max_files: 2,
        };
        let mut writer = RotatingLogWriter::new(log_dir.clone(), DEFAULT_LOG_FILE_NAME, settings)
            .expect("writer");

        write_bytes(&mut writer, 512 * 1024);
        write_bytes(&mut writer, 700 * 1024);

        assert!(log_dir.join(DEFAULT_LOG_FILE_NAME).exists());
        assert!(
            log_dir
                .join(format!("{}.1", DEFAULT_LOG_FILE_NAME))
                .exists()
        );
        assert!(
            !log_dir
                .join(format!("{}.2", DEFAULT_LOG_FILE_NAME))
                .exists()
        );

        writer
            .update_settings(LogRotationSettings {
                max_size_mb: 1,
                max_files: 1,
            })
            .expect("update settings");
        assert!(
            !log_dir
                .join(format!("{}.1", DEFAULT_LOG_FILE_NAME))
                .exists()
        );
    }

    #[test]
    fn log_controller_clears_logs() {
        let fixture = TestFixtureRoot::new_unique("log-clear").unwrap();
        let log_dir = fixture.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();
        let base = log_dir.join(DEFAULT_LOG_FILE_NAME);
        let rotated = log_dir.join(format!("{}.1", DEFAULT_LOG_FILE_NAME));
        fs::write(&base, "hello").unwrap();
        fs::write(&rotated, "world").unwrap();

        let controller = LogController::new(
            LogRunMode::Foreground,
            log_dir.clone(),
            DEFAULT_LOG_FILE_NAME,
            LogRotationSettings {
                max_size_mb: 16,
                max_files: 10,
            },
            None,
        );

        let stats = controller.clear_logs().expect("clear logs");
        assert_eq!(stats.deleted_files, 2);
        assert!(stats.deleted_bytes > 0);
        assert!(!base.exists());
        assert!(!rotated.exists());
        assert!(log_dir.exists());
    }
}
