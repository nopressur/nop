// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::warn;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{RwLock, mpsc};

#[derive(Debug)]
pub(crate) struct FailedIdStore {
    file_path: PathBuf,
    cache: RwLock<BTreeSet<String>>,
    writer_tx: mpsc::Sender<WriterCommand>,
}

#[derive(Debug)]
enum WriterCommand {
    Persist(Vec<String>),
    DeleteFile,
}

impl FailedIdStore {
    pub(crate) fn new(file_path: PathBuf) -> Result<Self, String> {
        let initial = load_snapshot_from_disk(&file_path)?;
        let (writer_tx, writer_rx) = mpsc::channel::<WriterCommand>();
        let file_path_for_worker = file_path.clone();
        let builder = std::thread::Builder::new().name("search-failed-id-writer".to_string());
        if let Err(err) = builder.spawn(move || writer_loop(file_path_for_worker, writer_rx)) {
            return Err(format!("Failed to start failed-id writer thread: {}", err));
        }
        Ok(Self {
            file_path,
            cache: RwLock::new(initial),
            writer_tx,
        })
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        let guard = read_recover(&self.cache, "failed-id snapshot");
        guard.iter().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, id_hex: &str) -> bool {
        let guard = read_recover(&self.cache, "failed-id contains");
        guard.contains(id_hex)
    }

    pub(crate) fn mark_failed(&self, id_hex: &str) {
        let mut guard = write_recover(&self.cache, "failed-id mark_failed");
        guard.insert(id_hex.to_string());
        self.enqueue_persist_locked(&guard);
    }

    pub(crate) fn clear_failed(&self, id_hex: &str) {
        let mut guard = write_recover(&self.cache, "failed-id clear_failed");
        if guard.remove(id_hex) {
            self.enqueue_persist_locked(&guard);
        }
    }

    pub(crate) fn clear_all_and_delete_file(&self) {
        let mut guard = write_recover(&self.cache, "failed-id clear_all");
        guard.clear();
        let _ = self.writer_tx.send(WriterCommand::DeleteFile);
    }

    pub(crate) fn file_path(&self) -> &PathBuf {
        &self.file_path
    }

    fn enqueue_persist_locked(&self, values: &BTreeSet<String>) {
        let snapshot: Vec<String> = values.iter().cloned().collect();
        if let Err(err) = self.writer_tx.send(WriterCommand::Persist(snapshot)) {
            warn!(
                "Search failed-id writer unavailable while queuing persist: {}",
                err
            );
        }
    }
}

fn load_snapshot_from_disk(file_path: &PathBuf) -> Result<BTreeSet<String>, String> {
    let raw = if file_path.exists() {
        let content = std::fs::read_to_string(file_path).map_err(|err| {
            format!(
                "Failed to read search failed IDs file {}: {}",
                file_path.display(),
                err
            )
        })?;
        if content.trim().is_empty() {
            None
        } else {
            Some(
                serde_yaml::from_str::<Vec<String>>(&content).map_err(|err| {
                    format!(
                        "Failed to parse search failed IDs file {}: {}",
                        file_path.display(),
                        err
                    )
                })?,
            )
        }
    } else {
        None
    };
    let mut set = BTreeSet::new();
    if let Some(values) = raw {
        for value in values {
            let normalized = value.trim().to_ascii_lowercase();
            if normalized.len() == 16 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
                set.insert(normalized);
            } else {
                warn!(
                    "Ignoring invalid failed search ID entry '{}' in {}",
                    value,
                    file_path.display()
                );
            }
        }
    }
    Ok(set)
}

fn writer_loop(file_path: PathBuf, writer_rx: mpsc::Receiver<WriterCommand>) {
    while let Ok(command) = writer_rx.recv() {
        match command {
            WriterCommand::Persist(snapshot) => {
                if let Err(err) = persist_snapshot(&file_path, &snapshot) {
                    warn!(
                        "Failed to persist search failed IDs file {}: {}",
                        file_path.display(),
                        err
                    );
                }
            }
            WriterCommand::DeleteFile => {
                if let Err(err) = std::fs::remove_file(&file_path)
                    && err.kind() != std::io::ErrorKind::NotFound
                {
                    warn!(
                        "Failed to delete search failed IDs file {}: {}",
                        file_path.display(),
                        err
                    );
                }
            }
        }
    }
}

fn persist_snapshot(file_path: &PathBuf, snapshot: &[String]) -> Result<(), String> {
    let content = serde_yaml::to_string(snapshot)
        .map_err(|err| format!("Failed to serialize search failed IDs: {}", err))?;
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create search failed IDs parent directory {}: {}",
                parent.display(),
                err
            )
        })?;
    }
    let temp_path = file_path.with_extension("yaml.tmp");
    std::fs::write(&temp_path, content).map_err(|err| {
        format!(
            "Failed to write temporary search failed IDs file {}: {}",
            temp_path.display(),
            err
        )
    })?;
    std::fs::rename(&temp_path, file_path).map_err(|err| {
        format!(
            "Failed to replace search failed IDs file {}: {}",
            file_path.display(),
            err
        )
    })?;
    Ok(())
}

fn read_recover<'a, T>(lock: &'a RwLock<T>, context: &str) -> std::sync::RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Search {} lock poisoned; recovering", context);
            poisoned.into_inner()
        }
    }
}

fn write_recover<'a, T>(lock: &'a RwLock<T>, context: &str) -> std::sync::RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Search {} lock poisoned; recovering", context);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FailedIdStore;
    use crate::test_support::TestFixtureRoot;
    use std::time::{Duration, Instant};

    #[test]
    fn failed_id_store_load_persist_and_clear_roundtrip() {
        let fixture = TestFixtureRoot::new_unique("search-failed-id-store").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        let file_path = runtime_paths.state_search_failed_ids_file.clone();
        std::fs::write(&file_path, "- \"0000000000000001\"\n- \"bad-id\"\n").expect("seed file");

        let store = FailedIdStore::new(file_path.clone()).expect("store");
        assert!(store.contains("0000000000000001"));
        assert!(!store.contains("bad-id"));

        store.mark_failed("0000000000000002");
        store.clear_failed("0000000000000001");

        let snapshot = store.snapshot();
        assert_eq!(snapshot, vec!["0000000000000002".to_string()]);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut raw = String::new();
        while Instant::now() < deadline {
            raw = std::fs::read_to_string(&file_path).unwrap_or_default();
            if raw.contains("0000000000000002") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(raw.contains("0000000000000002"));

        store.clear_all_and_delete_file();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if store.snapshot().is_empty() && !file_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(store.snapshot().is_empty());
        assert!(!file_path.exists());
    }
}
