// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

//! Single cross-process lock arbitrating daemon lifetime against CLI bypass.
//!
//! Exactly one side holds the lock for a runtime root at a time: the daemon
//! holds it from startup until exit, and each CLI bypass invocation holds it
//! for the duration of the bypass. The CLI socket path never touches the lock.
//! The lock complements the existing detections (pid file, socket probe); it
//! does not replace them.

use fs2::FileExt;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const RUNTIME_LOCK_FILE_NAME: &str = "runtime.lock";
const LOCK_WAIT_INTERVAL: Duration = Duration::from_millis(50);

/// Exclusive hold on a runtime root. Dropping releases the lock; the lock is
/// also released automatically if the holder process dies.
pub struct RuntimeLock {
    path: PathBuf,
    _file: File,
}

impl RuntimeLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub enum RuntimeLockError {
    /// Another process holds the lock right now.
    Held {
        path: PathBuf,
    },
    /// The lock was still held when the wait budget ran out.
    Timeout {
        path: PathBuf,
        waited: Duration,
    },
    Io(io::Error),
}

impl fmt::Display for RuntimeLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeLockError::Held { path } => write!(
                f,
                "runtime root is locked by another process (another daemon or an active nop command): {}",
                path.display()
            ),
            RuntimeLockError::Timeout { path, waited } => write!(
                f,
                "timed out after {}s waiting for the runtime lock at {} (another nop command or the daemon holds it)",
                waited.as_secs(),
                path.display()
            ),
            RuntimeLockError::Io(err) => write!(f, "runtime lock I/O error: {}", err),
        }
    }
}

impl std::error::Error for RuntimeLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuntimeLockError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for RuntimeLockError {
    fn from(err: io::Error) -> Self {
        RuntimeLockError::Io(err)
    }
}

pub fn runtime_lock_path(runtime_root: &Path) -> PathBuf {
    let root = if runtime_root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        runtime_root.to_path_buf()
    };
    root.join("state").join("sys").join(RUNTIME_LOCK_FILE_NAME)
}

/// Try once to lock the runtime root. Used by the daemon at startup: it must
/// fail fast when another process works on the tree.
pub fn try_acquire_runtime_lock(runtime_root: &Path) -> Result<RuntimeLock, RuntimeLockError> {
    let path = runtime_lock_path(runtime_root);
    let file = open_lock_file(&path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(RuntimeLock { path, _file: file }),
        Err(err) if is_lock_contention(&err) => Err(RuntimeLockError::Held { path }),
        Err(err) => Err(RuntimeLockError::Io(err)),
    }
}

/// Wait up to `timeout` for the runtime lock. Used by CLI bypass so concurrent
/// offline commands queue instead of failing. Only non-blocking lock attempts
/// are used, so this is safe to call from async code.
pub async fn acquire_runtime_lock_wait(
    runtime_root: &Path,
    timeout: Duration,
) -> Result<RuntimeLock, RuntimeLockError> {
    let path = runtime_lock_path(runtime_root);
    let file = open_lock_file(&path)?;
    let started = Instant::now();
    let mut announced = false;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(RuntimeLock { path, _file: file }),
            Err(err) if !is_lock_contention(&err) => return Err(RuntimeLockError::Io(err)),
            Err(_) => {
                if started.elapsed() >= timeout {
                    return Err(RuntimeLockError::Timeout {
                        path,
                        waited: started.elapsed(),
                    });
                }
                if !announced {
                    announced = true;
                    eprintln!(
                        "[runtime-lock] waiting for runtime lock at {} ...",
                        path.display()
                    );
                }
                tokio::time::sleep(LOCK_WAIT_INTERVAL).await;
            }
        }
    }
}

fn open_lock_file(path: &Path) -> Result<File, RuntimeLockError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?)
}

fn is_lock_contention(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_testing::test_fixtures::TestFixtureRoot;

    #[tokio::test]
    async fn lock_acquire_release_reacquire() {
        let fixture = TestFixtureRoot::new_unique("runtime-lock").unwrap();
        let root = fixture.path();

        let lock = try_acquire_runtime_lock(root).expect("acquire");
        assert_eq!(lock.path(), runtime_lock_path(root));
        assert!(lock.path().exists());
        drop(lock);

        try_acquire_runtime_lock(root).expect("reacquire after release");
    }

    #[tokio::test]
    async fn lock_wait_succeeds_when_free() {
        let fixture = TestFixtureRoot::new_unique("runtime-lock-wait").unwrap();
        let root = fixture.path();

        acquire_runtime_lock_wait(root, Duration::from_secs(5))
            .await
            .expect("wait-acquire on free lock");
    }

    #[tokio::test]
    async fn lock_creates_parent_dirs() {
        let fixture = TestFixtureRoot::new_unique("runtime-lock-dirs").unwrap();
        let root = fixture.path().join("nested").join("root");

        let lock = try_acquire_runtime_lock(&root).expect("acquire");
        assert!(lock.path().exists());
    }

    // Same-process lock contention cannot be tested with flock: locks are
    // per-process, so a second acquire from this process would succeed.
    // Cross-process contention is covered by CLI e2e tests instead.
}
