// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::errors::ManagementErrorKind;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const DEFAULT_BLOCKING_WORKERS: usize = 2;
const DEFAULT_OVERFLOW_WORKERS: usize = 1;

#[derive(Debug)]
pub struct BlockingError {
    context: &'static str,
    message: String,
    kind: ManagementErrorKind,
}

impl BlockingError {
    pub fn kind(&self) -> ManagementErrorKind {
        self.kind
    }
}

impl fmt::Display for BlockingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.message)
    }
}

impl Error for BlockingError {}

#[derive(Clone)]
pub struct BlockingPool {
    blocking: Arc<Semaphore>,
    overflow: Arc<Semaphore>,
}

impl BlockingPool {
    pub fn new(blocking_workers: usize, overflow_workers: usize) -> Self {
        Self {
            blocking: Arc::new(Semaphore::new(blocking_workers)),
            overflow: Arc::new(Semaphore::new(overflow_workers)),
        }
    }

    pub fn default_pool() -> Self {
        Self::new(DEFAULT_BLOCKING_WORKERS, DEFAULT_OVERFLOW_WORKERS)
    }

    pub async fn run_blocking<F, R>(
        &self,
        context: &'static str,
        task: F,
    ) -> Result<R, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let permit = match self.blocking.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => match self.overflow.clone().try_acquire_owned() {
                Ok(permit) => {
                    log::warn!(
                        "Blocking pool overflow used for {} (pool saturated)",
                        context
                    );
                    permit
                }
                Err(_) => {
                    return Err(BlockingError {
                        context,
                        message: "blocking pool saturated".to_string(),
                        kind: ManagementErrorKind::Busy,
                    });
                }
            },
        };

        Self::spawn_with_permit(context, permit, task).await
    }

    async fn spawn_with_permit<F, R>(
        context: &'static str,
        _permit: OwnedSemaphorePermit,
        task: F,
    ) -> Result<R, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        tokio::task::spawn_blocking(task)
            .await
            .map_err(|err| BlockingError {
                context,
                message: format!("blocking task failed: {}", err),
                kind: ManagementErrorKind::Internal,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocking_pool_returns_busy_when_saturated() {
        let pool = BlockingPool::new(1, 0);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (hold_tx, hold_rx) = std::sync::mpsc::channel();
        let pool_clone = pool.clone();

        let hold_task = tokio::spawn(async move {
            pool_clone
                .run_blocking("hold", move || {
                    let _ = ready_tx.send(());
                    let _ = hold_rx.recv();
                })
                .await
        });

        ready_rx.await.expect("ready signal");
        let err = pool
            .run_blocking("second", || {})
            .await
            .expect_err("expected busy error");
        assert_eq!(err.kind(), ManagementErrorKind::Busy);

        let _ = hold_tx.send(());
        let result = hold_task.await.expect("join ok");
        assert!(result.is_ok());
    }
}
