// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::wire::{WireError, WireResult};

#[derive(Debug, Default)]
pub struct WorkflowCounter {
    next_id: u32,
}

impl WorkflowCounter {
    pub fn new() -> Self {
        Self { next_id: 1 }
    }

    pub fn next_id(&mut self) -> WireResult<u32> {
        if self.next_id == 0 {
            return Err(WireError::new("Workflow counter wrapped"));
        }
        if self.next_id == u32::MAX {
            return Err(WireError::new("Workflow counter exhausted"));
        }
        let id = self.next_id;
        self.next_id += 1;
        Ok(id)
    }
}

#[derive(Debug, Default)]
pub struct WorkflowTracker {
    last_id: u32,
}

impl WorkflowTracker {
    pub fn new() -> Self {
        Self { last_id: 0 }
    }

    pub fn accept(&mut self, workflow_id: u32) -> WireResult<()> {
        if workflow_id == 0 {
            return Err(WireError::new("Workflow ID must be non-zero"));
        }
        if workflow_id <= self.last_id {
            return Err(WireError::new("Workflow ID must be strictly increasing"));
        }
        self.last_id = workflow_id;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_counter_is_monotonic() {
        let mut counter = WorkflowCounter::new();
        assert_eq!(counter.next_id().unwrap(), 1);
        assert_eq!(counter.next_id().unwrap(), 2);
    }

    #[test]
    fn workflow_counter_rejects_exhaustion() {
        let mut counter = WorkflowCounter { next_id: u32::MAX };
        let err = counter.next_id().unwrap_err();
        assert!(err.to_string().contains("exhausted"));
    }

    #[test]
    fn workflow_tracker_rejects_zero_and_reuse() {
        let mut tracker = WorkflowTracker::new();
        assert!(tracker.accept(0).is_err());
        tracker.accept(1).expect("accept 1");
        assert!(tracker.accept(1).is_err());
    }
}
