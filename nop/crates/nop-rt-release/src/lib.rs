// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::info;
use std::cmp::max;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Tracks the "Last Big Change" counter exposed via the X-Release header.
/// Self-bumping counter ensures every bump is strictly monotonic even if the
/// system clock does not move between successive updates.
#[derive(Clone)]
pub struct ReleaseTracker {
    counter: Arc<AtomicU64>,
}

impl ReleaseTracker {
    /// Initializes the tracker with the current epoch milliseconds to capture
    /// the moment the process started up.
    pub fn new() -> Self {
        let now = current_epoch_millis();
        Self {
            counter: Arc::new(AtomicU64::new(now)),
        }
    }

    /// Returns the current counter value.
    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Returns the current counter encoded as lowercase hexadecimal.
    pub fn current_hex(&self) -> String {
        format!("{:x}", self.current())
    }

    /// Bumps the counter to the current epoch (or the next integer) and logs the reason.
    pub fn bump(&self, reason: &str) -> u64 {
        let now = current_epoch_millis();
        let mut previous = self.counter.load(Ordering::SeqCst);
        loop {
            let new_value = max(now, previous.saturating_add(1));
            match self.counter.compare_exchange(
                previous,
                new_value,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    info!("🔁 Last Big Change bumped to {} ({})", new_value, reason);
                    return new_value;
                }
                Err(observed) => {
                    previous = observed;
                }
            }
        }
    }
}

impl Default for ReleaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn current_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_else(|_| 0)
}

#[cfg(test)]
mod tests {
    use super::ReleaseTracker;

    #[test]
    fn bump_is_monotonic() {
        let tracker = ReleaseTracker::new();
        let initial = tracker.current();
        let bumped = tracker.bump("test bump");

        assert!(bumped >= initial);
        assert_eq!(tracker.current(), bumped);

        let bumped_again = tracker.bump("test bump again");
        assert!(bumped_again > bumped);
        assert_eq!(tracker.current(), bumped_again);
    }

    #[test]
    fn current_hex_matches_current() {
        let tracker = ReleaseTracker::new();
        let current = tracker.current();
        let hex = tracker.current_hex();

        assert_eq!(hex, format!("{:x}", current));
    }
}
