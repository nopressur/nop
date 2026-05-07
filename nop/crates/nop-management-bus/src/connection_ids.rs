// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_CONNECTION_ID: AtomicU32 = AtomicU32::new(1);

pub fn next_connection_id() -> u32 {
    let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_is_non_zero() {
        let id = next_connection_id();
        assert_ne!(id, 0);
    }
}
