// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::LoginSessionStore;

#[derive(Clone)]
pub struct LoginState {
    pub login_sessions: LoginSessionStore,
}

impl LoginState {
    pub fn new() -> Self {
        Self {
            login_sessions: LoginSessionStore::new(),
        }
    }
}

impl Default for LoginState {
    fn default() -> Self {
        Self::new()
    }
}
