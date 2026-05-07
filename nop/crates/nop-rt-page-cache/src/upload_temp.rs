// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

/// Shared helpers for temporary files created during upload handling.
pub const TEMP_UPLOAD_PREFIX: &str = ".nop-upload-";
pub const TEMP_UPLOAD_SUFFIXES: [&str; 2] = [".upload", ".tmp"];

pub fn is_temp_upload_name(name: &str) -> bool {
    if name.starts_with(TEMP_UPLOAD_PREFIX) {
        return true;
    }
    TEMP_UPLOAD_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
}
