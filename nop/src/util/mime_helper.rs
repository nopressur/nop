// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::path::Path;

/// Detect MIME type using content-based detection (infer) with fallback to extension-based (mime_guess)
pub fn detect_mime_type(file_path: &Path, file_content: &[u8]) -> String {
    // First try content-based detection
    if let Some(mime_type) = infer::get(file_content) {
        return mime_type.mime_type().to_string();
    }

    // Fallback to extension-based detection
    let mime_guess = mime_guess::from_path(file_path);
    if let Some(mime_type) = mime_guess.first() {
        return mime_type.to_string();
    }

    // Final fallback
    "application/octet-stream".to_string()
}

// Additional MIME helpers moved to sidecar metadata in the flat storage model.
