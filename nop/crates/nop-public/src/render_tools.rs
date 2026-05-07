// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::markdown::HtmlSanitizer;

pub struct RenderTools {
    pub html_sanitizer: HtmlSanitizer,
}

impl RenderTools {
    pub fn new() -> Self {
        Self {
            html_sanitizer: HtmlSanitizer::new(),
        }
    }
}

impl Default for RenderTools {
    fn default() -> Self {
        Self::new()
    }
}
