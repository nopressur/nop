// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use ammonia;

pub struct HtmlSanitizer {
    cleaner: ammonia::Builder<'static>,
}

impl HtmlSanitizer {
    pub fn new() -> Self {
        let mut cleaner = ammonia::Builder::default();
        cleaner
            .strip_comments(true)
            .add_tags(&["span", "figure", "figcaption"])
            .link_rel(Some("noopener noreferrer"))
            .rm_tags(&["script", "link", "iframe", "object", "embed"]);
        Self { cleaner }
    }

    pub fn clean(&self, html: &str) -> String {
        self.cleaner.clean(html).to_string()
    }
}

impl Default for HtmlSanitizer {
    fn default() -> Self {
        Self::new()
    }
}
