// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;

#[derive(Debug, Clone)]
pub struct ReservedPaths {
    entries: Vec<ReservedPathEntry>,
}

#[derive(Debug, Clone)]
struct ReservedPathEntry {
    path: String,
    match_prefix: bool,
    alias_block: bool,
    robots_disallow: bool,
}

impl ReservedPaths {
    pub fn from_config(config: &ValidatedConfig) -> Self {
        Self::new(Some(config.admin.path.as_str()))
    }

    pub fn new(admin_path: Option<&str>) -> Self {
        let mut entries = Vec::new();

        entries.push(ReservedPathEntry::exact("robots.txt", true, false));
        entries.push(ReservedPathEntry::exact("sitemap.xml", true, false));
        entries.push(ReservedPathEntry::prefix("id", true, false));
        entries.push(ReservedPathEntry::prefix("login", true, true));
        entries.push(ReservedPathEntry::prefix("builtin", true, true));
        entries.push(ReservedPathEntry::prefix("api", true, true));

        if let Some(admin_path) = normalize_path(admin_path) {
            entries.push(ReservedPathEntry::prefix(&admin_path, true, false));
        }

        Self { entries }
    }

    pub fn alias_is_reserved(&self, alias: &str) -> bool {
        let normalized = normalize_alias(alias);
        if normalized.is_empty() {
            return false;
        }
        self.entries
            .iter()
            .any(|entry| entry.alias_block && entry.matches(&normalized))
    }

    pub fn robots_disallow_rules(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.robots_disallow)
            .map(ReservedPathEntry::robots_rule)
            .collect()
    }
}

impl Default for ReservedPaths {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ReservedPathEntry {
    fn exact(path: &str, alias_block: bool, robots_disallow: bool) -> Self {
        Self {
            path: normalize_path(Some(path)).unwrap_or_default(),
            match_prefix: false,
            alias_block,
            robots_disallow,
        }
    }

    fn prefix(path: &str, alias_block: bool, robots_disallow: bool) -> Self {
        Self {
            path: normalize_path(Some(path)).unwrap_or_default(),
            match_prefix: true,
            alias_block,
            robots_disallow,
        }
    }

    fn matches(&self, alias: &str) -> bool {
        if self.path.is_empty() {
            return false;
        }
        if self.match_prefix {
            alias == self.path || alias.starts_with(&format!("{}/", self.path))
        } else {
            alias == self.path
        }
    }

    fn robots_rule(&self) -> String {
        if self.match_prefix {
            format!("/{}/", self.path)
        } else {
            format!("/{}", self.path)
        }
    }
}

fn normalize_alias(alias: &str) -> String {
    alias.trim().trim_start_matches('/').to_ascii_lowercase()
}

fn normalize_path(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_reserved_matches_prefixes_and_exact_paths() {
        let reserved = ReservedPaths::new(Some("/admin"));

        assert!(reserved.alias_is_reserved("login"));
        assert!(reserved.alias_is_reserved("login/reset"));
        assert!(reserved.alias_is_reserved("builtin/app.css"));
        assert!(reserved.alias_is_reserved("api/v1"));
        assert!(reserved.alias_is_reserved("robots.txt"));
        assert!(reserved.alias_is_reserved("sitemap.xml"));
        assert!(reserved.alias_is_reserved("admin"));
        assert!(reserved.alias_is_reserved("admin/users"));

        assert!(!reserved.alias_is_reserved("docs/intro"));
        assert!(!reserved.alias_is_reserved("robots.txt/extra"));
    }

    #[test]
    fn robots_rules_exclude_admin_and_files() {
        let reserved = ReservedPaths::new(Some("/admin"));
        let rules = reserved.robots_disallow_rules();

        assert!(rules.contains(&"/login/".to_string()));
        assert!(rules.contains(&"/api/".to_string()));
        assert!(rules.contains(&"/builtin/".to_string()));
        assert!(!rules.iter().any(|rule| rule.contains("admin")));
        assert!(!rules.iter().any(|rule| rule.contains("robots.txt")));
        assert!(!rules.iter().any(|rule| rule.contains("sitemap.xml")));
    }
}
