// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::collections::HashMap;

/// Page-local structure derived from selected Markdown heading events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocumentStructure {
    pub entries: Vec<DocumentStructureEntry>,
    /// Label of the leading Markdown heading when it sits above the first
    /// display level (page title or preamble heading). Used as the "go to top"
    /// entry text; the scroll target is always the absolute page top.
    pub title: Option<String>,
}

impl DocumentStructure {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One linkable document-structure entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentStructureEntry {
    pub id: String,
    pub label: String,
    pub level: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MarkdownHeading {
    pub rank: u8,
    pub label: String,
    pub anchor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeadingDraft {
    pub rank: u8,
    pub label: String,
}

pub(crate) fn assign_heading_anchor_ids(drafts: Vec<HeadingDraft>) -> Vec<MarkdownHeading> {
    let mut used_ids = HashMap::new();

    drafts
        .into_iter()
        .map(|heading| MarkdownHeading {
            rank: heading.rank,
            anchor_id: unique_anchor_id(&heading.label, &mut used_ids),
            label: heading.label,
        })
        .collect()
}

pub(crate) fn select_document_structure(headings: &[MarkdownHeading]) -> DocumentStructure {
    let Some(first_rank) = first_display_rank(headings) else {
        return DocumentStructure::default();
    };
    let second_rank = second_display_rank(headings, first_rank);
    let title = match headings.first() {
        Some(first) if first.rank < first_rank => Some(first.label.clone()),
        _ => None,
    };

    let mut saw_first_level = false;
    let mut entries = Vec::new();

    for heading in headings {
        let level = if heading.rank == first_rank {
            saw_first_level = true;
            Some(1)
        } else if Some(heading.rank) == second_rank {
            if saw_first_level { Some(2) } else { Some(1) }
        } else {
            None
        };

        if let Some(level) = level {
            entries.push(DocumentStructureEntry {
                id: heading.anchor_id.clone(),
                label: heading.label.clone(),
                level,
            });
        }
    }

    DocumentStructure { entries, title }
}

fn first_display_rank(headings: &[MarkdownHeading]) -> Option<u8> {
    let counts = heading_rank_counts(headings);
    (1..=6).find(|rank| counts[*rank as usize] > 1)
}

fn second_display_rank(headings: &[MarkdownHeading], first_rank: u8) -> Option<u8> {
    let counts = heading_rank_counts(headings);
    ((first_rank + 1)..=6).find(|rank| counts[*rank as usize] > 0)
}

fn heading_rank_counts(headings: &[MarkdownHeading]) -> [usize; 7] {
    let mut counts = [0usize; 7];
    for heading in headings {
        counts[heading.rank as usize] += 1;
    }
    counts
}

fn unique_anchor_id(label: &str, used_ids: &mut HashMap<String, usize>) -> String {
    let base = anchor_base(label);
    let count = used_ids.entry(base.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        base
    } else {
        format!("{}-{}", base, count)
    }
}

fn anchor_base(label: &str) -> String {
    let mut out = String::new();
    let mut previous_was_separator = false;

    for ch in label.chars().flat_map(|ch| ch.to_lowercase()) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            previous_was_separator = false;
        } else if !previous_was_separator && !out.is_empty() {
            out.push('-');
            previous_was_separator = true;
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    if out.is_empty() {
        "section".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heading(rank: u8, label: &str) -> HeadingDraft {
        HeadingDraft {
            rank,
            label: label.to_string(),
        }
    }

    fn selection(headings: Vec<HeadingDraft>) -> DocumentStructure {
        let headings = assign_heading_anchor_ids(headings);
        select_document_structure(&headings)
    }

    fn entry_labels_and_levels(headings: Vec<HeadingDraft>) -> Vec<(String, u8)> {
        selection(headings)
            .entries
            .into_iter()
            .map(|entry| (entry.label, entry.level))
            .collect()
    }

    #[test]
    fn no_repeated_heading_rank_disables_structure() {
        let selected = selection(vec![
            heading(1, "Title"),
            heading(2, "One"),
            heading(3, "Detail"),
        ]);

        assert!(selected.is_empty());
    }

    #[test]
    fn leading_single_h1_is_kept_as_top_title() {
        let selected = selection(vec![
            heading(1, "Title"),
            heading(2, "One"),
            heading(2, "Two"),
        ]);

        assert_eq!(selected.title, Some("Title".to_string()));
        assert!(!selected.is_empty());
    }

    #[test]
    fn leading_included_heading_keeps_no_top_title() {
        let without_h1 = selection(vec![heading(2, "One"), heading(2, "Two")]);
        assert_eq!(without_h1.title, None);

        let repeated_h1 = selection(vec![heading(1, "One"), heading(2, "A"), heading(1, "Two")]);
        assert_eq!(repeated_h1.title, None);
    }

    #[test]
    fn no_h1_with_multiple_h2_headings_displays_h2() {
        assert_eq!(
            entry_labels_and_levels(vec![heading(2, "One"), heading(2, "Two")]),
            vec![("One".to_string(), 1), ("Two".to_string(), 1)]
        );
    }

    #[test]
    fn single_h1_plus_multiple_h2_and_h3_displays_h2_h3() {
        assert_eq!(
            entry_labels_and_levels(vec![
                heading(1, "Title"),
                heading(2, "One"),
                heading(3, "Detail"),
                heading(2, "Two"),
            ]),
            vec![
                ("One".to_string(), 1),
                ("Detail".to_string(), 2),
                ("Two".to_string(), 1),
            ]
        );
    }

    #[test]
    fn multiple_h1_displays_h1_plus_next_deeper_rank() {
        assert_eq!(
            entry_labels_and_levels(vec![
                heading(1, "One"),
                heading(2, "A"),
                heading(1, "Two"),
                heading(3, "Ignored"),
            ]),
            vec![
                ("One".to_string(), 1),
                ("A".to_string(), 2),
                ("Two".to_string(), 1),
            ]
        );
    }

    #[test]
    fn skipped_rank_selects_first_repeated_and_next_deeper_present_rank() {
        assert_eq!(
            entry_labels_and_levels(vec![
                heading(1, "Title"),
                heading(3, "One"),
                heading(4, "Detail"),
                heading(3, "Two"),
            ]),
            vec![
                ("One".to_string(), 1),
                ("Detail".to_string(), 2),
                ("Two".to_string(), 1),
            ]
        );
    }

    #[test]
    fn orphan_lower_rank_renders_as_first_level_entry() {
        assert_eq!(
            entry_labels_and_levels(vec![
                heading(3, "Orphan"),
                heading(2, "One"),
                heading(3, "Detail"),
                heading(2, "Two"),
            ]),
            vec![
                ("Orphan".to_string(), 1),
                ("One".to_string(), 1),
                ("Detail".to_string(), 2),
                ("Two".to_string(), 1),
            ]
        );
    }

    #[test]
    fn duplicate_heading_ids_are_stable_and_suffixed() {
        let selected = selection(vec![
            heading(2, "Repeat!"),
            heading(2, "Repeat"),
            heading(3, "Child"),
            heading(3, "Child"),
        ]);

        let ids: Vec<_> = selected.entries.into_iter().map(|entry| entry.id).collect();
        assert_eq!(ids, vec!["repeat", "repeat-2", "child", "child-2"]);
    }

    #[test]
    fn anchor_ids_are_assigned_before_structure_selection() {
        let headings = assign_heading_anchor_ids(vec![
            heading(1, "Repeat"),
            heading(2, "Repeat"),
            heading(2, "Repeat"),
        ]);

        assert_eq!(
            headings
                .into_iter()
                .map(|heading| heading.anchor_id)
                .collect::<Vec<_>>(),
            vec!["repeat", "repeat-2", "repeat-3"]
        );
    }

    #[test]
    fn heading_labels_are_plain_text() {
        assert_eq!(
            entry_labels_and_levels(vec![
                heading(2, "Use code & text"),
                heading(2, "Second shown"),
            ]),
            vec![
                ("Use code & text".to_string(), 1),
                ("Second shown".to_string(), 1),
            ]
        );
    }
}
