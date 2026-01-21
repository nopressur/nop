// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::public::nav::html_escape;

#[derive(Debug)]
pub(crate) struct DirectoryItem {
    pub(crate) title: String,
    pub(crate) path: String,
    pub(crate) is_directory: bool,
}

#[derive(Debug)]
pub(super) struct Breadcrumb {
    pub(super) title: String,
    pub(super) path: String,
}

pub(crate) fn generate_tag_listing_html(title: &str, items: &[DirectoryItem]) -> String {
    generate_directory_listing_html(title, items, &[])
}

pub(super) fn generate_directory_listing_html(
    title: &str,
    items: &[DirectoryItem],
    breadcrumbs: &[Breadcrumb],
) -> String {
    let mut html = String::new();

    if !breadcrumbs.is_empty() {
        html.push_str("<nav class=\"breadcrumb has-arrow-separator\" aria-label=\"breadcrumbs\">");
        html.push_str("<ul>");
        for breadcrumb in breadcrumbs {
            html.push_str("<li");
            if breadcrumb.path.is_empty() {
                html.push_str(" class=\"is-active\"");
            }
            html.push('>');

            if breadcrumb.path.is_empty() {
                html.push_str("<span>");
                html.push_str(&html_escape(&breadcrumb.title));
                html.push_str("</span>");
            } else {
                html.push_str("<a href=\"");
                html.push_str(&html_escape(&breadcrumb.path));
                html.push_str("\">");
                html.push_str(&html_escape(&breadcrumb.title));
                html.push_str("</a>");
            }
            html.push_str("</li>");
        }
        html.push_str("</ul>");
        html.push_str("</nav>");
    }

    html.push_str("<h1 class=\"title\">");
    html.push_str(&html_escape(title));
    html.push_str("</h1>");

    if items.is_empty() {
        html.push_str("<p class=\"has-text-grey\">No content found.</p>");
        return html;
    }

    let directories: Vec<&DirectoryItem> = items.iter().filter(|item| item.is_directory).collect();
    let files: Vec<&DirectoryItem> = items.iter().filter(|item| !item.is_directory).collect();

    if !directories.is_empty() {
        html.push_str("<h2 class=\"subtitle\">📁 Directories</h2>");
        html.push_str("<div class=\"columns is-multiline\">");
        for dir in directories {
            html.push_str("<div class=\"column is-half\">");
            html.push_str("<div class=\"box\">");
            html.push_str("<p class=\"title is-6\">");
            html.push_str("<a href=\"");
            html.push_str(&html_escape(&dir.path));
            html.push_str("\">");
            html.push_str("📁 ");
            html.push_str(&html_escape(&dir.title));
            html.push_str("</a>");
            html.push_str("</p>");
            html.push_str("</div>");
            html.push_str("</div>");
        }
        html.push_str("</div>");
    }

    if !files.is_empty() {
        html.push_str("<h2 class=\"subtitle\">📄 Pages</h2>");
        html.push_str("<div class=\"columns is-multiline\">");
        for file in files {
            html.push_str("<div class=\"column is-half\">");
            html.push_str("<div class=\"box\">");
            html.push_str("<p class=\"title is-6\">");
            html.push_str("<a href=\"");
            html.push_str(&html_escape(&file.path));
            html.push_str("\">");
            html.push_str("📄 ");
            html.push_str(&html_escape(&file.title));
            html.push_str("</a>");
            html.push_str("</p>");
            html.push_str("</div>");
            html.push_str("</div>");
        }
        html.push_str("</div>");
    }

    html
}
