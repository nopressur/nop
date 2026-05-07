// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use minijinja::context;
use nop_content_store::flat_storage::{content_id_hex, parse_content_id_hex};
use nop_rt_iam::types::User;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_templates::{TemplateEngine, render_minijinja_template};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct NavItem {
    pub title: String,
    pub path: String,
    pub children: Vec<NavItem>,
}

const HOME_ALIAS: &str = "index";

pub fn generate_navigation_with_user(
    cache: &PageMetaCache,
    user: Option<&User>,
    max_dropdown_items: usize,
) -> Vec<NavItem> {
    let mut nodes = HashMap::new();
    let mut roots = Vec::new();

    for object in cache.list_nav_objects() {
        let route_alias = object_route_alias(&object);
        let user_roles = user.map(|user| user.roles.as_slice());
        if !cache
            .user_has_access(&route_alias, user_roles)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(title) = object.nav_title.clone() else {
            continue;
        };
        let nav_parent_id = object
            .nav_parent_id
            .as_ref()
            .and_then(|value| parse_content_id_hex(value).ok());
        nodes.insert(
            object.key.id,
            NavNode {
                parent_id: nav_parent_id,
                title,
                path: nav_path_for_alias(&route_alias),
                order: object.nav_order.unwrap_or(0),
                alias: route_alias,
                children: Vec::new(),
            },
        );
    }

    let node_ids: Vec<_> = nodes.keys().cloned().collect();
    for node_id in node_ids {
        let parent_id = nodes.get(&node_id).and_then(|node| node.parent_id);
        if let Some(parent_id) = parent_id
            && let Some(parent) = nodes.get_mut(&parent_id)
        {
            parent.children.push(node_id);
            continue;
        }
        roots.push(node_id);
    }

    sort_nav_ids(&mut roots, &nodes);
    roots
        .into_iter()
        .filter_map(|node_id| build_nav_item(node_id, &nodes, max_dropdown_items))
        .collect()
}

pub fn generate_navigation_html(
    navigation: &[NavItem],
    template_engine: &dyn TemplateEngine,
) -> String {
    let context = context! {
        navigation => navigation
    };

    match render_minijinja_template(template_engine, "public/nav.html", context) {
        Ok(html) => html,
        Err(err) => {
            log::error!("Failed to render navigation template: {}", err);
            String::new()
        }
    }
}

#[derive(Debug, Clone)]
struct NavNode {
    parent_id: Option<nop_content_store::flat_storage::ContentId>,
    title: String,
    path: String,
    order: i32,
    alias: String,
    children: Vec<nop_content_store::flat_storage::ContentId>,
}

fn sort_nav_ids(
    ids: &mut [nop_content_store::flat_storage::ContentId],
    nodes: &HashMap<nop_content_store::flat_storage::ContentId, NavNode>,
) {
    ids.sort_by(|left, right| {
        let left_node = nodes.get(left);
        let right_node = nodes.get(right);
        match (left_node, right_node) {
            (Some(left_node), Some(right_node)) => {
                let left_title = left_node.title.to_lowercase();
                let right_title = right_node.title.to_lowercase();
                left_node
                    .order
                    .cmp(&right_node.order)
                    .then_with(|| left_title.cmp(&right_title))
                    .then_with(|| left_node.alias.cmp(&right_node.alias))
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
}

fn build_nav_item(
    node_id: nop_content_store::flat_storage::ContentId,
    nodes: &HashMap<nop_content_store::flat_storage::ContentId, NavNode>,
    max_dropdown_items: usize,
) -> Option<NavItem> {
    let node = match nodes.get(&node_id) {
        Some(node) => node,
        None => {
            log::warn!(
                "Navigation node missing for content id {}",
                content_id_hex(node_id)
            );
            return None;
        }
    };
    let mut children = node.children.clone();
    sort_nav_ids(&mut children, nodes);
    if max_dropdown_items > 0 && children.len() > max_dropdown_items {
        children.truncate(max_dropdown_items);
    }
    Some(NavItem {
        title: node.title.clone(),
        path: node.path.clone(),
        children: children
            .into_iter()
            .filter_map(|child_id| build_nav_item(child_id, nodes, max_dropdown_items))
            .collect(),
    })
}

fn nav_path_for_alias(alias: &str) -> String {
    if alias == HOME_ALIAS {
        "/".to_string()
    } else {
        format!("/{}", alias)
    }
}

fn object_route_alias(object: &nop_rt_page_cache::CachedObject) -> String {
    if object.alias.trim().is_empty() {
        format!("id/{}", content_id_hex(object.key.id))
    } else {
        object.alias.clone()
    }
}

pub fn html_escape(input: &str) -> String {
    let mut escaped = String::new();
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_content_store::flat_storage::ContentId;
    use nop_rt_templates::MiniJinjaEngine;

    #[test]
    fn navigation_titles_are_escaped() {
        let items = vec![NavItem {
            title: "<script>alert(1)</script>".to_string(),
            path: "/danger".to_string(),
            children: Vec::new(),
        }];
        let templates = MiniJinjaEngine::new();
        let html = generate_navigation_html(&items, &templates);

        assert!(html.contains("&lt;script&gt;alert(1)&lt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn build_nav_item_skips_missing_children() {
        let parent_id = ContentId(1);
        let missing_child = ContentId(2);
        let mut nodes = HashMap::new();
        nodes.insert(
            parent_id,
            NavNode {
                parent_id: None,
                title: "Root".to_string(),
                path: "/".to_string(),
                order: 0,
                alias: "index".to_string(),
                children: vec![missing_child],
            },
        );

        let item = build_nav_item(parent_id, &nodes, 0).expect("nav item");

        assert!(item.children.is_empty());
    }

    #[test]
    fn build_nav_item_returns_none_for_missing_node() {
        let nodes = HashMap::new();

        assert!(build_nav_item(ContentId(99), &nodes, 0).is_none());
    }

    #[test]
    fn sort_nav_ids_orders_by_title_when_order_matches() {
        let alpha = ContentId(1);
        let beta = ContentId(2);
        let charlie = ContentId(3);
        let mut nodes = HashMap::new();
        nodes.insert(
            alpha,
            NavNode {
                parent_id: None,
                title: "Alpha".to_string(),
                path: "/alpha".to_string(),
                order: 0,
                alias: "alpha".to_string(),
                children: Vec::new(),
            },
        );
        nodes.insert(
            beta,
            NavNode {
                parent_id: None,
                title: "beta".to_string(),
                path: "/beta".to_string(),
                order: 0,
                alias: "beta".to_string(),
                children: Vec::new(),
            },
        );
        nodes.insert(
            charlie,
            NavNode {
                parent_id: None,
                title: "Charlie".to_string(),
                path: "/charlie".to_string(),
                order: 0,
                alias: "charlie".to_string(),
                children: Vec::new(),
            },
        );
        let mut ids = vec![charlie, beta, alpha];

        sort_nav_ids(&mut ids, &nodes);

        assert_eq!(ids, vec![alpha, beta, charlie]);
    }
}
