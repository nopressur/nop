// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::PageRenderContext;
use crate::markdown::{DocumentStructure, PageRenderState};
use crate::nav::NavItem;
use minijinja::{Value, context};
use nop_rt_templates::{load_template, render_minijinja_template, render_template};

use super::theme::load_theme_content;

const USER_MENU_PLACEHOLDER: &str = r#"<div data-site-user-menu></div>"#;

pub async fn generate_html_page_with_user(
    title: &str,
    content: &str,
    navigation: &[NavItem],
    render_state: &PageRenderState,
    content_id_hex: &str,
    render_ctx: &PageRenderContext<'_>,
) -> String {
    // Load theme content
    let release_hex = render_ctx.release_tracker.current_hex();
    let theme_content =
        load_theme_content(render_ctx.runtime_paths, render_ctx.theme, &release_hex).await;

    let navbar_html = if render_state.disable_navbar {
        String::new()
    } else {
        generate_navbar_html(navigation, content_id_hex, render_ctx)
    };
    let structure_available =
        !render_state.disable_floating_nav && !render_state.document_structure.is_empty();
    let doc_structure_html = if !structure_available || render_state.has_hero {
        String::new()
    } else {
        generate_document_structure_panel_html(&render_state.document_structure)
    };
    // Load template
    let template = load_template("public/main_layout").unwrap_or_else(|_| {
        // Fallback template if loading fails
        r#"<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body><div>{content}</div></body></html>"#
            .to_string()
    });

    // Prepare template variables
    let website_title = render_ctx.runtime_settings.title();
    let escaped_title = compose_html_title(title, website_title.as_deref());
    let website_name = render_ctx.runtime_settings.name();
    let escaped_app_name = crate::nav::html_escape(&website_name);
    let topbar_html = if navbar_html.is_empty() {
        String::new()
    } else {
        generate_topbar_html(&escaped_app_name, structure_available)
    };
    let menu_drawer_html = if navbar_html.is_empty() {
        String::new()
    } else {
        generate_menu_drawer_html(navigation, &escaped_app_name)
    };
    let structure_drawer_html = if !structure_available {
        String::new()
    } else {
        generate_structure_drawer_html(&render_state.document_structure, &escaped_app_name)
    };
    let description_meta = render_ctx
        .runtime_settings
        .description()
        .map(|description| {
            format!(
                r#"<meta name="description" content="{}">"#,
                crate::nav::html_escape(&description)
            )
        })
        .unwrap_or_default();
    let bulma_href = format!("/builtin/bulma.min.css?v={}", release_hex);
    let favicon_href = "/favicon.ico".to_string();
    let site_src = format!("/builtin/site.js?v={}", release_hex);
    let doc_layout_class = if render_state.use_compact_width {
        "doc-layout"
    } else {
        "doc-layout doc-layout--wide"
    };
    let page_footer = generate_page_footer(render_ctx);

    let vars = nop_rt_templates::template_vars! {
        "title" => &escaped_title,
        "description_meta" => &description_meta,
        "content" => content,
        "theme_content" => &theme_content,
        "navbar_html" => &navbar_html,
        "doc_structure_html" => &doc_structure_html,
        "topbar_html" => &topbar_html,
        "menu_drawer_html" => &menu_drawer_html,
        "structure_drawer_html" => &structure_drawer_html,
        "app_name" => &escaped_app_name,
        "bulma_css" => &bulma_href,
        "favicon_ico" => &favicon_href,
        "site_js" => &site_src,
        "doc_layout_class" => &doc_layout_class,
        "page_footer" => &page_footer,
        "content_id" => content_id_hex,
    };

    render_template(&template, &vars)
}

fn generate_page_footer(render_ctx: &PageRenderContext<'_>) -> String {
    let reload_link = r#"<a href="" data-site-asset-reload>reload</a>"#;
    if render_ctx.show_admin_version_footer {
        format!(
            r#"<footer class="site-page-footer" data-site-page-footer><span data-site-admin-version>NoPressure {}</span> · {reload_link}</footer>"#,
            crate::nav::html_escape(render_ctx.app_version)
        )
    } else {
        format!(r#"<footer class="site-page-footer" data-site-page-footer>{reload_link}</footer>"#)
    }
}

pub(crate) fn compose_html_title(page_title: &str, website_title: Option<&str>) -> String {
    let escaped_page_title = crate::nav::html_escape(page_title);
    let Some(website_title) = website_title else {
        return escaped_page_title;
    };
    let website_title = website_title.trim();
    if website_title.is_empty() {
        return escaped_page_title;
    }
    format!(
        "{} | {}",
        escaped_page_title,
        crate::nav::html_escape(website_title)
    )
}

fn generate_navbar_html(
    navigation: &[NavItem],
    content_id_hex: &str,
    render_ctx: &PageRenderContext<'_>,
) -> String {
    let nav_html = crate::nav::generate_navigation_html(navigation, render_ctx.template_engine);
    let user_nav_html = generate_user_navigation_placeholder();
    let context = context! {
        nav_html => Value::from_safe_string(nav_html),
        user_nav_html => Value::from_safe_string(user_nav_html),
        app_name => render_ctx.runtime_settings.name(),
        content_id => content_id_hex,
    };
    match render_minijinja_template(
        render_ctx.template_engine,
        "public/navbar_layout.html",
        context,
    ) {
        Ok(html) => html,
        Err(error) => {
            log::error!("Failed to render navbar layout template: {}", error);
            String::new()
        }
    }
}

fn generate_user_navigation_placeholder() -> String {
    USER_MENU_PLACEHOLDER.to_string()
}

const TOP_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="4" x2="19" y2="4"/><polyline points="6 14 12 8 18 14"/></svg>"#;
const BOTTOM_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 10 12 16 18 10"/><line x1="5" y1="20" x2="19" y2="20"/></svg>"#;

fn generate_document_structure_panel_html(document_structure: &DocumentStructure) -> String {
    if document_structure.is_empty() {
        return String::new();
    }

    let mut html = String::new();
    html.push_str(
        r#"<aside class="site-doc-structure" data-site-doc-structure aria-label="Document structure">"#,
    );
    html.push_str(r#"<nav class="site-doc-structure__nav"><ol class="site-doc-structure__list">"#);
    push_document_structure_list(&mut html, document_structure);
    html.push_str("</ol></nav></aside>");
    html
}

fn push_document_structure_list(html: &mut String, document_structure: &DocumentStructure) {
    push_document_structure_top_entry(html, document_structure);
    push_document_structure_entries(html, document_structure);
    html.push_str(&format!(
        r#"<li class="site-doc-structure__entry site-doc-structure__entry--bottom"><button type="button" class="site-doc-structure__link site-doc-structure__bottom" data-site-doc-structure-bottom aria-label="Go to bottom">{BOTTOM_ICON_SVG}</button></li>"#,
    ));
}

fn push_document_structure_top_entry(html: &mut String, document_structure: &DocumentStructure) {
    html.push_str(
        r#"<li class="site-doc-structure__entry site-doc-structure__entry--top"><button type="button" class="site-doc-structure__link site-doc-structure__top" data-site-doc-structure-top aria-label="Go to top">"#,
    );
    html.push_str(TOP_ICON_SVG);
    if let Some(title) = &document_structure.title {
        html.push_str(r#"<span class="site-doc-structure__top-label">"#);
        html.push_str(&crate::nav::html_escape(title));
        html.push_str("</span>");
    }
    html.push_str("</button></li>");
}

fn push_document_structure_entries(html: &mut String, document_structure: &DocumentStructure) {
    for entry in &document_structure.entries {
        let id = crate::nav::html_escape(&entry.id);
        let label = crate::nav::html_escape(&entry.label);
        html.push_str(&format!(
            r##"<li class="site-doc-structure__entry site-doc-structure__entry--level-{}" data-site-doc-structure-level="{}"><a class="site-doc-structure__link" data-site-doc-structure-link href="#{}" data-site-doc-structure-target="{}">{}</a></li>"##,
            entry.level, entry.level, id, id, label
        ));
    }
}

fn generate_topbar_html(escaped_app_name: &str, has_structure: bool) -> String {
    let mut html = String::new();
    html.push_str(r#"<div class="site-topbar" data-site-topbar>"#);
    if has_structure {
        html.push_str(
            r#"<button class="site-topbar__button" type="button" data-site-topbar-structure aria-label="Open document structure" aria-expanded="false"><span aria-hidden="true">&#8249;</span></button>"#,
        );
    } else {
        html.push_str(r#"<span class="site-topbar__spacer" aria-hidden="true"></span>"#);
    }
    html.push_str(&format!(
        r#"<a class="site-topbar__title" data-site-topbar-title href="/">{escaped_app_name}</a>"#
    ));
    html.push_str(
        r#"<button class="site-topbar__button" type="button" data-site-topbar-menu aria-label="Open menu" aria-expanded="false"><span aria-hidden="true">&#8250;</span></button>"#,
    );
    html.push_str("</div>");
    html
}

fn generate_menu_drawer_html(navigation: &[NavItem], escaped_app_name: &str) -> String {
    let mut html = String::new();
    html.push_str(r#"<div class="site-drawer site-drawer--menu" data-site-menu-drawer hidden>"#);
    html.push_str(&format!(
        r#"<div class="site-drawer__topbar" data-site-drawer-topbar><button class="site-topbar__button" type="button" data-site-drawer-back aria-label="Back to page"><span aria-hidden="true">&#8249;</span></button><a class="site-topbar__title" href="/">{escaped_app_name}</a><span class="site-topbar__spacer" aria-hidden="true"></span></div>"#
    ));
    html.push_str(
        r#"<div data-site-drawer-search><input class="site-drawer__search-input" data-site-drawer-search-input type="text" autocomplete="off" spellcheck="false" placeholder="Search..." aria-label="Search query" maxlength="256"><div class="site-search-overlay__status" data-site-drawer-search-status aria-live="polite"></div><div class="site-search-overlay__results" data-site-drawer-search-results hidden></div></div>"#,
    );
    html.push_str(r#"<div data-site-drawer-rows></div>"#);
    html.push_str(r#"<nav data-site-drawer-nav aria-label="Site">"#);
    html.push_str(&crate::nav::generate_drawer_navigation_html(navigation));
    html.push_str("</nav></div>");
    html
}

fn generate_structure_drawer_html(
    document_structure: &DocumentStructure,
    escaped_app_name: &str,
) -> String {
    let mut html = String::new();
    html.push_str(
        r#"<div class="site-drawer site-drawer--structure" data-site-structure-drawer hidden>"#,
    );
    html.push_str(&format!(
        r#"<div class="site-drawer__topbar" data-site-drawer-topbar><span class="site-topbar__spacer" aria-hidden="true"></span><a class="site-topbar__title" href="/">{escaped_app_name}</a><button class="site-topbar__button" type="button" data-site-drawer-back aria-label="Back to page"><span aria-hidden="true">&#8250;</span></button></div>"#
    ));
    html.push_str(r#"<nav aria-label="Document structure"><ol>"#);
    push_document_structure_list(&mut html, document_structure);
    html.push_str("</ol></nav></div>");
    html
}

#[cfg(test)]
mod tests {
    use super::{compose_html_title, generate_document_structure_panel_html};
    use crate::markdown::{DocumentStructure, DocumentStructureEntry};

    #[test]
    fn compose_html_title_preserves_page_title_without_website_title() {
        assert_eq!(compose_html_title("About", None), "About");
        assert_eq!(compose_html_title("About", Some("   ")), "About");
    }

    #[test]
    fn compose_html_title_appends_website_title() {
        assert_eq!(
            compose_html_title("About", Some("Example Site")),
            "About | Example Site"
        );
    }

    #[test]
    fn compose_html_title_escapes_components() {
        assert_eq!(
            compose_html_title("A & B", Some("<Example>")),
            "A &amp; B | &lt;Example&gt;"
        );
    }

    #[test]
    fn document_structure_panel_escapes_labels_and_targets() {
        let html = generate_document_structure_panel_html(&DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "a-b".to_string(),
                label: "A & <B>".to_string(),
                level: 1,
            }],
            title: None,
        });

        assert!(html.contains(r#"data-site-doc-structure aria-label="Document structure""#));
        assert!(html.contains(r##"href="#a-b""##));
        assert!(html.contains(r#"data-site-doc-structure-target="a-b""#));
        assert!(html.contains(r#"data-site-doc-structure-level="1""#));
        assert!(html.contains("A &amp; &lt;B&gt;"));
        assert!(!html.contains("A & <B>"));
    }

    #[test]
    fn document_structure_markup_is_omitted_when_empty() {
        let structure = DocumentStructure::default();

        assert_eq!(generate_document_structure_panel_html(&structure), "");
    }

    #[test]
    fn document_structure_panel_renders_title_top_and_icon_bottom() {
        let html = generate_document_structure_panel_html(&DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: Some("My <Page>".to_string()),
        });

        assert!(html.contains(r#"data-site-doc-structure-top aria-label="Go to top"><svg"#));
        assert!(html.contains(
            r#"<span class="site-doc-structure__top-label">My &lt;Page&gt;</span></button>"#
        ));
        assert!(html.contains(r#"data-site-doc-structure-bottom aria-label="Go to bottom""#));
        let top = html.find("data-site-doc-structure-top").expect("top entry");
        let link = html
            .find("data-site-doc-structure-link")
            .expect("heading link");
        let bottom = html
            .find("data-site-doc-structure-bottom")
            .expect("bottom entry");
        assert!(top < link && link < bottom);
    }

    #[test]
    fn document_structure_panel_renders_icon_top_without_title() {
        let html = generate_document_structure_panel_html(&DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: None,
        });

        assert!(html.contains(r#"data-site-doc-structure-top aria-label="Go to top"><svg"#));
        assert!(html.contains(r#"data-site-doc-structure-bottom aria-label="Go to bottom"><svg"#));
    }

    #[test]
    fn document_structure_drawer_renders_top_and_bottom_entries() {
        let html = super::generate_structure_drawer_html(
            &DocumentStructure {
                entries: vec![DocumentStructureEntry {
                    id: "section".to_string(),
                    label: "Section".to_string(),
                    level: 1,
                }],
                title: Some("Drawer Title".to_string()),
            },
            "App",
        );

        assert!(html.contains("data-site-structure-drawer"));
        assert!(html.contains(">Drawer Title</span></button>"));
        assert!(html.contains(r#"data-site-doc-structure-top"#));
        assert!(html.contains(r#"data-site-doc-structure-bottom"#));
    }

    #[test]
    fn document_structure_panel_omits_navbar_menu_markup() {
        let html = generate_document_structure_panel_html(&DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 2,
            }],
            title: None,
        });

        assert!(!html.contains("data-site-doc-structure-menu"));
        assert!(html.contains(r#"data-site-doc-structure-link"#));
        assert!(html.contains(r##"href="#section""##));
    }
}
