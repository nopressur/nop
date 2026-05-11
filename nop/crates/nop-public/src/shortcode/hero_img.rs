// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

//! `hero-img` shortcode handler.
//!
//! Renders a full-viewport-width hero block carrying an image plus an
//! optional centred title and subtitle. The shortcode is registered with
//! `container_escape: true` so the substitution step wraps it with the
//! layout's `escape_container()` / `return_to_container()` fragments,
//! letting it span the full viewport even when the content container is
//! constrained.

use minijinja::context;
use nop_rt_templates::{TemplateEngine, render_minijinja_template};

use crate::shortcode::{ImageSourceError, ResolvedImage, Shortcode, ShortcodeContext};

pub fn handle_hero_img_shortcode(
    shortcode: &Shortcode,
    ctx: &ShortcodeContext<'_>,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    let src_attr = shortcode
        .attributes
        .get("src")
        .ok_or_else(|| "hero-img requires a `src` attribute".to_string())?;
    if src_attr.trim().is_empty() {
        return Err("hero-img `src` attribute is empty".to_string());
    }
    let src = resolve_url(ctx, src_attr, "src")?;

    let src_dark = match shortcode.attributes.get("src-dark") {
        Some(value) if !value.trim().is_empty() => Some(resolve_url(ctx, value, "src-dark")?),
        _ => None,
    };

    let title = shortcode
        .attributes
        .get("title")
        .map(String::as_str)
        .unwrap_or("")
        .to_string();
    let subtitle = shortcode
        .attributes
        .get("subtitle")
        .map(String::as_str)
        .unwrap_or("")
        .to_string();
    let has_caption = !title.is_empty() || !subtitle.is_empty();

    let lightify = shortcode.attributes.contains_key("lightify");
    let darkify = shortcode.attributes.contains_key("darkify");
    let light_shadow = shortcode.attributes.contains_key("light-shadow");
    let dark_shadow = shortcode.attributes.contains_key("dark-shadow");

    let mut classes = vec!["sc-hero-img".to_string()];
    if lightify {
        classes.push("sc-hero-img--lightify".to_string());
    }
    if darkify {
        classes.push("sc-hero-img--darkify".to_string());
    }
    if light_shadow {
        classes.push("sc-hero-img--light-shadow".to_string());
    }
    if dark_shadow {
        classes.push("sc-hero-img--dark-shadow".to_string());
    }
    let wrapper_class = classes.join(" ");

    // The image's `alt` attribute uses the title when available so screen
    // readers announce the hero's primary text. Empty otherwise — this is a
    // decorative banner.
    let alt = title.clone();

    // URLs go through MiniJinja's HTML attribute escaping. The resolver
    // validates path traversal, MIME, and `/img` reservations, but it does
    // not vet attribute-breakout characters: unquoted shortcode values may
    // contain `"` (see `unquoted_value` in `shortcode/mod.rs`), so an
    // unescaped URL could close the `src="…"` attribute and inject extra
    // attributes. Browsers decode entity-encoded characters in URL
    // attributes correctly (e.g. `&#x2f;` → `/`), so the escape is
    // functionally transparent.
    let template_context = context! {
        wrapper_class => wrapper_class,
        src => src,
        src_dark => src_dark,
        alt => alt,
        title => title,
        subtitle => subtitle,
        has_caption => has_caption,
    };

    render_minijinja_template(
        template_engine,
        "public/shortcode/hero_img.html",
        template_context,
    )
    .map_err(|err| format!("hero-img template render failed: {}", err))
}

fn resolve_url(ctx: &ShortcodeContext<'_>, value: &str, attr_name: &str) -> Result<String, String> {
    match ctx.resolve_image_source(value) {
        Ok(ResolvedImage::External(url)) | Ok(ResolvedImage::Local(url)) => Ok(url),
        Err(err) => Err(image_source_error_message(attr_name, err)),
    }
}

fn image_source_error_message(attr_name: &str, err: ImageSourceError) -> String {
    let reason = match err {
        ImageSourceError::Empty => "value is empty",
        ImageSourceError::PathTraversal => "path traversal not allowed",
        ImageSourceError::ReservedImgPath => "/img path is reserved",
        ImageSourceError::AliasNotFound => "image alias not found",
        ImageSourceError::NotImage => "alias is not an image",
    };
    format!("hero-img `{}` could not be resolved: {}", attr_name, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestFixtureRoot;
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use nop_rt_page_cache::PageMetaCache;
    use nop_rt_templates::MiniJinjaEngine;
    use std::collections::HashMap;
    use std::fs;
    use tokio::runtime::Builder;

    struct ImgHarness {
        _fixture: TestFixtureRoot,
        cache: PageMetaCache,
        engine: MiniJinjaEngine,
    }

    fn write_image(
        runtime_paths: &nop_rt_paths::RuntimePaths,
        content_id: ContentId,
        alias: &str,
        mime: &str,
    ) {
        let content_version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, content_version);
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, b"\x89PNG\r\n\x1a\n").expect("write blob");
        let sidecar = ContentSidecar {
            alias: alias.to_string(),
            title: None,
            mime: mime.to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("hero.png".to_string()),
            theme: None,
        };
        let path = sidecar_path(&runtime_paths.content_dir, content_id, content_version);
        write_sidecar_atomic(&path, &sidecar).expect("write sidecar");
    }

    fn build_harness() -> ImgHarness {
        let fixture = TestFixtureRoot::new_unique("hero-img").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        write_image(&runtime_paths, ContentId(1), "media/hero", "image/png");
        write_image(&runtime_paths, ContentId(2), "media/hero-dark", "image/png");
        // A non-image alias used to verify the NotImage rejection path.
        let blob = blob_path(&runtime_paths.content_dir, ContentId(3), ContentVersion(1));
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, b"# Doc\n").expect("write blob");
        let sidecar = ContentSidecar {
            alias: "docs/page".to_string(),
            title: Some("Doc".to_string()),
            mime: "text/markdown".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };
        let sidecar_path_value =
            sidecar_path(&runtime_paths.content_dir, ContentId(3), ContentVersion(1));
        write_sidecar_atomic(&sidecar_path_value, &sidecar).expect("write sidecar");

        let cache = PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            nop_content_store::reserved_paths::ReservedPaths::default(),
        );
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(cache.rebuild_cache(true))
            .expect("cache rebuild");

        ImgHarness {
            _fixture: fixture,
            cache,
            engine: MiniJinjaEngine::new(),
        }
    }

    fn make_shortcode(attrs: &[(&str, &str)]) -> Shortcode {
        let mut attributes = HashMap::new();
        for (key, value) in attrs {
            attributes.insert((*key).to_string(), (*value).to_string());
        }
        Shortcode {
            name: "hero-img".to_string(),
            attributes,
        }
    }

    fn ctx_for<'a>(harness: &'a ImgHarness, md_path: &'a str) -> ShortcodeContext<'a> {
        ShortcodeContext {
            cache: &harness.cache,
            user: None,
            md_path,
        }
    }

    #[test]
    fn handler_errors_when_src_missing() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[]);
        let result =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires"));
    }

    #[test]
    fn handler_errors_when_src_empty() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "   ")]);
        let result =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn handler_emits_external_url_unchanged() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "https://cdn.example.com/banner.png")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        // MiniJinja's HTML attribute auto-escape may entity-encode characters
        // such as `/`. Assert on the substantive URL parts rather than a
        // byte-for-byte match — the encoded form is functionally equivalent
        // (browsers decode entities in `src` attributes when fetching).
        assert!(html.contains("cdn.example.com"));
        assert!(html.contains("banner.png"));
        assert!(html.contains("class=\"sc-hero-img\""));
    }

    #[test]
    fn handler_resolves_local_path_with_versioned_url() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "/media/hero")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "docs/page"), &harness.engine)
                .expect("render ok");
        assert!(
            html.contains("media") && html.contains("hero?v="),
            "expected versioned local URL in: {}",
            html
        );
    }

    #[test]
    fn handler_emits_dark_source_when_src_dark_set() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "/media/hero"), ("src-dark", "/media/hero-dark")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "docs/page"), &harness.engine)
                .expect("render ok");
        assert!(html.contains("<source media=\"(prefers-color-scheme: dark)\""));
        assert!(html.contains("hero-dark?v="));
    }

    #[test]
    fn handler_omits_dark_source_when_src_dark_absent() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "https://cdn.example.com/banner.png")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "docs/page"), &harness.engine)
                .expect("render ok");
        assert!(!html.contains("<source"));
    }

    #[test]
    fn handler_renders_title_and_subtitle_centred_caption() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[
            ("src", "https://cdn.example.com/banner.png"),
            ("title", "Welcome"),
            ("subtitle", "Built for nopressure"),
        ]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(html.contains("class=\"sc-hero-img__caption\""));
        assert!(html.contains("class=\"sc-hero-img__title\">Welcome</h2>"));
        assert!(html.contains("class=\"sc-hero-img__subtitle\">Built for nopressure</p>"));
    }

    #[test]
    fn handler_omits_caption_when_neither_title_nor_subtitle_present() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "https://cdn.example.com/banner.png")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(!html.contains("sc-hero-img__caption"));
    }

    #[test]
    fn handler_renders_title_only() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[
            ("src", "https://cdn.example.com/banner.png"),
            ("title", "Title only"),
        ]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(html.contains("Title only"));
        assert!(!html.contains("sc-hero-img__subtitle"));
    }

    #[test]
    fn handler_toggles_each_flag_class() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[
            ("src", "https://cdn.example.com/banner.png"),
            ("lightify", ""),
            ("darkify", ""),
            ("light-shadow", ""),
            ("dark-shadow", ""),
        ]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(html.contains("sc-hero-img--lightify"));
        assert!(html.contains("sc-hero-img--darkify"));
        assert!(html.contains("sc-hero-img--light-shadow"));
        assert!(html.contains("sc-hero-img--dark-shadow"));
    }

    #[test]
    fn handler_omits_flag_classes_when_attributes_absent() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "https://cdn.example.com/banner.png")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(!html.contains("--lightify"));
        assert!(!html.contains("--darkify"));
        assert!(!html.contains("--light-shadow"));
        assert!(!html.contains("--dark-shadow"));
    }

    #[test]
    fn handler_escapes_hostile_quote_in_src() {
        // Unquoted shortcode values accept `"` (see `unquoted_value` in
        // shortcode/mod.rs). The handler must not allow such a value to
        // break out of the rendered `src="..."` attribute.
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "http://example.test/\"onerror=\"alert(1)")]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");

        // Raw breakout sequence must not appear: that would close the
        // `src=` attribute and start a new attribute on the same element.
        assert!(
            !html.contains("\"onerror=\""),
            "raw attribute breakout present in output: {}",
            html
        );
        // The hostile `"` must be entity-encoded somehow (MiniJinja uses
        // `&quot;` or `&#x22;` / `&#34;` depending on context). Accept any
        // common HTML entity form.
        assert!(
            html.contains("&quot;onerror=")
                || html.contains("&#x22;onerror=")
                || html.contains("&#34;onerror="),
            "expected entity-encoded hostile quote in output: {}",
            html
        );
    }

    #[test]
    fn handler_escapes_hostile_quote_in_src_dark() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[
            ("src", "https://cdn.example.com/banner.png"),
            ("src-dark", "http://example.test/\"onerror=\"alert(1)"),
        ]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");

        assert!(
            !html.contains("\"onerror=\""),
            "raw attribute breakout present in output: {}",
            html
        );
        assert!(
            html.contains("&quot;onerror=")
                || html.contains("&#x22;onerror=")
                || html.contains("&#34;onerror="),
            "expected entity-encoded hostile quote in output: {}",
            html
        );
    }

    #[test]
    fn handler_html_escapes_title_and_subtitle() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[
            ("src", "https://cdn.example.com/banner.png"),
            ("title", "<script>x</script>"),
            ("subtitle", "a & b"),
        ]);
        let html =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect("render ok");
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("a &amp; b"));
    }

    #[test]
    fn handler_errors_for_unknown_local_alias() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "media/missing")]);
        let err =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "docs/page"), &harness.engine)
                .expect_err("unknown alias errors");
        assert!(err.contains("not found"));
    }

    #[test]
    fn handler_errors_when_alias_is_not_an_image() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "/docs/page")]);
        let err =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "docs/page"), &harness.engine)
                .expect_err("non-image alias errors");
        assert!(err.contains("not an image"));
    }

    #[test]
    fn handler_errors_for_reserved_img_path() {
        let harness = build_harness();
        let shortcode = make_shortcode(&[("src", "/img/banner.png")]);
        let err =
            handle_hero_img_shortcode(&shortcode, &ctx_for(&harness, "any/page"), &harness.engine)
                .expect_err("/img reserved");
        assert!(err.contains("reserved"));
    }
}
