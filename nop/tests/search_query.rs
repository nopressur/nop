// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_config::SearchConfig;
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_rt_paths::RuntimePaths;
use nop_rt_search_service::{QueryAdminRequest, QueryPublicRequest, initialize};
use nop_testing::test_fixtures::TestFixtureRoot;

fn write_markdown(
    runtime_paths: &RuntimePaths,
    id: ContentId,
    version: ContentVersion,
    alias: &str,
    title: &str,
    tags: Vec<String>,
    body: &str,
) {
    let blob = blob_path(&runtime_paths.content_dir, id, version);
    if let Some(parent) = blob.parent() {
        std::fs::create_dir_all(parent).expect("create shard");
    }
    std::fs::write(&blob, body).expect("write markdown body");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: Some(title.to_string()),
        mime: "text/markdown".to_string(),
        tags,
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
    };
    let sidecar_file = sidecar_path(&runtime_paths.content_dir, id, version);
    write_sidecar_atomic(&sidecar_file, &sidecar).expect("write sidecar");
}

fn startup(runtime_paths: &RuntimePaths) -> std::sync::Arc<nop_rt_search_service::SearchService> {
    let startup = initialize(
        runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("search startup");
    startup.service
}

#[test]
fn public_query_excludes_tag_matching_without_access_filtering() {
    let fixture = TestFixtureRoot::new_unique("search-it-query-public").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    std::fs::write(
        runtime_paths.state_sys_dir.join("tags.yaml"),
        r#"secret:
  name: secret
  roles:
    - editor
  access_rule: intersect
"#,
    )
    .expect("tags");

    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/public",
        "Public Item",
        vec![],
        "shared phrase",
    );
    write_markdown(
        &runtime_paths,
        ContentId(2),
        ContentVersion(1),
        "docs/restricted",
        "Restricted Item",
        vec!["secret".to_string()],
        "shared phrase",
    );

    let search = startup(&runtime_paths);

    let anonymous_hits = search
        .query_public(QueryPublicRequest {
            query: "shared".to_string(),
            roles: Vec::new(),
        })
        .expect("anonymous query");
    assert_eq!(anonymous_hits.len(), 1);

    let tag_only = search
        .query_public(QueryPublicRequest {
            query: "secret".to_string(),
            roles: Vec::new(),
        })
        .expect("tag-only query");
    assert!(tag_only.is_empty());
}

#[test]
fn admin_query_is_tag_inclusive_and_full_access() {
    let fixture = TestFixtureRoot::new_unique("search-it-query-admin").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    std::fs::write(
        runtime_paths.state_sys_dir.join("tags.yaml"),
        r#"secret:
  name: secret
  roles:
    - editor
  access_rule: intersect
"#,
    )
    .expect("tags");

    write_markdown(
        &runtime_paths,
        ContentId(10),
        ContentVersion(1),
        "docs/public",
        "Alpha Item",
        vec![],
        "search body",
    );
    write_markdown(
        &runtime_paths,
        ContentId(11),
        ContentVersion(1),
        "docs/restricted",
        "Beta Item",
        vec!["secret".to_string()],
        "search body",
    );

    let search = startup(&runtime_paths);

    let tag_hits = search
        .query_admin(QueryAdminRequest {
            query: "secret".to_string(),
            tags: None,
        })
        .expect("admin tag query");
    assert_eq!(tag_hits.len(), 1);
    assert_eq!(tag_hits[0].title, "Beta Item");

    let shared_hits = search
        .query_admin(QueryAdminRequest {
            query: "search".to_string(),
            tags: None,
        })
        .expect("admin body query");
    assert_eq!(shared_hits.len(), 2);
}

#[test]
fn public_query_is_bounded() {
    let fixture = TestFixtureRoot::new_unique("search-it-query-limit").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    for idx in 0u64..20u64 {
        write_markdown(
            &runtime_paths,
            ContentId(200 + idx),
            ContentVersion(1),
            &format!("docs/it-{:02}", idx),
            &format!("Item {:02}", idx),
            vec![],
            "common body",
        );
    }

    let search = startup(&runtime_paths);

    let hits = search
        .query_public(QueryPublicRequest {
            query: "common".to_string(),
            roles: Vec::new(),
        })
        .expect("public query");

    assert_eq!(hits.len(), 16);
}

#[test]
fn admin_query_matches_table_text_case_insensitively() {
    let fixture = TestFixtureRoot::new_unique("search-it-table-case").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    write_markdown(
        &runtime_paths,
        ContentId(50),
        ContentVersion(1),
        "docs/nimbus-table",
        "Nimbus Table",
        vec![],
        r#"
| Nimbus | Orion | Orion Quartz |
|-----------|----------|---------------|
"#,
    );

    let search = startup(&runtime_paths);

    let lower_hits = search
        .query_admin(QueryAdminRequest {
            query: "nimbus".to_string(),
            tags: None,
        })
        .expect("lowercase query");
    assert_eq!(lower_hits.len(), 1);
    assert_eq!(lower_hits[0].title, "Nimbus Table");

    let upper_hits = search
        .query_admin(QueryAdminRequest {
            query: "NIMBUS".to_string(),
            tags: None,
        })
        .expect("uppercase query");
    assert_eq!(upper_hits.len(), 1);
    assert_eq!(upper_hits[0].title, "Nimbus Table");
}

#[test]
fn admin_query_matches_html_text_and_ignores_attributes_and_urls() {
    let fixture = TestFixtureRoot::new_unique("search-it-html").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    write_markdown(
        &runtime_paths,
        ContentId(51),
        ContentVersion(1),
        "docs/nimbus-html",
        "Nimbus HTML",
        vec![],
        r#"
<p data-kind="zzattrtoken">Nimbus <strong>Orion</strong></p>
<a href="https://zzurltoken.example/path">Orion Quartz</a>
"#,
    );

    let search = startup(&runtime_paths);

    let hits = search
        .query_admin(QueryAdminRequest {
            query: "ORION".to_string(),
            tags: None,
        })
        .expect("html visible text query");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].title, "Nimbus HTML");

    let attr_hits = search
        .query_admin(QueryAdminRequest {
            query: "zzattrtoken".to_string(),
            tags: None,
        })
        .expect("html attribute query");
    assert!(attr_hits.is_empty());

    let url_hits = search
        .query_admin(QueryAdminRequest {
            query: "zzurltoken".to_string(),
            tags: None,
        })
        .expect("html url query");
    assert!(url_hits.is_empty());
}
