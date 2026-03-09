// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop::config::SearchConfig;
use nop::content::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
};
use nop::content::reserved_paths::ReservedPaths;
use nop::runtime_paths::RuntimePaths;
use nop::search::{ReindexReason, initialize};
use nop::util::test_fixtures::TestFixtureRoot;

fn write_markdown(
    runtime_paths: &RuntimePaths,
    id: ContentId,
    version: ContentVersion,
    alias: &str,
    title: &str,
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
        tags: vec![],
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
    };
    let sidecar_file = sidecar_path(&runtime_paths.content_dir, id, version);
    write_sidecar_atomic(&sidecar_file, &sidecar).expect("write sidecar");
}

fn index_doc_count(index_dir: &std::path::Path) -> usize {
    let index = tantivy::Index::open_in_dir(index_dir).expect("open index");
    let reader = index.reader().expect("reader");
    let searcher = reader.searcher();
    searcher
        .segment_readers()
        .iter()
        .map(|segment| segment.num_docs() as usize)
        .sum()
}

#[test]
fn missing_index_startup_rebuilds_from_seeded_markdown_files() {
    let fixture = TestFixtureRoot::new_unique("search-it-missing-index").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );
    write_markdown(
        &runtime_paths,
        ContentId(2),
        ContentVersion(1),
        "docs/guide",
        "Guide",
        "full text",
    );

    let startup = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("search startup");

    assert_eq!(
        startup.startup_reindex_reason,
        Some(ReindexReason::MissingIndex)
    );
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 2);
}

#[test]
fn existing_index_startup_skips_forced_rebuild_when_not_requested() {
    let fixture = TestFixtureRoot::new_unique("search-it-existing-index").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");
    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );

    let first = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("first startup");
    assert_eq!(
        first.startup_reindex_reason,
        Some(ReindexReason::MissingIndex)
    );
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
    drop(first);

    std::thread::sleep(std::time::Duration::from_millis(100));

    let second = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("second startup");
    assert_eq!(second.startup_reindex_reason, None);
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
}

#[test]
fn forced_reindex_rebuilds_from_current_markdown_files() {
    let fixture = TestFixtureRoot::new_unique("search-it-forced-reindex").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");
    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );
    write_markdown(
        &runtime_paths,
        ContentId(2),
        ContentVersion(1),
        "docs/second",
        "Second",
        "second body",
    );

    let startup = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("startup");
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 2);

    let second_blob = blob_path(&runtime_paths.content_dir, ContentId(2), ContentVersion(1));
    let second_sidecar = sidecar_path(&runtime_paths.content_dir, ContentId(2), ContentVersion(1));
    std::fs::remove_file(second_blob).expect("remove blob");
    std::fs::remove_file(second_sidecar).expect("remove sidecar");

    startup
        .service
        .reindex_all_markdown(ReindexReason::Forced)
        .expect("forced reindex");
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
}
