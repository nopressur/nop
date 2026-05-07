// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::core::ManagementContext;
use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use nop_management_tags::{
    MessageResponseCodec, TAG_ACTION_ADD, TAG_ACTION_ADD_ERR, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
    TAG_ACTION_CHANGE_ERR, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_ERR,
    TAG_ACTION_DELETE_OK, TAG_ACTION_LIST, TAG_ACTION_LIST_ERR, TAG_ACTION_LIST_OK,
    TAG_ACTION_SHOW, TAG_ACTION_SHOW_ERR, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequestCodec,
    TagChangeRequestCodec, TagDeleteRequestCodec, TagListRequestCodec, TagListResponseCodec,
    TagRecord, TagShowRequestCodec, TagShowResponseCodec, handle_tags_request,
};
use std::collections::BTreeMap;
use std::sync::Arc;

impl nop_management_tags::TagStoreProvider for ManagementContext {
    fn tags_snapshot(&self) -> Result<BTreeMap<String, TagRecord>, String> {
        self.tag_store.snapshot().map_err(|err| err.to_string())
    }

    fn persist_tags(&self, tags: BTreeMap<String, TagRecord>) -> Result<(), String> {
        self.tag_store.persist(tags).map_err(|err| err.to_string())
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "tags",
        id: TAGS_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "add",
                id: TAG_ACTION_ADD,
            },
            ActionDescriptor {
                name: "change",
                id: TAG_ACTION_CHANGE,
            },
            ActionDescriptor {
                name: "delete",
                id: TAG_ACTION_DELETE,
            },
            ActionDescriptor {
                name: "list",
                id: TAG_ACTION_LIST,
            },
            ActionDescriptor {
                name: "show",
                id: TAG_ACTION_SHOW,
            },
            ActionDescriptor {
                name: "add_ok",
                id: TAG_ACTION_ADD_OK,
            },
            ActionDescriptor {
                name: "add_err",
                id: TAG_ACTION_ADD_ERR,
            },
            ActionDescriptor {
                name: "change_ok",
                id: TAG_ACTION_CHANGE_OK,
            },
            ActionDescriptor {
                name: "change_err",
                id: TAG_ACTION_CHANGE_ERR,
            },
            ActionDescriptor {
                name: "delete_ok",
                id: TAG_ACTION_DELETE_OK,
            },
            ActionDescriptor {
                name: "delete_err",
                id: TAG_ACTION_DELETE_ERR,
            },
            ActionDescriptor {
                name: "list_ok",
                id: TAG_ACTION_LIST_OK,
            },
            ActionDescriptor {
                name: "list_err",
                id: TAG_ACTION_LIST_ERR,
            },
            ActionDescriptor {
                name: "show_ok",
                id: TAG_ACTION_SHOW_OK,
            },
            ActionDescriptor {
                name: "show_err",
                id: TAG_ACTION_SHOW_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_tags_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_SHOW),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            TagAddRequestCodec,
            TagChangeRequestCodec,
            TagDeleteRequestCodec,
            TagListRequestCodec,
            TagShowRequestCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(TAG_ACTION_ADD_OK),
            MessageResponseCodec::new(TAG_ACTION_ADD_ERR),
            MessageResponseCodec::new(TAG_ACTION_CHANGE_OK),
            MessageResponseCodec::new(TAG_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(TAG_ACTION_DELETE_OK),
            MessageResponseCodec::new(TAG_ACTION_DELETE_ERR),
            MessageResponseCodec::new(TAG_ACTION_LIST_ERR),
            MessageResponseCodec::new(TAG_ACTION_SHOW_ERR),
            TagListResponseCodec,
            TagShowResponseCodec
        ]
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManagementBus, ManagementContext};
    use nop_config::{
        AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
        LoggingRotationConfig, NavigationConfig, PasswordHashingConfig, RenderingConfig,
        SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
    };
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, read_sidecar, sidecar_path,
        write_sidecar_atomic,
    };
    use nop_management_contract::ResponsePayload;
    use nop_management_contract::tags::{
        TagAddRequest, TagChangeRequest, TagCommand, TagDeleteRequest, TagListRequest,
    };
    use nop_testing::test_fixtures::TestFixtureRoot;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Arc;

    fn build_test_context(root: &Path) -> ManagementContext {
        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: UsersConfig {
                auth_method: AuthMethod::Local,
                local: Some(LocalAuthConfig {
                    jwt: JwtConfig {
                        secret: "test-secret".to_string(),
                        issuer: "nopressure".to_string(),
                        audience: "nopressure-users".to_string(),
                        expiration_hours: 12,
                        cookie_name: "nop_auth".to_string(),
                        force_secure_cookie: false,
                        disable_refresh: false,
                        refresh_threshold_percentage: 10,
                        refresh_threshold_hours: 24,
                    },
                    password: PasswordHashingConfig::default(),
                    password_complexity_disabled: false,
                }),
                oidc: None,
            },
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 10,
                cooldown_seconds: 60,
                use_forwarded_for: false,
                login_sessions: nop_config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: None,
            app: AppConfig {
                name: "Test App".to_string(),
                description: "Test Description".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            search: nop_config::SearchConfig::default(),
            dev_mode: None,
        };
        let content = serde_yaml::to_string(&config).expect("serialize config");
        std::fs::write(root.join("config.yaml"), content).expect("write config");
        std::fs::write(root.join("users.yaml"), "{}\n").expect("write users");
        std::fs::create_dir_all(root.join("state").join("sys")).expect("state/sys");
        std::fs::write(
            root.join("state").join("sys").join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");

        let validated = Config::load_and_validate(root).expect("validate config");
        let runtime_paths =
            nop_rt_paths::RuntimePaths::from_root(root, &validated).expect("runtime paths");
        ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(validated),
            runtime_paths,
        )
        .expect("context")
    }

    #[tokio::test]
    async fn tag_add_and_list_roundtrip() {
        let fixture = TestFixtureRoot::new_unique("tags-add-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let add =
            nop_management_contract::ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                id: "news/alerts".to_string(),
                name: "News Alerts".to_string(),
                roles: vec!["editor".to_string()],
                access_rule: Some(nop_roles::AccessRule::Union),
            }));
        let response = bus
            .send(crate::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.domain_id, TAGS_DOMAIN_ID);
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let list =
            nop_management_contract::ManagementCommand::Tags(TagCommand::List(TagListRequest {}));
        let response = bus
            .send(crate::next_connection_id(), 2, list)
            .await
            .expect("list response");
        match response.payload {
            ResponsePayload::TagList(payload) => {
                assert_eq!(payload.tags.len(), 1);
                assert_eq!(payload.tags[0].id, "news/alerts");
            }
            _ => panic!("Expected tag list response"),
        }
    }

    #[tokio::test]
    async fn tag_delete_removes_content_tags() {
        let fixture = TestFixtureRoot::new_unique("tags-delete-cascade").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let content_id = ContentId(42);
        let version = ContentVersion(0);
        let content_dir = fixture.content_dir();
        let blob = blob_path(&content_dir, content_id, version);
        std::fs::create_dir_all(blob.parent().expect("blob parent")).expect("content shard");
        std::fs::write(&blob, "# Tagged content\n").expect("write blob");

        let sidecar_path = sidecar_path(&content_dir, content_id, version);
        let sidecar = ContentSidecar {
            alias: "docs/tagged".to_string(),
            title: Some("Tagged".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["release/alpha".to_string()],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("tagged.md".to_string()),
            theme: None,
        };
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");

        let add =
            nop_management_contract::ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                id: "release/alpha".to_string(),
                name: "Release Alpha".to_string(),
                roles: vec![],
                access_rule: None,
            }));
        let response = bus
            .send(crate::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let delete = nop_management_contract::ManagementCommand::Tags(TagCommand::Delete(
            TagDeleteRequest {
                id: "release/alpha".to_string(),
            },
        ));
        let response = bus
            .send(crate::next_connection_id(), 2, delete)
            .await
            .expect("delete response");
        assert_eq!(response.action_id, TAG_ACTION_DELETE_OK);

        let updated = read_sidecar(&sidecar_path).expect("read sidecar");
        assert!(updated.tags.is_empty());
    }

    #[tokio::test]
    async fn tag_rename_updates_content_tags() {
        let fixture = TestFixtureRoot::new_unique("tags-rename").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let content_id = ContentId(7);
        let version = ContentVersion(0);
        let content_dir = fixture.content_dir();
        let blob = blob_path(&content_dir, content_id, version);
        std::fs::create_dir_all(blob.parent().expect("blob parent")).expect("content shard");
        std::fs::write(&blob, "# Tagged content\n").expect("write blob");

        let sidecar_path = sidecar_path(&content_dir, content_id, version);
        let sidecar = ContentSidecar {
            alias: "docs/rename".to_string(),
            title: Some("Rename".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["release/alpha".to_string()],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("rename.md".to_string()),
            theme: None,
        };
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");

        let add =
            nop_management_contract::ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                id: "release/alpha".to_string(),
                name: "Release Alpha".to_string(),
                roles: vec![],
                access_rule: None,
            }));
        let response = bus
            .send(crate::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let change = nop_management_contract::ManagementCommand::Tags(TagCommand::Change(
            TagChangeRequest {
                id: "release/alpha".to_string(),
                new_id: Some("release/beta".to_string()),
                name: None,
                roles: None,
                access_rule: None,
                clear_access: false,
            },
        ));
        let response = bus
            .send(crate::next_connection_id(), 2, change)
            .await
            .expect("change response");
        assert_eq!(response.action_id, TAG_ACTION_CHANGE_OK);

        let updated = read_sidecar(&sidecar_path).expect("read sidecar");
        assert_eq!(updated.tags, vec!["release/beta".to_string()]);

        let tags_content =
            std::fs::read_to_string(fixture.state_dir().join("sys").join("tags.yaml"))
                .expect("read tags");
        let tags: BTreeMap<String, TagRecord> =
            serde_yaml::from_str(&tags_content).expect("parse tags");
        assert!(tags.contains_key("release/beta"));
        assert!(!tags.contains_key("release/alpha"));
    }

    #[tokio::test]
    async fn tag_rename_rejects_collision() {
        let fixture = TestFixtureRoot::new_unique("tags-rename-collision").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let add_a =
            nop_management_contract::ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                id: "tag-a".to_string(),
                name: "Tag A".to_string(),
                roles: vec![],
                access_rule: None,
            }));
        let response = bus
            .send(crate::next_connection_id(), 1, add_a)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let add_b =
            nop_management_contract::ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                id: "tag-b".to_string(),
                name: "Tag B".to_string(),
                roles: vec![],
                access_rule: None,
            }));
        let response = bus
            .send(crate::next_connection_id(), 2, add_b)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let change = nop_management_contract::ManagementCommand::Tags(TagCommand::Change(
            TagChangeRequest {
                id: "tag-a".to_string(),
                new_id: Some("tag-b".to_string()),
                name: None,
                roles: None,
                access_rule: None,
                clear_access: false,
            },
        ));
        let response = bus
            .send(crate::next_connection_id(), 3, change)
            .await
            .expect("change response");
        assert_eq!(response.action_id, TAG_ACTION_CHANGE_ERR);
    }
}
