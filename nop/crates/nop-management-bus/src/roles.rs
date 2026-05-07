// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use nop_management_roles::{
    MessageResponseCodec, ROLE_ACTION_ADD, ROLE_ACTION_ADD_ERR, ROLE_ACTION_ADD_OK,
    ROLE_ACTION_CHANGE, ROLE_ACTION_CHANGE_ERR, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE,
    ROLE_ACTION_DELETE_ERR, ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST, ROLE_ACTION_LIST_ERR,
    ROLE_ACTION_LIST_OK, ROLE_ACTION_SHOW, ROLE_ACTION_SHOW_ERR, ROLE_ACTION_SHOW_OK,
    ROLES_DOMAIN_ID, RoleAddRequestCodec, RoleChangeRequestCodec, RoleDeleteRequestCodec,
    RoleListRequestCodec, RoleListResponseCodec, RoleShowRequestCodec, RoleShowResponseCodec,
    handle_roles_request,
};
use std::sync::Arc;

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "roles",
        id: ROLES_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "add",
                id: ROLE_ACTION_ADD,
            },
            ActionDescriptor {
                name: "change",
                id: ROLE_ACTION_CHANGE,
            },
            ActionDescriptor {
                name: "delete",
                id: ROLE_ACTION_DELETE,
            },
            ActionDescriptor {
                name: "list",
                id: ROLE_ACTION_LIST,
            },
            ActionDescriptor {
                name: "show",
                id: ROLE_ACTION_SHOW,
            },
            ActionDescriptor {
                name: "add_ok",
                id: ROLE_ACTION_ADD_OK,
            },
            ActionDescriptor {
                name: "add_err",
                id: ROLE_ACTION_ADD_ERR,
            },
            ActionDescriptor {
                name: "change_ok",
                id: ROLE_ACTION_CHANGE_OK,
            },
            ActionDescriptor {
                name: "change_err",
                id: ROLE_ACTION_CHANGE_ERR,
            },
            ActionDescriptor {
                name: "delete_ok",
                id: ROLE_ACTION_DELETE_OK,
            },
            ActionDescriptor {
                name: "delete_err",
                id: ROLE_ACTION_DELETE_ERR,
            },
            ActionDescriptor {
                name: "list_ok",
                id: ROLE_ACTION_LIST_OK,
            },
            ActionDescriptor {
                name: "list_err",
                id: ROLE_ACTION_LIST_ERR,
            },
            ActionDescriptor {
                name: "show_ok",
                id: ROLE_ACTION_SHOW_OK,
            },
            ActionDescriptor {
                name: "show_err",
                id: ROLE_ACTION_SHOW_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_roles_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_SHOW),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            RoleAddRequestCodec,
            RoleChangeRequestCodec,
            RoleDeleteRequestCodec,
            RoleListRequestCodec,
            RoleShowRequestCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(ROLE_ACTION_ADD_OK),
            MessageResponseCodec::new(ROLE_ACTION_ADD_ERR),
            MessageResponseCodec::new(ROLE_ACTION_CHANGE_OK),
            MessageResponseCodec::new(ROLE_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(ROLE_ACTION_DELETE_OK),
            MessageResponseCodec::new(ROLE_ACTION_DELETE_ERR),
            MessageResponseCodec::new(ROLE_ACTION_LIST_ERR),
            MessageResponseCodec::new(ROLE_ACTION_SHOW_ERR),
            RoleListResponseCodec,
            RoleShowResponseCodec
        ]
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ManagementBus;
    use crate::core::ManagementContext;
    use nop_config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use nop_management_contract::ManagementCommand;
    use nop_management_contract::roles::{RoleCommand, RoleDeleteRequest};
    use nop_rt_iam::types::User;
    use nop_rt_iam::{MemoryUserStore, UserServices};
    use nop_testing::test_fixtures::TestFixtureRoot;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;

    #[derive(Deserialize)]
    struct TagRecordFixture {
        #[serde(default)]
        roles: Vec<String>,
    }

    fn build_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: test_server_list(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: test_local_users_config(),
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
                description: "Test".to_string(),
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
        }
    }

    #[tokio::test]
    async fn role_delete_cascades_tags_and_users() {
        let fixture = TestFixtureRoot::new_unique("role-delete").unwrap();
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        fs::write(
            runtime_paths.state_sys_dir.join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");
        fs::write(
            runtime_paths.state_sys_dir.join("tags.yaml"),
            "docs:\n  name: Docs\n  roles:\n    - editor\n",
        )
        .expect("write tags");

        let config = build_test_config();
        let store = Arc::new(MemoryUserStore::from_users(vec![User {
            email: "editor@example.com".to_string(),
            name: "Editor".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        }]));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");
        let user_services = Arc::new(user_services);
        let context = ManagementContext::from_components_with_user_services(
            runtime_paths.root.clone(),
            Arc::new(config),
            runtime_paths.clone(),
            Some(user_services.clone()),
        )
        .expect("context");
        let registry = crate::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                crate::next_connection_id(),
                1,
                ManagementCommand::Roles(RoleCommand::Delete(RoleDeleteRequest {
                    role: "editor".to_string(),
                })),
            )
            .await
            .expect("role delete");
        assert_eq!(response.action_id, ROLE_ACTION_DELETE_OK);

        let tags_content =
            fs::read_to_string(runtime_paths.state_sys_dir.join("tags.yaml")).expect("read tags");
        let tags: BTreeMap<String, TagRecordFixture> =
            serde_yaml::from_str(&tags_content).expect("parse tags");
        let docs_roles = tags.get("docs").expect("docs tag").roles.clone();
        assert!(docs_roles.is_empty());

        let users = user_services.list_users().expect("list users");
        let editor = users
            .into_iter()
            .find(|user| user.email == "editor@example.com")
            .expect("user");
        assert!(editor.roles.is_empty());
    }
}
