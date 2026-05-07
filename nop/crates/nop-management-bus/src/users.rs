// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::core::ManagementContext;
use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use async_trait::async_trait;
use nop_config::ValidatedUsersConfig;
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use nop_rt_iam::UserServices;
use nop_rt_iam::types::User;
use std::sync::Arc;
use std::time::Duration;

use nop_management_users::{
    BlockingRunner, MessageResponseCodec, PasswordChangeToken, PasswordSaltResponseCodec,
    PasswordValidateResponseCodec, USER_ACTION_ADD, USER_ACTION_ADD_ERR, USER_ACTION_ADD_OK,
    USER_ACTION_CHANGE, USER_ACTION_CHANGE_ERR, USER_ACTION_CHANGE_OK, USER_ACTION_DELETE,
    USER_ACTION_DELETE_ERR, USER_ACTION_DELETE_OK, USER_ACTION_LIST, USER_ACTION_LIST_ERR,
    USER_ACTION_LIST_OK, USER_ACTION_PASSWORD_SALT, USER_ACTION_PASSWORD_SALT_ERR,
    USER_ACTION_PASSWORD_SALT_OK, USER_ACTION_PASSWORD_SET, USER_ACTION_PASSWORD_SET_ERR,
    USER_ACTION_PASSWORD_SET_OK, USER_ACTION_PASSWORD_UPDATE, USER_ACTION_PASSWORD_UPDATE_ERR,
    USER_ACTION_PASSWORD_UPDATE_OK, USER_ACTION_PASSWORD_VALIDATE,
    USER_ACTION_PASSWORD_VALIDATE_ERR, USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD,
    USER_ACTION_ROLE_ADD_ERR, USER_ACTION_ROLE_ADD_OK, USER_ACTION_ROLE_REMOVE,
    USER_ACTION_ROLE_REMOVE_ERR, USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_ROLES_LIST,
    USER_ACTION_ROLES_LIST_ERR, USER_ACTION_ROLES_LIST_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_ERR,
    USER_ACTION_SHOW_OK, USERS_DOMAIN_ID, UserAddCodec, UserChangeCodec, UserDeleteCodec,
    UserListCodec, UserListResponseCodec, UserPasswordSaltCodec, UserPasswordSetCodec,
    UserPasswordUpdateCodec, UserPasswordValidateCodec, UserRecord, UserRoleAddCodec,
    UserRoleRemoveCodec, UserRolesListCodec, UserRolesListResponseCodec, UserServicesAccess,
    UserShowCodec, UserShowResponseCodec, UsersConfigAccess, handle_users_request,
};

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "users",
        id: USERS_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "add",
                id: USER_ACTION_ADD,
            },
            ActionDescriptor {
                name: "change",
                id: USER_ACTION_CHANGE,
            },
            ActionDescriptor {
                name: "delete",
                id: USER_ACTION_DELETE,
            },
            ActionDescriptor {
                name: "password_set",
                id: USER_ACTION_PASSWORD_SET,
            },
            ActionDescriptor {
                name: "list",
                id: USER_ACTION_LIST,
            },
            ActionDescriptor {
                name: "show",
                id: USER_ACTION_SHOW,
            },
            ActionDescriptor {
                name: "role_add",
                id: USER_ACTION_ROLE_ADD,
            },
            ActionDescriptor {
                name: "role_remove",
                id: USER_ACTION_ROLE_REMOVE,
            },
            ActionDescriptor {
                name: "roles_list",
                id: USER_ACTION_ROLES_LIST,
            },
            ActionDescriptor {
                name: "password_salt",
                id: USER_ACTION_PASSWORD_SALT,
            },
            ActionDescriptor {
                name: "password_validate",
                id: USER_ACTION_PASSWORD_VALIDATE,
            },
            ActionDescriptor {
                name: "password_update",
                id: USER_ACTION_PASSWORD_UPDATE,
            },
            ActionDescriptor {
                name: "add_ok",
                id: USER_ACTION_ADD_OK,
            },
            ActionDescriptor {
                name: "add_err",
                id: USER_ACTION_ADD_ERR,
            },
            ActionDescriptor {
                name: "change_ok",
                id: USER_ACTION_CHANGE_OK,
            },
            ActionDescriptor {
                name: "change_err",
                id: USER_ACTION_CHANGE_ERR,
            },
            ActionDescriptor {
                name: "delete_ok",
                id: USER_ACTION_DELETE_OK,
            },
            ActionDescriptor {
                name: "delete_err",
                id: USER_ACTION_DELETE_ERR,
            },
            ActionDescriptor {
                name: "password_set_ok",
                id: USER_ACTION_PASSWORD_SET_OK,
            },
            ActionDescriptor {
                name: "password_set_err",
                id: USER_ACTION_PASSWORD_SET_ERR,
            },
            ActionDescriptor {
                name: "password_salt_ok",
                id: USER_ACTION_PASSWORD_SALT_OK,
            },
            ActionDescriptor {
                name: "password_salt_err",
                id: USER_ACTION_PASSWORD_SALT_ERR,
            },
            ActionDescriptor {
                name: "password_validate_ok",
                id: USER_ACTION_PASSWORD_VALIDATE_OK,
            },
            ActionDescriptor {
                name: "password_validate_err",
                id: USER_ACTION_PASSWORD_VALIDATE_ERR,
            },
            ActionDescriptor {
                name: "password_update_ok",
                id: USER_ACTION_PASSWORD_UPDATE_OK,
            },
            ActionDescriptor {
                name: "password_update_err",
                id: USER_ACTION_PASSWORD_UPDATE_ERR,
            },
            ActionDescriptor {
                name: "list_ok",
                id: USER_ACTION_LIST_OK,
            },
            ActionDescriptor {
                name: "list_err",
                id: USER_ACTION_LIST_ERR,
            },
            ActionDescriptor {
                name: "show_ok",
                id: USER_ACTION_SHOW_OK,
            },
            ActionDescriptor {
                name: "show_err",
                id: USER_ACTION_SHOW_ERR,
            },
            ActionDescriptor {
                name: "role_add_ok",
                id: USER_ACTION_ROLE_ADD_OK,
            },
            ActionDescriptor {
                name: "role_add_err",
                id: USER_ACTION_ROLE_ADD_ERR,
            },
            ActionDescriptor {
                name: "role_remove_ok",
                id: USER_ACTION_ROLE_REMOVE_OK,
            },
            ActionDescriptor {
                name: "role_remove_err",
                id: USER_ACTION_ROLE_REMOVE_ERR,
            },
            ActionDescriptor {
                name: "roles_list_ok",
                id: USER_ACTION_ROLES_LIST_OK,
            },
            ActionDescriptor {
                name: "roles_list_err",
                id: USER_ACTION_ROLES_LIST_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_users_request(request, context.as_ref()).await })
    });

    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SET),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_VALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_UPDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_SHOW),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLE_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLE_REMOVE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLES_LIST),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            UserAddCodec,
            UserChangeCodec,
            UserDeleteCodec,
            UserPasswordSetCodec,
            UserPasswordSaltCodec,
            UserPasswordValidateCodec,
            UserPasswordUpdateCodec,
            UserListCodec,
            UserShowCodec,
            UserRoleAddCodec,
            UserRoleRemoveCodec,
            UserRolesListCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(USER_ACTION_ADD_OK),
            MessageResponseCodec::new(USER_ACTION_ADD_ERR),
            MessageResponseCodec::new(USER_ACTION_CHANGE_OK),
            MessageResponseCodec::new(USER_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(USER_ACTION_DELETE_OK),
            MessageResponseCodec::new(USER_ACTION_DELETE_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SET_OK),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SET_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_UPDATE_OK),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_UPDATE_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SALT_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_VALIDATE_ERR),
            MessageResponseCodec::new(USER_ACTION_LIST_ERR),
            MessageResponseCodec::new(USER_ACTION_SHOW_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLE_ADD_OK),
            MessageResponseCodec::new(USER_ACTION_ROLE_ADD_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLE_REMOVE_OK),
            MessageResponseCodec::new(USER_ACTION_ROLE_REMOVE_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLES_LIST_ERR),
            UserListResponseCodec,
            UserShowResponseCodec,
            UserRolesListResponseCodec,
            PasswordSaltResponseCodec,
            PasswordValidateResponseCodec
        ]
    );

    Ok(())
}

fn user_services_ref(context: &ManagementContext) -> Result<&UserServices, String> {
    context
        .user_services
        .as_ref()
        .map(|services| services.as_ref())
        .ok_or_else(|| "User services not initialized".to_string())
}

fn user_services_arc(context: &ManagementContext) -> Result<Arc<UserServices>, String> {
    context
        .user_services
        .clone()
        .ok_or_else(|| "User services not initialized".to_string())
}

fn to_user_record(user: User) -> UserRecord {
    UserRecord {
        email: user.email,
        name: user.name,
        password: user.password,
        legacy_password_hash: user.legacy_password_hash,
        roles: user.roles,
        password_version: user.password_version,
    }
}

impl UsersConfigAccess for ManagementContext {
    fn users_config(&self) -> &ValidatedUsersConfig {
        &self.config.users
    }
}

#[async_trait]
impl BlockingRunner for ManagementContext {
    async fn run_blocking<F, R>(&self, context: &'static str, task: F) -> Result<R, String>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.blocking_pool
            .run_blocking(context, task)
            .await
            .map_err(|err| err.to_string())
    }
}

#[async_trait]
impl UserServicesAccess for ManagementContext {
    fn password_params(&self) -> Result<&nop_config::PasswordHashingParams, String> {
        Ok(user_services_ref(self)?.password_params())
    }

    fn list_users(&self) -> Result<Vec<UserRecord>, String> {
        let users = user_services_ref(self)?
            .list_users()
            .map_err(|err| err.to_string())?;
        Ok(users.into_iter().map(to_user_record).collect())
    }

    fn get_user(&self, email: &str) -> Result<Option<UserRecord>, String> {
        let user = user_services_ref(self)?
            .get_user(email)
            .map_err(|err| err.to_string())?;
        Ok(user.map(to_user_record))
    }

    async fn password_validate(&self, email: &str, front_end_hash: &str) -> Result<bool, String> {
        let services = user_services_arc(self)?;
        let email = email.to_string();
        let front_end_hash = front_end_hash.to_string();
        self.blocking_pool
            .run_blocking("validate password", move || {
                services
                    .password_validate(&email, &front_end_hash)
                    .map_err(|err| err.to_string())
            })
            .await
            .map_err(|err| err.to_string())?
    }

    async fn add_user(
        &self,
        email: &str,
        name: &str,
        password: nop_iam_passwords::PasswordProviderBlock,
        roles: Vec<String>,
    ) -> Result<(), String> {
        let services = user_services_arc(self)?;
        services
            .add_user(email, name, password, roles)
            .await
            .map_err(|err| err.to_string())
    }

    async fn update_user_complete(
        &self,
        email: &str,
        name: Option<&str>,
        password: Option<nop_iam_passwords::PasswordProviderBlock>,
        roles: Option<Vec<String>>,
    ) -> Result<(), String> {
        let services = user_services_arc(self)?;
        services
            .update_user_complete(email, name, password, roles)
            .await
            .map_err(|err| err.to_string())
    }

    async fn delete_user(&self, email: &str) -> Result<(), String> {
        let services = user_services_arc(self)?;
        services
            .delete_user(email)
            .await
            .map_err(|err| err.to_string())
    }

    async fn issue_password_change_token(
        &self,
        email: &str,
        next_front_end_salt: String,
        ttl: Duration,
    ) -> Result<(String, PasswordChangeToken), String> {
        let services = user_services_arc(self)?;
        let store = services.password_change_store().clone();
        let (token, issued) = store
            .issue(email, next_front_end_salt, ttl)
            .await
            .map_err(|err| err.message().to_string())?;
        Ok((
            token,
            PasswordChangeToken {
                email: issued.email,
                next_front_end_salt: issued.next_front_end_salt,
            },
        ))
    }

    async fn get_password_change_token(
        &self,
        change_token: &str,
    ) -> Result<Option<PasswordChangeToken>, String> {
        let services = user_services_arc(self)?;
        let store = services.password_change_store().clone();
        let token = store
            .get(change_token)
            .await
            .map_err(|err| err.message().to_string())?;
        Ok(token.map(|token| PasswordChangeToken {
            email: token.email,
            next_front_end_salt: token.next_front_end_salt,
        }))
    }

    async fn invalidate_password_change_token(&self, change_token: &str) -> Result<(), String> {
        let services = user_services_arc(self)?;
        let store = services.password_change_store().clone();
        store
            .invalidate(change_token)
            .await
            .map_err(|err| err.message().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use nop_iam_passwords::PasswordProviderBlock;
    use nop_management_contract::ResponsePayload;
    use nop_management_contract::users::{
        UserCommand, UserListRequest, UserRoleAddRequest, UserRoleRemoveRequest,
        UserRolesListRequest, UserShowRequest,
    };
    use nop_management_contract::{ManagementCommand, ManagementRequest};
    use nop_rt_iam::MemoryUserStore;
    use nop_rt_iam::types::User;
    use nop_testing::test_fixtures::TestFixtureRoot;

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
        }
    }

    fn build_context(
        fixture: &TestFixtureRoot,
        users: Vec<User>,
    ) -> (ManagementContext, Arc<UserServices>) {
        let config = build_test_config();
        let store = Arc::new(MemoryUserStore::from_users(users));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");
        let user_services = Arc::new(user_services);
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        std::fs::write(
            runtime_paths.state_sys_dir.join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");
        let context = ManagementContext::from_components_with_user_services(
            runtime_paths.root.clone(),
            Arc::new(config),
            runtime_paths,
            Some(user_services.clone()),
        )
        .expect("context");
        (context, user_services)
    }

    fn dummy_password_block() -> PasswordProviderBlock {
        PasswordProviderBlock {
            front_end_salt: "00aa00bb00cc00dd".to_string(),
            back_end_salt: "1122334455667788".to_string(),
            stored_hash: "dummy-hash".to_string(),
        }
    }

    #[tokio::test]
    async fn list_returns_user_summaries() {
        let fixture = TestFixtureRoot::new_unique("users-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User One".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::List(UserListRequest {})),
            actor_email: None,
        };
        let response = handle_users_request(request, &context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserList(payload) => {
                assert_eq!(payload.users.len(), 1);
                assert_eq!(payload.users[0].email, "user@example.com");
                assert_eq!(payload.users[0].name, "User One");
            }
            _ => panic!("Expected user list response"),
        }
    }

    #[tokio::test]
    async fn show_returns_user_details() {
        let fixture = TestFixtureRoot::new_unique("users-show").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Two".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::Show(UserShowRequest {
                email: "USER@example.com".to_string(),
            })),
            actor_email: None,
        };
        let response = handle_users_request(request, &context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserShow(payload) => {
                assert_eq!(payload.email, "user@example.com");
                assert_eq!(payload.name, "User Two");
                assert_eq!(payload.roles, vec!["editor"]);
            }
            _ => panic!("Expected user show response"),
        }
    }

    #[tokio::test]
    async fn roles_list_returns_roles() {
        let fixture = TestFixtureRoot::new_unique("users-roles-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Three".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RolesList(UserRolesListRequest {})),
            actor_email: None,
        };
        let response = handle_users_request(request, &context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserRolesList(payload) => {
                assert!(payload.roles.contains(&"admin".to_string()));
                assert!(payload.roles.contains(&"editor".to_string()));
            }
            _ => panic!("Expected roles list response"),
        }
    }

    #[tokio::test]
    async fn role_add_and_remove_update_user() {
        let fixture = TestFixtureRoot::new_unique("users-role-update").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Four".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        };
        let (context, user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::next_connection_id();

        let add_request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RoleAdd(UserRoleAddRequest {
                email: "user@example.com".to_string(),
                role: "editor".to_string(),
            })),
            actor_email: None,
        };
        handle_users_request(add_request, &context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        let users = user_services.list_users().expect("users");
        let updated = users
            .iter()
            .find(|user| user.email == "user@example.com")
            .expect("user");
        assert!(updated.roles.contains(&"editor".to_string()));

        let remove_request = ManagementRequest {
            workflow_id: 2,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RoleRemove(UserRoleRemoveRequest {
                email: "user@example.com".to_string(),
                role: "editor".to_string(),
            })),
            actor_email: None,
        };
        handle_users_request(remove_request, &context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        let users = user_services.list_users().expect("users");
        let updated = users
            .iter()
            .find(|user| user.email == "user@example.com")
            .expect("user");
        assert!(!updated.roles.contains(&"editor".to_string()));
    }
}
