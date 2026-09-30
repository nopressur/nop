// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use nop_management_settings::{
    SETTINGS_ACTION_GET, SETTINGS_ACTION_GET_ERR, SETTINGS_ACTION_GET_OK,
    SETTINGS_ACTION_SET_DESCRIPTION, SETTINGS_ACTION_SET_DESCRIPTION_ERR,
    SETTINGS_ACTION_SET_DESCRIPTION_OK, SETTINGS_ACTION_SET_NAME, SETTINGS_ACTION_SET_NAME_ERR,
    SETTINGS_ACTION_SET_NAME_OK, SETTINGS_ACTION_SET_TITLE, SETTINGS_ACTION_SET_TITLE_ERR,
    SETTINGS_ACTION_SET_TITLE_OK, SETTINGS_DOMAIN_ID, handle_settings_request,
};
use std::sync::Arc;

impl nop_management_settings::SettingsContext for crate::ManagementContext {
    fn runtime_root(&self) -> &std::path::Path {
        self.runtime_root.as_path()
    }

    fn runtime_settings(&self) -> &nop_config::RuntimeSettings {
        &self.runtime_settings
    }

    fn bump_website_epoch(&self, reason: &str) {
        if let Some(release_tracker) = self.release_tracker.as_ref() {
            release_tracker.bump(reason);
        }
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "settings",
        id: SETTINGS_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "get",
                id: SETTINGS_ACTION_GET,
            },
            ActionDescriptor {
                name: "set_name",
                id: SETTINGS_ACTION_SET_NAME,
            },
            ActionDescriptor {
                name: "set_title",
                id: SETTINGS_ACTION_SET_TITLE,
            },
            ActionDescriptor {
                name: "set_description",
                id: SETTINGS_ACTION_SET_DESCRIPTION,
            },
            ActionDescriptor {
                name: "get_ok",
                id: SETTINGS_ACTION_GET_OK,
            },
            ActionDescriptor {
                name: "get_err",
                id: SETTINGS_ACTION_GET_ERR,
            },
            ActionDescriptor {
                name: "set_name_ok",
                id: SETTINGS_ACTION_SET_NAME_OK,
            },
            ActionDescriptor {
                name: "set_name_err",
                id: SETTINGS_ACTION_SET_NAME_ERR,
            },
            ActionDescriptor {
                name: "set_title_ok",
                id: SETTINGS_ACTION_SET_TITLE_OK,
            },
            ActionDescriptor {
                name: "set_title_err",
                id: SETTINGS_ACTION_SET_TITLE_ERR,
            },
            ActionDescriptor {
                name: "set_description_ok",
                id: SETTINGS_ACTION_SET_DESCRIPTION_OK,
            },
            ActionDescriptor {
                name: "set_description_err",
                id: SETTINGS_ACTION_SET_DESCRIPTION_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_settings_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(SETTINGS_DOMAIN_ID, SETTINGS_ACTION_GET),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SETTINGS_DOMAIN_ID, SETTINGS_ACTION_SET_NAME),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SETTINGS_DOMAIN_ID, SETTINGS_ACTION_SET_TITLE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SETTINGS_DOMAIN_ID, SETTINGS_ACTION_SET_DESCRIPTION),
        handler,
    )?;

    registry.register_request_codec(Arc::new(nop_management_settings::SettingsGetRequestCodec))?;
    registry.register_request_codec(Arc::new(
        nop_management_settings::SettingsSetNameRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_settings::SettingsSetTitleRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_settings::SettingsSetDescriptionRequestCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::SettingsGetOkResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::MessageResponseCodec::new(SETTINGS_ACTION_GET_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::SettingsSetNameOkResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::MessageResponseCodec::new(SETTINGS_ACTION_SET_NAME_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::SettingsSetTitleOkResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::MessageResponseCodec::new(SETTINGS_ACTION_SET_TITLE_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::SettingsSetDescriptionOkResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_settings::MessageResponseCodec::new(SETTINGS_ACTION_SET_DESCRIPTION_ERR),
    ))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManagementBus, ManagementContext, build_default_registry};
    use nop_config::Config;
    use nop_management_contract::{ManagementCommand, ResponsePayload};
    use nop_management_settings::{
        SettingsCommand, SettingsGetRequest, SettingsSetDescriptionRequest, SettingsSetNameRequest,
        SettingsSetTitleRequest,
    };
    use nop_rt_release::ReleaseTracker;
    use nop_testing::test_fixtures::TestFixtureRoot;
    use std::fs;

    #[tokio::test]
    async fn settings_get_set_clear_persist_and_update_runtime_snapshot() {
        let fixture = TestFixtureRoot::new_unique("settings-management").unwrap();
        fixture.init_runtime_layout().unwrap();
        write_config(fixture.path());
        let validated_config = Arc::new(Config::load_and_validate(fixture.path()).unwrap());
        let runtime_paths = fixture.runtime_paths().unwrap();
        let release_tracker = Arc::new(ReleaseTracker::new());
        let initial_epoch = release_tracker.current();
        let context = ManagementContext::from_components(
            fixture.path().to_path_buf(),
            validated_config,
            runtime_paths,
        )
        .expect("context")
        .with_release_tracker(release_tracker.clone());
        let runtime_settings = context.runtime_settings.clone();
        let bus = ManagementBus::start(build_default_registry().expect("registry"), context);

        let response = bus
            .send(
                1,
                1,
                ManagementCommand::Settings(SettingsCommand::Get(SettingsGetRequest {})),
            )
            .await
            .expect("settings get");
        assert_eq!(response.action_id, SETTINGS_ACTION_GET_OK);
        assert_settings(&response, "NoPressure", None, Some("Test Description"));

        let response = bus
            .send(
                1,
                2,
                ManagementCommand::Settings(SettingsCommand::SetName(SettingsSetNameRequest {
                    name: "  Example Name  ".to_string(),
                })),
            )
            .await
            .expect("settings set name");
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_NAME_OK);
        assert_settings(&response, "Example Name", None, Some("Test Description"));
        assert_eq!(runtime_settings.name(), "Example Name");
        let name_epoch = release_tracker.current();
        assert!(name_epoch > initial_epoch);

        let response = bus
            .send(
                1,
                3,
                ManagementCommand::Settings(SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("  Example Site  ".to_string()),
                })),
            )
            .await
            .expect("settings set title");
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_settings(
            &response,
            "Example Name",
            Some("Example Site"),
            Some("Test Description"),
        );
        assert_eq!(
            runtime_settings.website_title().as_deref(),
            Some("Example Site")
        );
        let title_epoch = release_tracker.current();
        assert!(title_epoch > name_epoch);
        assert_eq!(
            Config::load(fixture.path())
                .unwrap()
                .settings
                .title
                .as_deref(),
            Some("Example Site")
        );

        let response = bus
            .send(
                1,
                4,
                ManagementCommand::Settings(SettingsCommand::SetDescription(
                    SettingsSetDescriptionRequest {
                        description: Some("  Example description  ".to_string()),
                    },
                )),
            )
            .await
            .expect("settings set description");
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_DESCRIPTION_OK);
        assert_settings(
            &response,
            "Example Name",
            Some("Example Site"),
            Some("Example description"),
        );
        let description_epoch = release_tracker.current();
        assert!(description_epoch > title_epoch);

        let response = bus
            .send(
                1,
                5,
                ManagementCommand::Settings(SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: None,
                })),
            )
            .await
            .expect("settings clear title");
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_settings(&response, "Example Name", None, Some("Example description"));
        assert_eq!(runtime_settings.website_title(), None);
        assert_eq!(Config::load(fixture.path()).unwrap().settings.title, None);
        assert!(release_tracker.current() > description_epoch);
    }

    fn assert_settings(
        response: &nop_management_contract::ManagementResponse,
        expected_name: &str,
        expected_title: Option<&str>,
        expected_description: Option<&str>,
    ) {
        match &response.payload {
            ResponsePayload::Settings(settings) => {
                assert_eq!(settings.name, expected_name);
                assert_eq!(settings.title.as_deref(), expected_title);
                assert_eq!(settings.description.as_deref(), expected_description);
            }
            _ => panic!("expected settings payload"),
        }
    }

    fn write_config(root: &std::path::Path) {
        fs::write(root.join("config.yaml"), test_config_yaml()).expect("write config");
        fs::write(root.join("users.yaml"), "{}\n").expect("write users");
    }

    fn test_config_yaml() -> &'static str {
        r#"server:
  host: "127.0.0.1"
  port: 8080
admin:
  path: "/admin"
users:
  auth_method: local
  local:
    jwt:
      secret: "test-secret"
      issuer: "nopressure"
      audience: "nopressure-users"
      expiration_hours: 12
      cookie_name: "nop_auth"
      force_secure_cookie: false
      disable_refresh: false
      refresh_threshold_percentage: 10
      refresh_threshold_hours: 24
    password:
      memory_cost: 65536
      time_cost: 3
      parallelism: 4
      output_length: 32
      salt_length: 32
    password_complexity_disabled: false
navigation:
  max_dropdown_items: 7
logging:
  level: info
  rotation:
    max_size_mb: 10
    max_files: 5
security:
  max_violations: 10
  cooldown_seconds: 60
  use_forwarded_for: false
  login_sessions:
    timeout_minutes: 480
    absolute_timeout_hours: 24
  hsts_enabled: false
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  hsts_preload: false
app:
  name: "Test App"
  description: "Test Description"
upload:
  max_file_size_mb: 100
  allowed_extensions: ["md"]
streaming:
  enabled: false
shortcodes:
  builtin:
    enabled: true
search:
  enabled: false
settings:
  name: "NoPressure"
  title: null
  description: null
"#
    }
}
