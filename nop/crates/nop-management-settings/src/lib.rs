// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_config::{
    RuntimeSettings, SettingsConfig, WEBSITE_DESCRIPTION_MAX_CHARS, WEBSITE_NAME_MAX_CHARS,
    WEBSITE_TITLE_MAX_CHARS, normalize_optional_setting, normalize_required_setting,
};
pub use nop_management_contract::settings::{
    SETTINGS_ACTION_GET, SETTINGS_ACTION_GET_ERR, SETTINGS_ACTION_GET_OK,
    SETTINGS_ACTION_SET_DESCRIPTION, SETTINGS_ACTION_SET_DESCRIPTION_ERR,
    SETTINGS_ACTION_SET_DESCRIPTION_OK, SETTINGS_ACTION_SET_NAME, SETTINGS_ACTION_SET_NAME_ERR,
    SETTINGS_ACTION_SET_NAME_OK, SETTINGS_ACTION_SET_TITLE, SETTINGS_ACTION_SET_TITLE_ERR,
    SETTINGS_ACTION_SET_TITLE_OK, SETTINGS_DOMAIN_ID, SettingsCommand, SettingsGetRequest,
    SettingsResponse, SettingsSetDescriptionRequest, SettingsSetNameRequest,
    SettingsSetTitleRequest,
};
use nop_management_contract::{
    FieldLimit, FieldLimits, FieldValues, ManagementCommand, ManagementRequest, ManagementResponse,
    ResponsePayload, define_message_response_codec, define_request_codec, define_response_codec,
};
use nop_management_errors::DomainResult;
use std::path::Path;

pub trait SettingsContext {
    fn runtime_root(&self) -> &Path;
    fn runtime_settings(&self) -> &RuntimeSettings;

    fn bump_website_epoch(&self, _reason: &str) {}
}

fn validate_set_name(request: &SettingsSetNameRequest) -> Result<(), String> {
    normalize_required_setting("settings.name", &request.name, WEBSITE_NAME_MAX_CHARS)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn validate_set_title(request: &SettingsSetTitleRequest) -> Result<(), String> {
    normalize_optional_setting(
        "settings.title",
        request.title.as_deref(),
        WEBSITE_TITLE_MAX_CHARS,
    )
    .map(|_| ())
    .map_err(|err| err.to_string())
}

fn validate_set_description(request: &SettingsSetDescriptionRequest) -> Result<(), String> {
    normalize_optional_setting(
        "settings.description",
        request.description.as_deref(),
        WEBSITE_DESCRIPTION_MAX_CHARS,
    )
    .map(|_| ())
    .map_err(|err| err.to_string())
}

fn optional_field_values(field: &'static str, value: Option<&String>) -> FieldValues {
    let mut values = FieldValues::new();
    if let Some(value) = value {
        values.insert_len(field, value.chars().count());
    }
    values
}

fn name_field_values(name: &str) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("name", name.chars().count());
    values
}

fn settings_response_field_values(settings: &SettingsResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("name", settings.name.chars().count());
    if let Some(title) = &settings.title {
        values.insert_len("title", title.chars().count());
    }
    if let Some(description) = &settings.description {
        values.insert_len("description", description.chars().count());
    }
    values
}

fn settings_response_limits() -> FieldLimits {
    FieldLimits::new(vec![
        ("name", FieldLimit::MaxChars(WEBSITE_NAME_MAX_CHARS)),
        ("title", FieldLimit::MaxChars(WEBSITE_TITLE_MAX_CHARS)),
        (
            "description",
            FieldLimit::MaxChars(WEBSITE_DESCRIPTION_MAX_CHARS),
        ),
    ])
}

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = SETTINGS_DOMAIN_ID,
    error = "Unsupported response payload for settings message codec",
);

define_request_codec!(
    SettingsGetRequestCodec,
    domain = Settings,
    command = SettingsCommand,
    variant = Get,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_GET,
    request = SettingsGetRequest,
    validate = |_request| Ok::<(), String>(()),
    limits = FieldLimits::new(vec![]),
    values = |_request| FieldValues::new(),
    error = "Unsupported request payload for settings get codec",
);

define_request_codec!(
    SettingsSetNameRequestCodec,
    domain = Settings,
    command = SettingsCommand,
    variant = SetName,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_NAME,
    request = SettingsSetNameRequest,
    validate = |request| validate_set_name(request),
    limits = FieldLimits::new(vec![("name", FieldLimit::MaxChars(WEBSITE_NAME_MAX_CHARS))]),
    values = |request| name_field_values(&request.name),
    error = "Unsupported request payload for settings name codec",
);

define_request_codec!(
    SettingsSetTitleRequestCodec,
    domain = Settings,
    command = SettingsCommand,
    variant = SetTitle,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_TITLE,
    request = SettingsSetTitleRequest,
    validate = |request| validate_set_title(request),
    limits = FieldLimits::new(vec![(
        "title",
        FieldLimit::MaxChars(WEBSITE_TITLE_MAX_CHARS)
    )]),
    values = |request| optional_field_values("title", request.title.as_ref()),
    error = "Unsupported request payload for settings title codec",
);

define_request_codec!(
    SettingsSetDescriptionRequestCodec,
    domain = Settings,
    command = SettingsCommand,
    variant = SetDescription,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_DESCRIPTION,
    request = SettingsSetDescriptionRequest,
    validate = |request| validate_set_description(request),
    limits = FieldLimits::new(vec![(
        "description",
        FieldLimit::MaxChars(WEBSITE_DESCRIPTION_MAX_CHARS),
    )]),
    values = |request| optional_field_values("description", request.description.as_ref()),
    error = "Unsupported request payload for settings description codec",
);

define_response_codec!(
    SettingsGetOkResponseCodec,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_GET_OK,
    payload = Settings,
    response = SettingsResponse,
    limits = settings_response_limits(),
    values = |payload| settings_response_field_values(payload),
    error = "Unsupported response payload for settings response codec",
);

define_response_codec!(
    SettingsSetNameOkResponseCodec,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_NAME_OK,
    payload = Settings,
    response = SettingsResponse,
    limits = settings_response_limits(),
    values = |payload| settings_response_field_values(payload),
    error = "Unsupported response payload for settings response codec",
);

define_response_codec!(
    SettingsSetTitleOkResponseCodec,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_TITLE_OK,
    payload = Settings,
    response = SettingsResponse,
    limits = settings_response_limits(),
    values = |payload| settings_response_field_values(payload),
    error = "Unsupported response payload for settings response codec",
);

define_response_codec!(
    SettingsSetDescriptionOkResponseCodec,
    domain_id = SETTINGS_DOMAIN_ID,
    action_id = SETTINGS_ACTION_SET_DESCRIPTION_OK,
    payload = Settings,
    response = SettingsResponse,
    limits = settings_response_limits(),
    values = |payload| settings_response_field_values(payload),
    error = "Unsupported response payload for settings response codec",
);

pub async fn handle_settings_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SettingsContext,
{
    let workflow_id = request.workflow_id;
    let command = match request.command {
        ManagementCommand::Settings(command) => command,
        _ => {
            return Ok(response_err(
                SETTINGS_ACTION_GET_ERR,
                workflow_id,
                "Invalid settings command",
            ));
        }
    };

    let response = match command {
        SettingsCommand::Get(_) => handle_get(workflow_id, context).await,
        SettingsCommand::SetName(payload) => handle_set_name(payload, workflow_id, context).await,
        SettingsCommand::SetTitle(payload) => handle_set_title(payload, workflow_id, context).await,
        SettingsCommand::SetDescription(payload) => {
            handle_set_description(payload, workflow_id, context).await
        }
    };

    Ok(response)
}

async fn handle_get<C>(workflow_id: u32, context: &C) -> ManagementResponse
where
    C: SettingsContext,
{
    settings_response(
        SETTINGS_ACTION_GET_OK,
        workflow_id,
        context.runtime_settings().snapshot(),
    )
}

async fn handle_set_name<C>(
    payload: SettingsSetNameRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SettingsContext,
{
    let normalized =
        match normalize_required_setting("settings.name", &payload.name, WEBSITE_NAME_MAX_CHARS) {
            Ok(value) => value,
            Err(err) => {
                return response_err(SETTINGS_ACTION_SET_NAME_ERR, workflow_id, &err.to_string());
            }
        };

    persist_and_update(
        SETTINGS_ACTION_SET_NAME_OK,
        SETTINGS_ACTION_SET_NAME_ERR,
        workflow_id,
        context,
        "settings.name",
        |settings| settings.name = Some(normalized),
    )
}

async fn handle_set_title<C>(
    payload: SettingsSetTitleRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SettingsContext,
{
    let normalized = match normalize_optional_setting(
        "settings.title",
        payload.title.as_deref(),
        WEBSITE_TITLE_MAX_CHARS,
    ) {
        Ok(value) => value,
        Err(err) => {
            return response_err(SETTINGS_ACTION_SET_TITLE_ERR, workflow_id, &err.to_string());
        }
    };

    persist_and_update(
        SETTINGS_ACTION_SET_TITLE_OK,
        SETTINGS_ACTION_SET_TITLE_ERR,
        workflow_id,
        context,
        "settings.title",
        |settings| settings.title = normalized,
    )
}

async fn handle_set_description<C>(
    payload: SettingsSetDescriptionRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SettingsContext,
{
    let normalized = match normalize_optional_setting(
        "settings.description",
        payload.description.as_deref(),
        WEBSITE_DESCRIPTION_MAX_CHARS,
    ) {
        Ok(value) => value,
        Err(err) => {
            return response_err(
                SETTINGS_ACTION_SET_DESCRIPTION_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    persist_and_update(
        SETTINGS_ACTION_SET_DESCRIPTION_OK,
        SETTINGS_ACTION_SET_DESCRIPTION_ERR,
        workflow_id,
        context,
        "settings.description",
        |settings| settings.description = normalized,
    )
}

fn persist_and_update<C>(
    ok_action_id: u32,
    err_action_id: u32,
    workflow_id: u32,
    context: &C,
    epoch_reason: &'static str,
    update: impl FnOnce(&mut SettingsConfig),
) -> ManagementResponse
where
    C: SettingsContext,
{
    let previous_settings = context.runtime_settings().snapshot();
    let mut settings = previous_settings.clone();
    update(&mut settings);

    let persisted = match nop_config::Config::persist_settings(context.runtime_root(), &settings) {
        Ok(settings) => settings,
        Err(err) => {
            return response_err(err_action_id, workflow_id, &err.to_string());
        }
    };

    context.runtime_settings().set_settings(&persisted);
    if persisted != previous_settings {
        context.bump_website_epoch(epoch_reason);
    }

    settings_response(
        ok_action_id,
        workflow_id,
        context.runtime_settings().snapshot(),
    )
}

fn settings_response(
    action_id: u32,
    workflow_id: u32,
    settings: SettingsConfig,
) -> ManagementResponse {
    ManagementResponse {
        domain_id: SETTINGS_DOMAIN_ID,
        action_id,
        workflow_id,
        payload: ResponsePayload::Settings(SettingsResponse {
            name: settings.name_or_default(),
            title: settings.title,
            description: settings.description,
        }),
    }
}

fn response_err(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    ManagementResponse::message(SETTINGS_DOMAIN_ID, action_id, workflow_id, message).unwrap_or_else(
        |_| ManagementResponse {
            domain_id: SETTINGS_DOMAIN_ID,
            action_id,
            workflow_id,
            payload: ResponsePayload::Message(nop_management_contract::MessageResponse {
                message: "Settings request failed".to_string(),
            }),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_management_contract::{RequestCodec, ResponseCodec};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct TestContext {
        root: TempDir,
        runtime_settings: RuntimeSettings,
        website_epoch_bumps: AtomicUsize,
    }

    impl TestContext {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            fs::write(root.path().join("config.yaml"), test_config_yaml()).expect("write config");
            Self {
                root,
                runtime_settings: RuntimeSettings::new(&SettingsConfig::default()),
                website_epoch_bumps: AtomicUsize::new(0),
            }
        }

        fn website_epoch_bumps(&self) -> usize {
            self.website_epoch_bumps.load(Ordering::SeqCst)
        }
    }

    impl SettingsContext for TestContext {
        fn runtime_root(&self) -> &Path {
            self.root.path()
        }

        fn runtime_settings(&self) -> &RuntimeSettings {
            &self.runtime_settings
        }

        fn bump_website_epoch(&self, _reason: &str) {
            self.website_epoch_bumps.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn set_title_request_codec_roundtrips_and_validates_limits() {
        let codec = SettingsSetTitleRequestCodec;
        let command =
            ManagementCommand::Settings(SettingsCommand::SetTitle(SettingsSetTitleRequest {
                title: Some("Example Site".to_string()),
            }));

        codec.validate(&command).expect("valid");
        let encoded = codec.encode(&command).expect("encode");
        let decoded = codec.decode(&encoded).expect("decode");
        match decoded {
            ManagementCommand::Settings(SettingsCommand::SetTitle(request)) => {
                assert_eq!(request.title.as_deref(), Some("Example Site"));
            }
            _ => panic!("unexpected command"),
        }

        let invalid =
            ManagementCommand::Settings(SettingsCommand::SetTitle(SettingsSetTitleRequest {
                title: Some("x".repeat(WEBSITE_TITLE_MAX_CHARS + 1)),
            }));
        assert!(codec.validate(&invalid).is_err());
    }

    #[test]
    fn settings_response_codec_roundtrips_identity() {
        let codec = SettingsGetOkResponseCodec;
        let response = ManagementResponse {
            domain_id: SETTINGS_DOMAIN_ID,
            action_id: SETTINGS_ACTION_GET_OK,
            workflow_id: 7,
            payload: ResponsePayload::Settings(SettingsResponse {
                name: "Example".to_string(),
                title: Some("Example Site".to_string()),
                description: Some("Example description".to_string()),
            }),
        };

        codec.validate(&response).expect("valid");
        let encoded = codec.encode(&response).expect("encode");
        let decoded = codec.decode(&encoded).expect("decode");
        match decoded {
            ResponsePayload::Settings(settings) => {
                assert_eq!(settings.name, "Example");
                assert_eq!(settings.title.as_deref(), Some("Example Site"));
                assert_eq!(settings.description.as_deref(), Some("Example description"));
            }
            _ => panic!("unexpected response payload"),
        }
    }

    #[tokio::test]
    async fn handler_get_set_clear_persist_and_update_runtime_settings() {
        let context = TestContext::new();

        let response = handle_settings_request(
            request(1, SettingsCommand::Get(SettingsGetRequest {})),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("get: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_GET_OK);
        assert_settings(&response, "NoPressure", None, None);

        let response = handle_settings_request(
            request(
                2,
                SettingsCommand::SetName(SettingsSetNameRequest {
                    name: "  Example Name  ".to_string(),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set name: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_NAME_OK);
        assert_settings(&response, "Example Name", None, Some("Test Description"));
        assert_eq!(context.runtime_settings.name(), "Example Name");
        assert_eq!(context.website_epoch_bumps(), 1);

        let response = handle_settings_request(
            request(
                3,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("  Example Site  ".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set title: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_settings(
            &response,
            "Example Name",
            Some("Example Site"),
            Some("Test Description"),
        );
        assert_eq!(context.website_epoch_bumps(), 2);

        let persisted = nop_config::Config::load(context.root.path()).expect("load persisted");
        assert_eq!(persisted.settings.name.as_deref(), Some("Example Name"));
        assert_eq!(persisted.settings.title.as_deref(), Some("Example Site"));

        let response = handle_settings_request(
            request(
                4,
                SettingsCommand::SetDescription(SettingsSetDescriptionRequest {
                    description: Some("  Example description  ".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set description: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_DESCRIPTION_OK);
        assert_settings(
            &response,
            "Example Name",
            Some("Example Site"),
            Some("Example description"),
        );
        assert_eq!(context.website_epoch_bumps(), 3);

        let response = handle_settings_request(
            request(
                5,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("   ".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("clear title: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_settings(&response, "Example Name", None, Some("Example description"));
        assert_eq!(context.runtime_settings.website_title(), None);
        assert_eq!(context.website_epoch_bumps(), 4);
    }

    #[tokio::test]
    async fn handler_does_not_bump_website_epoch_for_noop_or_rejected_update() {
        let context = TestContext::new();

        let response = handle_settings_request(
            request(
                1,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("Example Site".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set title: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_eq!(context.website_epoch_bumps(), 1);

        let response = handle_settings_request(
            request(
                2,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("  Example Site  ".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set title noop: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
        assert_eq!(context.website_epoch_bumps(), 1);

        let response = handle_settings_request(
            request(
                3,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("Example\nSite".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set title invalid: {}", err));
        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_ERR);
        assert_eq!(context.website_epoch_bumps(), 1);
    }

    #[tokio::test]
    async fn handler_rejects_invalid_title() {
        let context = TestContext::new();
        let response = handle_settings_request(
            request(
                4,
                SettingsCommand::SetTitle(SettingsSetTitleRequest {
                    title: Some("Example\nSite".to_string()),
                }),
            ),
            &context,
        )
        .await
        .unwrap_or_else(|err| panic!("set: {}", err));

        assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_ERR);
        match response.payload {
            ResponsePayload::Message(message) => {
                assert!(message.message.contains("ASCII control characters"));
            }
            _ => panic!("expected message payload"),
        }
    }

    fn request(workflow_id: u32, command: SettingsCommand) -> ManagementRequest {
        ManagementRequest {
            workflow_id,
            connection_id: 1,
            command: ManagementCommand::Settings(command),
            actor_email: None,
        }
    }

    fn assert_settings(
        response: &ManagementResponse,
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
