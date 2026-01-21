// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]
#![allow(unused_imports)]

macro_rules! define_domain_responses {
    ($domain_id:expr) => {
        fn response_ok(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> crate::management::ManagementResponse {
            crate::management::ManagementResponse::message(
                $domain_id,
                action_id,
                workflow_id,
                message,
            )
            .unwrap_or_else(|_| crate::management::ManagementResponse {
                domain_id: $domain_id,
                action_id,
                workflow_id,
                payload: crate::management::ResponsePayload::Message(
                    crate::management::MessageResponse {
                        message: message.to_string(),
                    },
                ),
            })
        }

        fn response_err(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> crate::management::ManagementResponse {
            crate::management::ManagementResponse::message(
                $domain_id,
                action_id,
                workflow_id,
                message,
            )
            .unwrap_or_else(|_| crate::management::ManagementResponse {
                domain_id: $domain_id,
                action_id,
                workflow_id,
                payload: crate::management::ResponsePayload::Message(
                    crate::management::MessageResponse {
                        message: message.to_string(),
                    },
                ),
            })
        }
    };
    ($domain_id:expr, ok_fallback = $ok_fallback:expr, err_fallback = $err_fallback:expr) => {
        fn response_ok(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> crate::management::ManagementResponse {
            crate::management::ManagementResponse::message(
                $domain_id,
                action_id,
                workflow_id,
                message,
            )
            .unwrap_or_else(|_| crate::management::ManagementResponse {
                domain_id: $domain_id,
                action_id,
                workflow_id,
                payload: crate::management::ResponsePayload::Message(
                    crate::management::MessageResponse {
                        message: $ok_fallback.to_string(),
                    },
                ),
            })
        }

        fn response_err(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> crate::management::ManagementResponse {
            crate::management::ManagementResponse::message(
                $domain_id,
                action_id,
                workflow_id,
                message,
            )
            .unwrap_or_else(|_| crate::management::ManagementResponse {
                domain_id: $domain_id,
                action_id,
                workflow_id,
                payload: crate::management::ResponsePayload::Message(
                    crate::management::MessageResponse {
                        message: $err_fallback.to_string(),
                    },
                ),
            })
        }
    };
}

macro_rules! define_request_codec {
    (
        $codec:ident,
        domain = $domain_enum:ident,
        command = $command_enum:ident,
        variant = $variant:ident,
        domain_id = $domain_id:expr,
        action_id = $action_id:expr,
        request = $request_ty:ty,
        limits = $limits:expr,
        values = |$request:ident| $values:expr,
        error = $error:literal $(,)?
    ) => {
        struct $codec;

        impl crate::management::RequestCodec for $codec {
            fn key(&self) -> crate::management::DomainActionKey {
                crate::management::DomainActionKey::new($domain_id, $action_id)
            }

            fn limits(&self) -> crate::management::FieldLimits {
                $limits
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<crate::management::ManagementCommand, crate::management::CodecError> {
                let request: $request_ty = crate::management::codec::decode_payload(payload)?;
                Ok(crate::management::ManagementCommand::$domain_enum(
                    $command_enum::$variant(request),
                ))
            }

            fn encode(
                &self,
                command: &crate::management::ManagementCommand,
            ) -> Result<Vec<u8>, crate::management::CodecError> {
                match command {
                    crate::management::ManagementCommand::$domain_enum(
                        $command_enum::$variant(request),
                    ) => crate::management::codec::encode_payload(request),
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn validate(
                &self,
                command: &crate::management::ManagementCommand,
            ) -> Result<(), crate::management::CodecError> {
                match command {
                    crate::management::ManagementCommand::$domain_enum(
                        $command_enum::$variant($request),
                    ) => {
                        $request.validate().map_err(|err| {
                            crate::management::CodecError::new(
                                crate::management::ManagementErrorKind::Validation,
                                err.to_string(),
                            )
                        })?;
                        let values = $values;
                        crate::management::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

macro_rules! define_response_codec {
    (
        $codec:ident,
        domain_id = $domain_id:expr,
        action_id = $action_id:expr,
        payload = $payload_variant:ident,
        response = $response_ty:ty,
        limits = $limits:expr,
        values = |$payload:ident| $values:expr,
        error = $error:literal $(,)?
    ) => {
        struct $codec;

        impl crate::management::ResponseCodec for $codec {
            fn key(&self) -> crate::management::DomainActionKey {
                crate::management::DomainActionKey::new($domain_id, $action_id)
            }

            fn limits(&self) -> crate::management::FieldLimits {
                $limits
            }

            fn encode(
                &self,
                response: &crate::management::ManagementResponse,
            ) -> Result<Vec<u8>, crate::management::CodecError> {
                match &response.payload {
                    crate::management::ResponsePayload::$payload_variant($payload) => {
                        crate::management::codec::encode_payload($payload)
                    }
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<crate::management::ResponsePayload, crate::management::CodecError> {
                let response: $response_ty = crate::management::codec::decode_payload(payload)?;
                Ok(crate::management::ResponsePayload::$payload_variant(
                    response,
                ))
            }

            fn validate(
                &self,
                response: &crate::management::ManagementResponse,
            ) -> Result<(), crate::management::CodecError> {
                match &response.payload {
                    crate::management::ResponsePayload::$payload_variant($payload) => {
                        let values = $values;
                        crate::management::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

macro_rules! define_message_response_codec {
    (
        $codec:ident,
        domain_id = $domain_id:expr,
        error = $error:literal $(,)?
    ) => {
        struct $codec {
            action_id: u32,
        }

        impl $codec {
            fn new(action_id: u32) -> Self {
                Self { action_id }
            }
        }

        impl crate::management::ResponseCodec for $codec {
            fn key(&self) -> crate::management::DomainActionKey {
                crate::management::DomainActionKey::new($domain_id, self.action_id)
            }

            fn limits(&self) -> crate::management::FieldLimits {
                crate::management::FieldLimits::new(vec![(
                    "message",
                    crate::management::FieldLimit::MaxChars(1024),
                )])
            }

            fn encode(
                &self,
                response: &crate::management::ManagementResponse,
            ) -> Result<Vec<u8>, crate::management::CodecError> {
                match &response.payload {
                    crate::management::ResponsePayload::Message(payload) => {
                        crate::management::codec::encode_payload(payload)
                    }
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<crate::management::ResponsePayload, crate::management::CodecError> {
                let response: crate::management::MessageResponse =
                    crate::management::codec::decode_payload(payload)?;
                let message =
                    crate::management::MessageResponse::new(response.message).map_err(|err| {
                        crate::management::CodecError::new(
                            crate::management::ManagementErrorKind::Codec,
                            err.to_string(),
                        )
                    })?;
                Ok(crate::management::ResponsePayload::Message(message))
            }

            fn validate(
                &self,
                response: &crate::management::ManagementResponse,
            ) -> Result<(), crate::management::CodecError> {
                match &response.payload {
                    crate::management::ResponsePayload::Message(payload) => {
                        let mut values = crate::management::FieldValues::new();
                        values.insert_len("message", payload.message.chars().count());
                        crate::management::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err(crate::management::CodecError::new(
                        crate::management::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

macro_rules! register_request_codecs {
    ($registry:expr, [$( $codec:expr ),+ $(,)?]) => {
        $(
            $registry.register_request_codec(std::sync::Arc::new($codec))?;
        )+
    };
}

macro_rules! register_response_codecs {
    ($registry:expr, [$( $codec:expr ),+ $(,)?]) => {
        $(
            $registry.register_response_codec(std::sync::Arc::new($codec))?;
        )+
    };
}

mod blocking;
mod bus;
pub mod cli;
pub mod cli_helper;
mod codec;
mod connection_ids;
mod content;
mod core;
mod errors;
mod registry;
mod roles;
pub mod socket;
mod system;
mod tags;
mod upload_registry;
mod users;
mod wire;
mod workflow;
pub mod ws;
mod yaml_store;

pub use blocking::{BlockingError, BlockingPool};
pub use bus::ManagementBus;
pub use codec::{
    CodecError, CodecRegistry, FieldLimit, FieldLimits, FieldValue, FieldValues, RequestCodec,
    ResponseCodec, validate_field_limits,
};
pub use connection_ids::next_connection_id;
pub use content::{
    BinaryPrevalidateRequest, BinaryPrevalidateResponse, BinaryUploadCommitRequest,
    BinaryUploadInitRequest, CONTENT_ACTION_BINARY_PREVALIDATE,
    CONTENT_ACTION_BINARY_PREVALIDATE_ERR, CONTENT_ACTION_BINARY_PREVALIDATE_OK,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK, CONTENT_ACTION_BINARY_UPLOAD_INIT,
    CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
    CONTENT_ACTION_DELETE, CONTENT_ACTION_DELETE_ERR, CONTENT_ACTION_DELETE_OK,
    CONTENT_ACTION_LIST, CONTENT_ACTION_LIST_ERR, CONTENT_ACTION_LIST_OK, CONTENT_ACTION_NAV_INDEX,
    CONTENT_ACTION_NAV_INDEX_ERR, CONTENT_ACTION_NAV_INDEX_OK, CONTENT_ACTION_READ,
    CONTENT_ACTION_READ_ERR, CONTENT_ACTION_READ_OK, CONTENT_ACTION_UPDATE,
    CONTENT_ACTION_UPDATE_ERR, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPDATE_STREAM_COMMIT,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR, CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPDATE_STREAM_INIT, CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
    CONTENT_ACTION_UPDATE_STREAM_INIT_OK, CONTENT_ACTION_UPLOAD, CONTENT_ACTION_UPLOAD_ERR,
    CONTENT_ACTION_UPLOAD_OK, CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
    CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPLOAD_STREAM_INIT, CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
    CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, CONTENT_DOMAIN_ID, ContentCommand, ContentDeleteRequest,
    ContentListRequest, ContentListResponse, ContentNavIndexEntry, ContentNavIndexRequest,
    ContentNavIndexResponse, ContentReadRequest, ContentReadResponse, ContentSortDirection,
    ContentSortField, ContentSummary, ContentUpdateRequest, ContentUpdateStreamCommitRequest,
    ContentUpdateStreamInitRequest, ContentUploadRequest, ContentUploadResponse,
    ContentUploadStreamCommitRequest, ContentUploadStreamInitRequest, UploadStreamInitResponse,
};
pub use core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse, MessageResponse,
    ResponsePayload, VersionInfo,
};
pub use errors::{DomainError, DomainResult, ManagementError, ManagementErrorKind};
pub use registry::{
    ActionDescriptor, DomainActionKey, DomainDescriptor, ManagementHandler, ManagementRegistry,
    RegistryError,
};
pub(crate) use roles::RoleStore;
pub use roles::{
    ROLE_ACTION_ADD, ROLE_ACTION_ADD_ERR, ROLE_ACTION_ADD_OK, ROLE_ACTION_CHANGE,
    ROLE_ACTION_CHANGE_ERR, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE, ROLE_ACTION_DELETE_ERR,
    ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST, ROLE_ACTION_LIST_ERR, ROLE_ACTION_LIST_OK,
    ROLE_ACTION_SHOW, ROLE_ACTION_SHOW_ERR, ROLE_ACTION_SHOW_OK, ROLES_DOMAIN_ID, RoleAddRequest,
    RoleChangeRequest, RoleCommand, RoleDeleteRequest, RoleListRequest, RoleListResponse,
    RoleShowRequest, RoleShowResponse,
};
pub use system::{
    ClearLogsRequest, ClearLogsResponse, GetLoggingConfigRequest, LoggingConfigResponse,
    PingRequest, PongErrorResponse, PongResponse, SYSTEM_ACTION_LOGGING_CLEAR,
    SYSTEM_ACTION_LOGGING_CLEAR_ERR, SYSTEM_ACTION_LOGGING_CLEAR_OK, SYSTEM_ACTION_LOGGING_GET,
    SYSTEM_ACTION_LOGGING_GET_ERR, SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_LOGGING_SET,
    SYSTEM_ACTION_LOGGING_SET_ERR, SYSTEM_ACTION_LOGGING_SET_OK, SYSTEM_ACTION_PING,
    SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, SetLoggingConfigRequest,
};
pub use tags::{
    AccessRule, TAG_ACTION_ADD, TAG_ACTION_ADD_ERR, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
    TAG_ACTION_CHANGE_ERR, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_ERR,
    TAG_ACTION_DELETE_OK, TAG_ACTION_LIST, TAG_ACTION_LIST_ERR, TAG_ACTION_LIST_OK,
    TAG_ACTION_SHOW, TAG_ACTION_SHOW_ERR, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest,
    TagChangeRequest, TagCommand, TagDeleteRequest, TagListRequest, TagListResponse,
    TagShowRequest, TagShowResponse, TagSummary,
};
pub(crate) use tags::{TagRecord, TagStore};
pub use upload_registry::UploadRegistry;
pub use users::{
    PasswordPayload, PasswordSaltResponse, PasswordValidateResponse, USER_ACTION_ADD,
    USER_ACTION_ADD_ERR, USER_ACTION_ADD_OK, USER_ACTION_CHANGE, USER_ACTION_CHANGE_ERR,
    USER_ACTION_CHANGE_OK, USER_ACTION_DELETE, USER_ACTION_DELETE_ERR, USER_ACTION_DELETE_OK,
    USER_ACTION_LIST, USER_ACTION_LIST_ERR, USER_ACTION_LIST_OK, USER_ACTION_PASSWORD_SALT,
    USER_ACTION_PASSWORD_SALT_ERR, USER_ACTION_PASSWORD_SALT_OK, USER_ACTION_PASSWORD_SET,
    USER_ACTION_PASSWORD_SET_ERR, USER_ACTION_PASSWORD_SET_OK, USER_ACTION_PASSWORD_UPDATE,
    USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_UPDATE_OK, USER_ACTION_PASSWORD_VALIDATE,
    USER_ACTION_PASSWORD_VALIDATE_ERR, USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD,
    USER_ACTION_ROLE_ADD_ERR, USER_ACTION_ROLE_ADD_OK, USER_ACTION_ROLE_REMOVE,
    USER_ACTION_ROLE_REMOVE_ERR, USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_ROLES_LIST,
    USER_ACTION_ROLES_LIST_ERR, USER_ACTION_ROLES_LIST_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_ERR,
    USER_ACTION_SHOW_OK, USERS_DOMAIN_ID, UserAddRequest, UserChangeRequest, UserCommand,
    UserDeleteRequest, UserListRequest, UserListResponse, UserPasswordSaltRequest,
    UserPasswordSetRequest, UserPasswordUpdateRequest, UserPasswordValidateRequest,
    UserRoleAddRequest, UserRoleRemoveRequest, UserRolesListRequest, UserRolesListResponse,
    UserShowRequest, UserShowResponse, UserSummary,
};
pub use wire::{OptionMap, WireDecode, WireEncode, WireError, WireReader, WireResult, WireWriter};
pub use workflow::{WorkflowCounter, WorkflowTracker};

pub fn build_default_registry() -> Result<ManagementRegistry, RegistryError> {
    let mut registry = ManagementRegistry::new();
    system::register(&mut registry)?;
    users::register(&mut registry)?;
    roles::register(&mut registry)?;
    tags::register(&mut registry)?;
    content::register(&mut registry)?;
    Ok(registry)
}
