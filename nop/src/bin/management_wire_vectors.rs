// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop::management;
use nop::management::WireEncode;
use nop::management::WireWriter;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize)]
struct VectorFile {
    version: u32,
    entries: Vec<VectorEntry>,
}

#[derive(Serialize)]
struct VectorEntry {
    name: String,
    direction: String,
    domain_id: u32,
    action_id: u32,
    payload: Value,
    hex: String,
}

fn main() {
    let mut entries = Vec::new();

    system_entries(&mut entries);
    user_entries(&mut entries);
    tag_entries(&mut entries);
    role_entries(&mut entries);
    content_entries(&mut entries);

    let file = VectorFile {
        version: 1,
        entries,
    };
    let json = serde_json::to_string_pretty(&file).expect("serialize fixtures");

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("management-wire-vectors.json");
    fs::write(&path, format!("{}\n", json)).expect("write fixtures");
}

fn encode_payload<T: WireEncode>(payload: &T) -> Vec<u8> {
    let mut writer = WireWriter::new();
    payload.encode(&mut writer).expect("encode payload");
    writer.into_bytes()
}

fn push_request<T: Serialize + WireEncode>(
    entries: &mut Vec<VectorEntry>,
    name: &str,
    domain_id: u32,
    action_id: u32,
    payload: T,
) {
    push_entry(entries, name, "request", domain_id, action_id, payload);
}

fn push_response<T: Serialize + WireEncode>(
    entries: &mut Vec<VectorEntry>,
    name: &str,
    domain_id: u32,
    action_id: u32,
    payload: T,
) {
    push_entry(entries, name, "response", domain_id, action_id, payload);
}

fn push_entry<T: Serialize + WireEncode>(
    entries: &mut Vec<VectorEntry>,
    name: &str,
    direction: &str,
    domain_id: u32,
    action_id: u32,
    payload: T,
) {
    let hex = hex::encode(encode_payload(&payload));
    let payload = serde_json::to_value(payload).expect("serialize payload");
    entries.push(VectorEntry {
        name: name.to_string(),
        direction: direction.to_string(),
        domain_id,
        action_id,
        payload,
        hex,
    });
}

fn system_entries(entries: &mut Vec<VectorEntry>) {
    use management::{
        ClearLogsRequest, ClearLogsResponse, GetLoggingConfigRequest, LoggingConfigResponse,
        PingRequest, PongErrorResponse, PongResponse, SYSTEM_ACTION_LOGGING_CLEAR,
        SYSTEM_ACTION_LOGGING_CLEAR_ERR, SYSTEM_ACTION_LOGGING_CLEAR_OK, SYSTEM_ACTION_LOGGING_GET,
        SYSTEM_ACTION_LOGGING_GET_ERR, SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_LOGGING_SET,
        SYSTEM_ACTION_LOGGING_SET_ERR, SYSTEM_ACTION_LOGGING_SET_OK, SYSTEM_ACTION_PING,
        SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, SetLoggingConfigRequest,
    };

    push_request(
        entries,
        "system.ping.request",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_PING,
        PingRequest {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
        },
    );
    push_request(
        entries,
        "system.logging_get.request",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_GET,
        GetLoggingConfigRequest {},
    );
    push_request(
        entries,
        "system.logging_set.request",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_SET,
        SetLoggingConfigRequest {
            rotation_max_size_mb: 128,
            rotation_max_files: 7,
        },
    );
    push_request(
        entries,
        "system.logging_clear.request",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_CLEAR,
        ClearLogsRequest {},
    );

    push_response(
        entries,
        "system.pong.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_PONG,
        PongResponse {
            message: "ok".to_string(),
        },
    );
    push_response(
        entries,
        "system.pong_error.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_PONG_ERROR,
        PongErrorResponse {
            message: "version mismatch".to_string(),
        },
    );
    push_response(
        entries,
        "system.logging_get_ok.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_GET_OK,
        LoggingConfigResponse {
            level: "info".to_string(),
            rotation_max_size_mb: 256,
            rotation_max_files: 5,
            run_mode: "daemon".to_string(),
            file_logging_active: true,
        },
    );
    push_response(
        entries,
        "system.logging_get_err.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_GET_ERR,
        management::MessageResponse {
            message: "logging not configured".to_string(),
        },
    );
    push_response(
        entries,
        "system.logging_set_ok.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_SET_OK,
        LoggingConfigResponse {
            level: "debug".to_string(),
            rotation_max_size_mb: 512,
            rotation_max_files: 9,
            run_mode: "daemon".to_string(),
            file_logging_active: true,
        },
    );
    push_response(
        entries,
        "system.logging_set_err.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_SET_ERR,
        management::MessageResponse {
            message: "invalid rotation size".to_string(),
        },
    );
    push_response(
        entries,
        "system.logging_clear_ok.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_CLEAR_OK,
        ClearLogsResponse {
            message: "cleared".to_string(),
            deleted_files: 3,
            deleted_bytes: 2048,
        },
    );
    push_response(
        entries,
        "system.logging_clear_err.response",
        SYSTEM_DOMAIN_ID,
        SYSTEM_ACTION_LOGGING_CLEAR_ERR,
        management::MessageResponse {
            message: "permission denied".to_string(),
        },
    );
}

fn user_entries(entries: &mut Vec<VectorEntry>) {
    use management::{
        PasswordPayload, PasswordSaltResponse, PasswordValidateResponse, USER_ACTION_ADD,
        USER_ACTION_ADD_ERR, USER_ACTION_ADD_OK, USER_ACTION_CHANGE, USER_ACTION_CHANGE_ERR,
        USER_ACTION_CHANGE_OK, USER_ACTION_DELETE, USER_ACTION_DELETE_ERR, USER_ACTION_DELETE_OK,
        USER_ACTION_LIST, USER_ACTION_LIST_ERR, USER_ACTION_LIST_OK, USER_ACTION_PASSWORD_SALT,
        USER_ACTION_PASSWORD_SALT_ERR, USER_ACTION_PASSWORD_SALT_OK, USER_ACTION_PASSWORD_SET,
        USER_ACTION_PASSWORD_SET_ERR, USER_ACTION_PASSWORD_SET_OK, USER_ACTION_PASSWORD_UPDATE,
        USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_UPDATE_OK,
        USER_ACTION_PASSWORD_VALIDATE, USER_ACTION_PASSWORD_VALIDATE_ERR,
        USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD, USER_ACTION_ROLE_ADD_ERR,
        USER_ACTION_ROLE_ADD_OK, USER_ACTION_ROLE_REMOVE, USER_ACTION_ROLE_REMOVE_ERR,
        USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_ROLES_LIST, USER_ACTION_ROLES_LIST_ERR,
        USER_ACTION_ROLES_LIST_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_ERR, USER_ACTION_SHOW_OK,
        USERS_DOMAIN_ID, UserAddRequest, UserChangeRequest, UserDeleteRequest, UserListRequest,
        UserListResponse, UserPasswordSaltRequest, UserPasswordSetRequest,
        UserPasswordUpdateRequest, UserPasswordValidateRequest, UserRoleAddRequest,
        UserRoleRemoveRequest, UserRolesListRequest, UserRolesListResponse, UserShowRequest,
        UserShowResponse, UserSummary,
    };

    push_request(
        entries,
        "users.add.request",
        USERS_DOMAIN_ID,
        USER_ACTION_ADD,
        UserAddRequest {
            email: "user@example.com".to_string(),
            name: "User One".to_string(),
            password: PasswordPayload::Plaintext {
                plaintext: "secret".to_string(),
            },
            roles: vec!["admin".to_string(), "editor".to_string()],
            change_token: None,
        },
    );
    push_request(
        entries,
        "users.change.request",
        USERS_DOMAIN_ID,
        USER_ACTION_CHANGE,
        UserChangeRequest {
            email: "user@example.com".to_string(),
            name: Some("User Two".to_string()),
            roles: Some(vec!["editor".to_string()]),
        },
    );
    push_request(
        entries,
        "users.delete.request",
        USERS_DOMAIN_ID,
        USER_ACTION_DELETE,
        UserDeleteRequest {
            email: "delete@example.com".to_string(),
        },
    );
    push_request(
        entries,
        "users.password_set.request",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SET,
        UserPasswordSetRequest {
            email: "user@example.com".to_string(),
            password: PasswordPayload::Plaintext {
                plaintext: "newsecret".to_string(),
            },
            change_token: None,
        },
    );
    push_request(
        entries,
        "users.password_set_front_end.request",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SET,
        UserPasswordSetRequest {
            email: "user@example.com".to_string(),
            password: PasswordPayload::FrontEndHash {
                front_end_hash: "aa".repeat(32),
                front_end_salt: "bb".repeat(16),
            },
            change_token: Some("pc_token".to_string()),
        },
    );
    push_request(
        entries,
        "users.password_salt.request",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        UserPasswordSaltRequest {
            email: "user@example.com".to_string(),
        },
    );
    push_request(
        entries,
        "users.password_validate.request",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_VALIDATE,
        UserPasswordValidateRequest {
            email: "user@example.com".to_string(),
            front_end_hash: "aa".repeat(32),
        },
    );
    push_request(
        entries,
        "users.password_update.request",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_UPDATE,
        UserPasswordUpdateRequest {
            email: "user@example.com".to_string(),
            current_front_end_hash: "aa".repeat(32),
            new_front_end_hash: "bb".repeat(32),
            new_front_end_salt: "cc".repeat(16),
            change_token: "pc_token".to_string(),
        },
    );
    push_request(
        entries,
        "users.list.request",
        USERS_DOMAIN_ID,
        USER_ACTION_LIST,
        UserListRequest {},
    );
    push_request(
        entries,
        "users.show.request",
        USERS_DOMAIN_ID,
        USER_ACTION_SHOW,
        UserShowRequest {
            email: "viewer@example.com".to_string(),
        },
    );
    push_request(
        entries,
        "users.role_add.request",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_ADD,
        UserRoleAddRequest {
            email: "user@example.com".to_string(),
            role: "viewer".to_string(),
        },
    );
    push_request(
        entries,
        "users.role_remove.request",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_REMOVE,
        UserRoleRemoveRequest {
            email: "user@example.com".to_string(),
            role: "editor".to_string(),
        },
    );
    push_request(
        entries,
        "users.roles_list.request",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLES_LIST,
        UserRolesListRequest {},
    );

    push_response(
        entries,
        "users.add_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ADD_OK,
        management::MessageResponse {
            message: "user created".to_string(),
        },
    );
    push_response(
        entries,
        "users.add_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ADD_ERR,
        management::MessageResponse {
            message: "email already exists".to_string(),
        },
    );
    push_response(
        entries,
        "users.change_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_CHANGE_OK,
        management::MessageResponse {
            message: "user updated".to_string(),
        },
    );
    push_response(
        entries,
        "users.change_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_CHANGE_ERR,
        management::MessageResponse {
            message: "user not found".to_string(),
        },
    );
    push_response(
        entries,
        "users.delete_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_DELETE_OK,
        management::MessageResponse {
            message: "user deleted".to_string(),
        },
    );
    push_response(
        entries,
        "users.delete_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_DELETE_ERR,
        management::MessageResponse {
            message: "cannot delete admin".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_set_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SET_OK,
        management::MessageResponse {
            message: "password updated".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_set_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SET_ERR,
        management::MessageResponse {
            message: "password too short".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_salt_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT_OK,
        PasswordSaltResponse {
            change_token: "pc_token".to_string(),
            current_front_end_salt: "aa".repeat(16),
            next_front_end_salt: "bb".repeat(16),
            expires_in_seconds: 600,
        },
    );
    push_response(
        entries,
        "users.password_salt_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT_ERR,
        management::MessageResponse {
            message: "salt unavailable".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_validate_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_VALIDATE_OK,
        PasswordValidateResponse { valid: true },
    );
    push_response(
        entries,
        "users.password_validate_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_VALIDATE_ERR,
        management::MessageResponse {
            message: "validation failed".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_update_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_UPDATE_OK,
        management::MessageResponse {
            message: "password updated".to_string(),
        },
    );
    push_response(
        entries,
        "users.password_update_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_UPDATE_ERR,
        management::MessageResponse {
            message: "password change failed".to_string(),
        },
    );
    push_response(
        entries,
        "users.list_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_LIST_OK,
        UserListResponse {
            users: vec![
                UserSummary {
                    email: "alpha@example.com".to_string(),
                    name: "Alpha".to_string(),
                },
                UserSummary {
                    email: "beta@example.com".to_string(),
                    name: "Beta".to_string(),
                },
            ],
        },
    );
    push_response(
        entries,
        "users.list_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_LIST_ERR,
        management::MessageResponse {
            message: "user list error".to_string(),
        },
    );
    push_response(
        entries,
        "users.show_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_SHOW_OK,
        UserShowResponse {
            email: "alpha@example.com".to_string(),
            name: "Alpha".to_string(),
            roles: vec!["admin".to_string(), "editor".to_string()],
        },
    );
    push_response(
        entries,
        "users.show_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_SHOW_ERR,
        management::MessageResponse {
            message: "user not found".to_string(),
        },
    );
    push_response(
        entries,
        "users.role_add_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_ADD_OK,
        management::MessageResponse {
            message: "role added".to_string(),
        },
    );
    push_response(
        entries,
        "users.role_add_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_ADD_ERR,
        management::MessageResponse {
            message: "role already assigned".to_string(),
        },
    );
    push_response(
        entries,
        "users.role_remove_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_REMOVE_OK,
        management::MessageResponse {
            message: "role removed".to_string(),
        },
    );
    push_response(
        entries,
        "users.role_remove_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_REMOVE_ERR,
        management::MessageResponse {
            message: "role not found".to_string(),
        },
    );
    push_response(
        entries,
        "users.roles_list_ok.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLES_LIST_OK,
        UserRolesListResponse {
            roles: vec![
                "admin".to_string(),
                "editor".to_string(),
                "viewer".to_string(),
            ],
        },
    );
    push_response(
        entries,
        "users.roles_list_err.response",
        USERS_DOMAIN_ID,
        USER_ACTION_ROLES_LIST_ERR,
        management::MessageResponse {
            message: "role list error".to_string(),
        },
    );
}

fn tag_entries(entries: &mut Vec<VectorEntry>) {
    use management::{
        AccessRule, TAG_ACTION_ADD, TAG_ACTION_ADD_ERR, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
        TAG_ACTION_CHANGE_ERR, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_ERR,
        TAG_ACTION_DELETE_OK, TAG_ACTION_LIST, TAG_ACTION_LIST_ERR, TAG_ACTION_LIST_OK,
        TAG_ACTION_SHOW, TAG_ACTION_SHOW_ERR, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest,
        TagChangeRequest, TagDeleteRequest, TagListRequest, TagListResponse, TagShowRequest,
        TagShowResponse, TagSummary,
    };

    push_request(
        entries,
        "tags.add.request",
        TAGS_DOMAIN_ID,
        TAG_ACTION_ADD,
        TagAddRequest {
            id: "news".to_string(),
            name: "News".to_string(),
            roles: vec!["editor".to_string(), "admin".to_string()],
            access_rule: Some(AccessRule::Union),
        },
    );
    push_request(
        entries,
        "tags.change.request",
        TAGS_DOMAIN_ID,
        TAG_ACTION_CHANGE,
        TagChangeRequest {
            id: "news".to_string(),
            new_id: Some("updates".to_string()),
            name: Some("Updates".to_string()),
            roles: Some(vec!["editor".to_string()]),
            access_rule: Some(AccessRule::Intersect),
            clear_access: true,
        },
    );
    push_request(
        entries,
        "tags.delete.request",
        TAGS_DOMAIN_ID,
        TAG_ACTION_DELETE,
        TagDeleteRequest {
            id: "old".to_string(),
        },
    );
    push_request(
        entries,
        "tags.list.request",
        TAGS_DOMAIN_ID,
        TAG_ACTION_LIST,
        TagListRequest {},
    );
    push_request(
        entries,
        "tags.show.request",
        TAGS_DOMAIN_ID,
        TAG_ACTION_SHOW,
        TagShowRequest {
            id: "news".to_string(),
        },
    );

    push_response(
        entries,
        "tags.add_ok.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_ADD_OK,
        management::MessageResponse {
            message: "tag created".to_string(),
        },
    );
    push_response(
        entries,
        "tags.add_err.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_ADD_ERR,
        management::MessageResponse {
            message: "tag already exists".to_string(),
        },
    );
    push_response(
        entries,
        "tags.change_ok.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_CHANGE_OK,
        management::MessageResponse {
            message: "tag updated".to_string(),
        },
    );
    push_response(
        entries,
        "tags.change_err.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_CHANGE_ERR,
        management::MessageResponse {
            message: "tag not found".to_string(),
        },
    );
    push_response(
        entries,
        "tags.delete_ok.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_DELETE_OK,
        management::MessageResponse {
            message: "tag deleted".to_string(),
        },
    );
    push_response(
        entries,
        "tags.delete_err.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_DELETE_ERR,
        management::MessageResponse {
            message: "tag in use".to_string(),
        },
    );
    push_response(
        entries,
        "tags.list_ok.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_LIST_OK,
        TagListResponse {
            tags: vec![
                TagSummary {
                    id: "news".to_string(),
                    name: "News".to_string(),
                },
                TagSummary {
                    id: "updates".to_string(),
                    name: "Updates".to_string(),
                },
            ],
        },
    );
    push_response(
        entries,
        "tags.list_err.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_LIST_ERR,
        management::MessageResponse {
            message: "tag list error".to_string(),
        },
    );
    push_response(
        entries,
        "tags.show_ok.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_SHOW_OK,
        TagShowResponse {
            id: "news".to_string(),
            name: "News".to_string(),
            roles: vec!["editor".to_string()],
            access_rule: Some(AccessRule::Union),
        },
    );
    push_response(
        entries,
        "tags.show_err.response",
        TAGS_DOMAIN_ID,
        TAG_ACTION_SHOW_ERR,
        management::MessageResponse {
            message: "tag not found".to_string(),
        },
    );
}

fn role_entries(entries: &mut Vec<VectorEntry>) {
    use management::{
        ROLE_ACTION_ADD, ROLE_ACTION_ADD_ERR, ROLE_ACTION_ADD_OK, ROLE_ACTION_CHANGE,
        ROLE_ACTION_CHANGE_ERR, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE, ROLE_ACTION_DELETE_ERR,
        ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST, ROLE_ACTION_LIST_ERR, ROLE_ACTION_LIST_OK,
        ROLE_ACTION_SHOW, ROLE_ACTION_SHOW_ERR, ROLE_ACTION_SHOW_OK, ROLES_DOMAIN_ID,
        RoleAddRequest, RoleChangeRequest, RoleDeleteRequest, RoleListRequest, RoleListResponse,
        RoleShowRequest, RoleShowResponse,
    };

    push_request(
        entries,
        "roles.add.request",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_ADD,
        RoleAddRequest {
            role: "editor".to_string(),
        },
    );
    push_request(
        entries,
        "roles.change.request",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_CHANGE,
        RoleChangeRequest {
            role: "editor".to_string(),
            new_role: "contributor".to_string(),
        },
    );
    push_request(
        entries,
        "roles.delete.request",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_DELETE,
        RoleDeleteRequest {
            role: "obsolete".to_string(),
        },
    );
    push_request(
        entries,
        "roles.list.request",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_LIST,
        RoleListRequest {},
    );
    push_request(
        entries,
        "roles.show.request",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_SHOW,
        RoleShowRequest {
            role: "editor".to_string(),
        },
    );

    push_response(
        entries,
        "roles.add_ok.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_ADD_OK,
        management::MessageResponse {
            message: "role created".to_string(),
        },
    );
    push_response(
        entries,
        "roles.add_err.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_ADD_ERR,
        management::MessageResponse {
            message: "role already exists".to_string(),
        },
    );
    push_response(
        entries,
        "roles.change_ok.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_CHANGE_OK,
        management::MessageResponse {
            message: "role updated".to_string(),
        },
    );
    push_response(
        entries,
        "roles.change_err.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_CHANGE_ERR,
        management::MessageResponse {
            message: "role not found".to_string(),
        },
    );
    push_response(
        entries,
        "roles.delete_ok.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_DELETE_OK,
        management::MessageResponse {
            message: "role deleted".to_string(),
        },
    );
    push_response(
        entries,
        "roles.delete_err.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_DELETE_ERR,
        management::MessageResponse {
            message: "role in use".to_string(),
        },
    );
    push_response(
        entries,
        "roles.list_ok.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_LIST_OK,
        RoleListResponse {
            roles: vec![
                "admin".to_string(),
                "editor".to_string(),
                "viewer".to_string(),
            ],
        },
    );
    push_response(
        entries,
        "roles.list_err.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_LIST_ERR,
        management::MessageResponse {
            message: "role list error".to_string(),
        },
    );
    push_response(
        entries,
        "roles.show_ok.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_SHOW_OK,
        RoleShowResponse {
            role: "editor".to_string(),
        },
    );
    push_response(
        entries,
        "roles.show_err.response",
        ROLES_DOMAIN_ID,
        ROLE_ACTION_SHOW_ERR,
        management::MessageResponse {
            message: "role not found".to_string(),
        },
    );
}

fn content_entries(entries: &mut Vec<VectorEntry>) {
    use management::{
        BinaryPrevalidateRequest, BinaryPrevalidateResponse, BinaryUploadCommitRequest,
        BinaryUploadInitRequest, CONTENT_ACTION_BINARY_PREVALIDATE,
        CONTENT_ACTION_BINARY_PREVALIDATE_ERR, CONTENT_ACTION_BINARY_PREVALIDATE_OK,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK, CONTENT_ACTION_BINARY_UPLOAD_INIT,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
        CONTENT_ACTION_DELETE, CONTENT_ACTION_DELETE_ERR, CONTENT_ACTION_DELETE_OK,
        CONTENT_ACTION_LIST, CONTENT_ACTION_LIST_ERR, CONTENT_ACTION_LIST_OK,
        CONTENT_ACTION_NAV_INDEX, CONTENT_ACTION_NAV_INDEX_ERR, CONTENT_ACTION_NAV_INDEX_OK,
        CONTENT_ACTION_READ, CONTENT_ACTION_READ_ERR, CONTENT_ACTION_READ_OK,
        CONTENT_ACTION_UPDATE, CONTENT_ACTION_UPDATE_ERR, CONTENT_ACTION_UPDATE_OK,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT, CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK, CONTENT_ACTION_UPDATE_STREAM_INIT,
        CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
        CONTENT_ACTION_UPLOAD, CONTENT_ACTION_UPLOAD_ERR, CONTENT_ACTION_UPLOAD_OK,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK, CONTENT_ACTION_UPLOAD_STREAM_INIT,
        CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
        CONTENT_DOMAIN_ID, ContentDeleteRequest, ContentListRequest, ContentListResponse,
        ContentNavIndexEntry, ContentNavIndexRequest, ContentNavIndexResponse, ContentReadRequest,
        ContentReadResponse, ContentSortDirection, ContentSortField, ContentSummary,
        ContentUpdateRequest, ContentUpdateStreamCommitRequest, ContentUpdateStreamInitRequest,
        ContentUploadRequest, ContentUploadResponse, ContentUploadStreamCommitRequest,
        ContentUploadStreamInitRequest, UploadStreamInitResponse,
    };

    push_request(
        entries,
        "content.list.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_LIST,
        ContentListRequest {
            page: 1,
            page_size: 20,
            sort_field: ContentSortField::Title,
            sort_direction: ContentSortDirection::Asc,
            query: Some("guide".to_string()),
            tags: Some(vec!["docs".to_string(), "guide".to_string()]),
            markdown_only: true,
        },
    );
    push_request(
        entries,
        "content.read.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_READ,
        ContentReadRequest {
            id: "0000000000000001".to_string(),
        },
    );
    push_request(
        entries,
        "content.update.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE,
        ContentUpdateRequest {
            id: "0000000000000001".to_string(),
            new_alias: Some("docs/getting-started".to_string()),
            title: Some("Getting Started".to_string()),
            tags: Some(vec!["guide".to_string(), "start".to_string()]),
            nav_title: Some("Start".to_string()),
            nav_parent_id: None,
            nav_order: Some(2),
            theme: Some("default".to_string()),
            content: Some("# Hello".to_string()),
        },
    );
    push_request(
        entries,
        "content.delete.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_DELETE,
        ContentDeleteRequest {
            id: "0000000000000002".to_string(),
        },
    );
    push_request(
        entries,
        "content.upload.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD,
        ContentUploadRequest {
            alias: Some("docs/new".to_string()),
            title: Some("New Doc".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["doc".to_string()],
            nav_title: Some("New".to_string()),
            nav_parent_id: Some("root".to_string()),
            nav_order: Some(1),
            original_filename: Some("new.md".to_string()),
            theme: Some("default".to_string()),
            content: vec![1, 2, 3, 4],
        },
    );
    push_request(
        entries,
        "content.nav_index.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_NAV_INDEX,
        ContentNavIndexRequest {},
    );
    push_request(
        entries,
        "content.binary_prevalidate.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_PREVALIDATE,
        BinaryPrevalidateRequest {
            filename: "photo.png".to_string(),
            mime: "image/png".to_string(),
            size_bytes: 123456,
        },
    );
    push_request(
        entries,
        "content.binary_upload_init.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_INIT,
        BinaryUploadInitRequest {
            alias: Some("images/photo".to_string()),
            title: Some("Photo".to_string()),
            tags: vec!["media".to_string()],
            filename: "photo.png".to_string(),
            mime: "image/png".to_string(),
            size_bytes: 3456,
        },
    );
    push_request(
        entries,
        "content.binary_upload_commit.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
        BinaryUploadCommitRequest { upload_id: 7 },
    );
    push_request(
        entries,
        "content.upload_stream_init.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_INIT,
        ContentUploadStreamInitRequest {
            alias: Some("docs/stream".to_string()),
            title: Some("Stream Doc".to_string()),
            tags: vec!["stream".to_string()],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            theme: Some("default".to_string()),
            size_bytes: 777,
        },
    );
    push_request(
        entries,
        "content.upload_stream_commit.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
        ContentUploadStreamCommitRequest { upload_id: 9 },
    );
    push_request(
        entries,
        "content.update_stream_init.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_INIT,
        ContentUpdateStreamInitRequest {
            id: "0000000000000003".to_string(),
            new_alias: None,
            title: Some("Streamed".to_string()),
            tags: None,
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            theme: None,
            size_bytes: 777,
        },
    );
    push_request(
        entries,
        "content.update_stream_commit.request",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT,
        ContentUpdateStreamCommitRequest { upload_id: 10 },
    );

    push_response(
        entries,
        "content.list_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_LIST_OK,
        ContentListResponse {
            total: 1,
            page: 1,
            page_size: 20,
            items: vec![ContentSummary {
                id: "1".to_string(),
                alias: "docs/intro".to_string(),
                title: Some("Intro".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["guide".to_string()],
                nav_title: Some("Intro".to_string()),
                nav_parent_id: None,
                nav_order: Some(1),
                original_filename: Some("intro.md".to_string()),
                is_markdown: true,
            }],
        },
    );
    push_response(
        entries,
        "content.list_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_LIST_ERR,
        management::MessageResponse {
            message: "content list error".to_string(),
        },
    );
    push_response(
        entries,
        "content.read_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_READ_OK,
        ContentReadResponse {
            id: "1".to_string(),
            alias: "docs/intro".to_string(),
            title: Some("Intro".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["guide".to_string()],
            nav_title: Some("Intro".to_string()),
            nav_parent_id: None,
            nav_order: Some(1),
            original_filename: Some("intro.md".to_string()),
            theme: Some("default".to_string()),
            content: Some("# Intro".to_string()),
        },
    );
    push_response(
        entries,
        "content.read_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_READ_ERR,
        management::MessageResponse {
            message: "content not found".to_string(),
        },
    );
    push_response(
        entries,
        "content.update_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_OK,
        management::MessageResponse {
            message: "content updated".to_string(),
        },
    );
    push_response(
        entries,
        "content.update_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_ERR,
        management::MessageResponse {
            message: "content update failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.delete_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_DELETE_OK,
        management::MessageResponse {
            message: "content deleted".to_string(),
        },
    );
    push_response(
        entries,
        "content.delete_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_DELETE_ERR,
        management::MessageResponse {
            message: "content delete failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.upload_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_OK,
        ContentUploadResponse {
            id: "2".to_string(),
            alias: "docs/new".to_string(),
            mime: "text/markdown".to_string(),
            is_markdown: true,
        },
    );
    push_response(
        entries,
        "content.upload_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_ERR,
        management::MessageResponse {
            message: "content upload failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.nav_index_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_NAV_INDEX_OK,
        ContentNavIndexResponse {
            items: vec![ContentNavIndexEntry {
                id: "1".to_string(),
                alias: "docs/intro".to_string(),
                title: Some("Intro".to_string()),
                nav_title: Some("Intro".to_string()),
                nav_parent_id: None,
                nav_order: Some(1),
            }],
        },
    );
    push_response(
        entries,
        "content.nav_index_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_NAV_INDEX_ERR,
        management::MessageResponse {
            message: "nav index failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.binary_prevalidate_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_PREVALIDATE_OK,
        BinaryPrevalidateResponse {
            accepted: true,
            message: "ok".to_string(),
        },
    );
    push_response(
        entries,
        "content.binary_prevalidate_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
        management::MessageResponse {
            message: "binary prevalidate failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.binary_upload_init_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
        UploadStreamInitResponse {
            upload_id: 7,
            stream_id: 11,
            max_bytes: 4096,
            chunk_bytes: 1024,
        },
    );
    push_response(
        entries,
        "content.binary_upload_init_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
        management::MessageResponse {
            message: "binary upload init failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.binary_upload_commit_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        ContentUploadResponse {
            id: "3".to_string(),
            alias: "images/photo".to_string(),
            mime: "image/png".to_string(),
            is_markdown: false,
        },
    );
    push_response(
        entries,
        "content.binary_upload_commit_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
        management::MessageResponse {
            message: "binary upload commit failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.upload_stream_init_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
        UploadStreamInitResponse {
            upload_id: 8,
            stream_id: 12,
            max_bytes: 65536,
            chunk_bytes: 2048,
        },
    );
    push_response(
        entries,
        "content.upload_stream_init_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
        management::MessageResponse {
            message: "upload stream init failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.upload_stream_commit_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
        ContentUploadResponse {
            id: "4".to_string(),
            alias: "docs/stream".to_string(),
            mime: "text/markdown".to_string(),
            is_markdown: true,
        },
    );
    push_response(
        entries,
        "content.upload_stream_commit_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
        management::MessageResponse {
            message: "upload stream commit failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.update_stream_init_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
        UploadStreamInitResponse {
            upload_id: 9,
            stream_id: 13,
            max_bytes: 1024,
            chunk_bytes: 512,
        },
    );
    push_response(
        entries,
        "content.update_stream_init_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
        management::MessageResponse {
            message: "update stream init failed".to_string(),
        },
    );
    push_response(
        entries,
        "content.update_stream_commit_ok.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
        management::MessageResponse {
            message: "update stream committed".to_string(),
        },
    );
    push_response(
        entries,
        "content.update_stream_commit_err.response",
        CONTENT_DOMAIN_ID,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
        management::MessageResponse {
            message: "update stream commit failed".to_string(),
        },
    );
}
