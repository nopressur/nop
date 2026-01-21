// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop::management::{
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
    CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, CONTENT_DOMAIN_ID, ClearLogsRequest, ClearLogsResponse,
    ContentDeleteRequest, ContentListRequest, ContentListResponse, ContentNavIndexRequest,
    ContentNavIndexResponse, ContentReadRequest, ContentReadResponse, ContentUpdateRequest,
    ContentUpdateStreamCommitRequest, ContentUpdateStreamInitRequest, ContentUploadRequest,
    ContentUploadResponse, ContentUploadStreamCommitRequest, ContentUploadStreamInitRequest,
    GetLoggingConfigRequest, LoggingConfigResponse, MessageResponse, PingRequest,
    PongErrorResponse, PongResponse, ROLE_ACTION_ADD, ROLE_ACTION_ADD_ERR, ROLE_ACTION_ADD_OK,
    ROLE_ACTION_CHANGE, ROLE_ACTION_CHANGE_ERR, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE,
    ROLE_ACTION_DELETE_ERR, ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST, ROLE_ACTION_LIST_ERR,
    ROLE_ACTION_LIST_OK, ROLE_ACTION_SHOW, ROLE_ACTION_SHOW_ERR, ROLE_ACTION_SHOW_OK,
    ROLES_DOMAIN_ID, RoleAddRequest, RoleChangeRequest, RoleDeleteRequest, RoleListRequest,
    RoleListResponse, RoleShowRequest, RoleShowResponse, SYSTEM_ACTION_LOGGING_CLEAR,
    SYSTEM_ACTION_LOGGING_CLEAR_ERR, SYSTEM_ACTION_LOGGING_CLEAR_OK, SYSTEM_ACTION_LOGGING_GET,
    SYSTEM_ACTION_LOGGING_GET_ERR, SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_LOGGING_SET,
    SYSTEM_ACTION_LOGGING_SET_ERR, SYSTEM_ACTION_LOGGING_SET_OK, SYSTEM_ACTION_PING,
    SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, SetLoggingConfigRequest,
    TAG_ACTION_ADD, TAG_ACTION_ADD_ERR, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
    TAG_ACTION_CHANGE_ERR, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_ERR,
    TAG_ACTION_DELETE_OK, TAG_ACTION_LIST, TAG_ACTION_LIST_ERR, TAG_ACTION_LIST_OK,
    TAG_ACTION_SHOW, TAG_ACTION_SHOW_ERR, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest,
    TagChangeRequest, TagDeleteRequest, TagListRequest, TagListResponse, TagShowRequest,
    TagShowResponse, USER_ACTION_ADD, USER_ACTION_ADD_ERR, USER_ACTION_ADD_OK, USER_ACTION_CHANGE,
    USER_ACTION_CHANGE_ERR, USER_ACTION_CHANGE_OK, USER_ACTION_DELETE, USER_ACTION_DELETE_ERR,
    USER_ACTION_DELETE_OK, USER_ACTION_LIST, USER_ACTION_LIST_ERR, USER_ACTION_LIST_OK,
    USER_ACTION_PASSWORD_SALT, USER_ACTION_PASSWORD_SALT_ERR, USER_ACTION_PASSWORD_SALT_OK,
    USER_ACTION_PASSWORD_SET, USER_ACTION_PASSWORD_SET_ERR, USER_ACTION_PASSWORD_SET_OK,
    USER_ACTION_PASSWORD_UPDATE, USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_UPDATE_OK,
    USER_ACTION_PASSWORD_VALIDATE, USER_ACTION_PASSWORD_VALIDATE_ERR,
    USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD, USER_ACTION_ROLE_ADD_ERR,
    USER_ACTION_ROLE_ADD_OK, USER_ACTION_ROLE_REMOVE, USER_ACTION_ROLE_REMOVE_ERR,
    USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_ROLES_LIST, USER_ACTION_ROLES_LIST_ERR,
    USER_ACTION_ROLES_LIST_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_ERR, USER_ACTION_SHOW_OK,
    USERS_DOMAIN_ID, UploadStreamInitResponse, UserAddRequest, UserChangeRequest,
    UserDeleteRequest, UserListRequest, UserListResponse, UserPasswordSaltRequest,
    UserPasswordSetRequest, UserPasswordUpdateRequest, UserPasswordValidateRequest,
    UserRoleAddRequest, UserRoleRemoveRequest, UserRolesListRequest, UserRolesListResponse,
    UserShowRequest, UserShowResponse, WireDecode, WireEncode, WireReader, WireResult, WireWriter,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct VectorFile {
    version: u32,
    entries: Vec<VectorEntry>,
}

#[derive(Debug, Deserialize)]
struct VectorEntry {
    name: String,
    direction: String,
    domain_id: u32,
    action_id: u32,
    payload: Value,
    hex: String,
}

#[test]
fn wire_vectors_match_payloads() {
    let vectors = load_vectors();
    assert_eq!(vectors.version, 1, "Unexpected vector registry version");

    for vector in vectors.entries {
        let bytes = decode_hex(&vector.hex);
        match (
            vector.direction.as_str(),
            vector.domain_id,
            vector.action_id,
        ) {
            ("request", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING) => {
                assert_vector::<PingRequest>(&vector, &bytes)
            }
            ("request", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET) => {
                assert_vector::<GetLoggingConfigRequest>(&vector, &bytes)
            }
            ("request", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET) => {
                assert_vector::<SetLoggingConfigRequest>(&vector, &bytes)
            }
            ("request", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR) => {
                assert_vector::<ClearLogsRequest>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG) => {
                assert_vector::<PongResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG_ERROR) => {
                assert_vector::<PongErrorResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_OK) => {
                assert_vector::<LoggingConfigResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_OK) => {
                assert_vector::<LoggingConfigResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_OK) => {
                assert_vector::<ClearLogsResponse>(&vector, &bytes)
            }
            ("response", SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_ADD) => {
                assert_vector::<UserAddRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_CHANGE) => {
                assert_vector::<UserChangeRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_DELETE) => {
                assert_vector::<UserDeleteRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SET) => {
                assert_vector::<UserPasswordSetRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT) => {
                assert_vector::<UserPasswordSaltRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_VALIDATE) => {
                assert_vector::<UserPasswordValidateRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_UPDATE) => {
                assert_vector::<UserPasswordUpdateRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_LIST) => {
                assert_vector::<UserListRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_SHOW) => {
                assert_vector::<UserShowRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_ROLE_ADD) => {
                assert_vector::<UserRoleAddRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_ROLE_REMOVE) => {
                assert_vector::<UserRoleRemoveRequest>(&vector, &bytes)
            }
            ("request", USERS_DOMAIN_ID, USER_ACTION_ROLES_LIST) => {
                assert_vector::<UserRolesListRequest>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ADD_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ADD_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_CHANGE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_CHANGE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_DELETE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_DELETE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SET_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SET_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT_OK) => {
                assert_vector::<nop::management::PasswordSaltResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_VALIDATE_OK) => {
                assert_vector::<nop::management::PasswordValidateResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_VALIDATE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_UPDATE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_PASSWORD_UPDATE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_LIST_OK) => {
                assert_vector::<UserListResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_LIST_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_SHOW_OK) => {
                assert_vector::<UserShowResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_SHOW_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLE_ADD_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLE_ADD_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLE_REMOVE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLE_REMOVE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLES_LIST_OK) => {
                assert_vector::<UserRolesListResponse>(&vector, &bytes)
            }
            ("response", USERS_DOMAIN_ID, USER_ACTION_ROLES_LIST_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("request", TAGS_DOMAIN_ID, TAG_ACTION_ADD) => {
                assert_vector::<TagAddRequest>(&vector, &bytes)
            }
            ("request", TAGS_DOMAIN_ID, TAG_ACTION_CHANGE) => {
                assert_vector::<TagChangeRequest>(&vector, &bytes)
            }
            ("request", TAGS_DOMAIN_ID, TAG_ACTION_DELETE) => {
                assert_vector::<TagDeleteRequest>(&vector, &bytes)
            }
            ("request", TAGS_DOMAIN_ID, TAG_ACTION_LIST) => {
                assert_vector::<TagListRequest>(&vector, &bytes)
            }
            ("request", TAGS_DOMAIN_ID, TAG_ACTION_SHOW) => {
                assert_vector::<TagShowRequest>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_ADD_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_ADD_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_CHANGE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_CHANGE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_DELETE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_DELETE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_LIST_OK) => {
                assert_vector::<TagListResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_LIST_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_SHOW_OK) => {
                assert_vector::<TagShowResponse>(&vector, &bytes)
            }
            ("response", TAGS_DOMAIN_ID, TAG_ACTION_SHOW_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("request", ROLES_DOMAIN_ID, ROLE_ACTION_ADD) => {
                assert_vector::<RoleAddRequest>(&vector, &bytes)
            }
            ("request", ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE) => {
                assert_vector::<RoleChangeRequest>(&vector, &bytes)
            }
            ("request", ROLES_DOMAIN_ID, ROLE_ACTION_DELETE) => {
                assert_vector::<RoleDeleteRequest>(&vector, &bytes)
            }
            ("request", ROLES_DOMAIN_ID, ROLE_ACTION_LIST) => {
                assert_vector::<RoleListRequest>(&vector, &bytes)
            }
            ("request", ROLES_DOMAIN_ID, ROLE_ACTION_SHOW) => {
                assert_vector::<RoleShowRequest>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_ADD_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_ADD_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_DELETE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_DELETE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_LIST_OK) => {
                assert_vector::<RoleListResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_LIST_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_SHOW_OK) => {
                assert_vector::<RoleShowResponse>(&vector, &bytes)
            }
            ("response", ROLES_DOMAIN_ID, ROLE_ACTION_SHOW_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST) => {
                assert_vector::<ContentListRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_READ) => {
                assert_vector::<ContentReadRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE) => {
                assert_vector::<ContentUpdateRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE) => {
                assert_vector::<ContentDeleteRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD) => {
                assert_vector::<ContentUploadRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX) => {
                assert_vector::<ContentNavIndexRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE) => {
                assert_vector::<BinaryPrevalidateRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT) => {
                assert_vector::<BinaryUploadInitRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT) => {
                assert_vector::<BinaryUploadCommitRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT) => {
                assert_vector::<ContentUploadStreamInitRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT) => {
                assert_vector::<ContentUploadStreamCommitRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT) => {
                assert_vector::<ContentUpdateStreamInitRequest>(&vector, &bytes)
            }
            ("request", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT) => {
                assert_vector::<ContentUpdateStreamCommitRequest>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST_OK) => {
                assert_vector::<ContentListResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_READ_OK) => {
                assert_vector::<ContentReadResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_READ_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_OK) => {
                assert_vector::<ContentUploadResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX_OK) => {
                assert_vector::<ContentNavIndexResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE_OK) => {
                assert_vector::<BinaryPrevalidateResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK) => {
                assert_vector::<UploadStreamInitResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK) => {
                assert_vector::<ContentUploadResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT_OK) => {
                assert_vector::<UploadStreamInitResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK) => {
                assert_vector::<ContentUploadResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT_OK) => {
                assert_vector::<UploadStreamInitResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            ("response", CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR) => {
                assert_vector::<MessageResponse>(&vector, &bytes)
            }
            _ => panic!(
                "Unhandled vector {} ({} {} {})",
                vector.name, vector.direction, vector.domain_id, vector.action_id
            ),
        }
    }
}

fn assert_vector<T>(vector: &VectorEntry, bytes: &[u8])
where
    T: WireEncode + WireDecode + Serialize,
{
    let decoded = decode_payload::<T>(bytes).expect("decode payload");
    let actual = serde_json::to_value(&decoded).expect("serialize payload");
    assert_payload_eq(&actual, &vector.payload, &vector.name);
    let encoded = encode_payload(&decoded).expect("encode payload");
    assert_eq!(
        hex::encode(encoded),
        vector.hex,
        "hex mismatch for {}",
        vector.name
    );
}

fn encode_payload<T: WireEncode>(payload: &T) -> WireResult<Vec<u8>> {
    let mut writer = WireWriter::new();
    payload.encode(&mut writer)?;
    Ok(writer.into_bytes())
}

fn decode_payload<T: WireDecode>(bytes: &[u8]) -> WireResult<T> {
    let mut reader = WireReader::new(bytes);
    let decoded = T::decode(&mut reader)?;
    reader.ensure_fully_consumed()?;
    Ok(decoded)
}

fn assert_payload_eq(actual: &Value, expected: &Value, name: &str) {
    if !json_matches(actual, expected) {
        panic!(
            "Payload mismatch for {}.\nactual: {}\nexpected: {}",
            name, actual, expected
        );
    }
}

fn json_matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => left == right,
        (Value::Number(actual_number), Value::String(expected_string)) => {
            match expected_string.parse::<u64>() {
                Ok(parsed) => actual_number.as_u64() == Some(parsed),
                Err(_) => false,
            }
        }
        (Value::Array(actual_values), Value::Array(expected_values)) => {
            if actual_values.len() != expected_values.len() {
                return false;
            }
            actual_values
                .iter()
                .zip(expected_values.iter())
                .all(|(actual_item, expected_item)| json_matches(actual_item, expected_item))
        }
        (Value::Object(actual_map), Value::Object(expected_map)) => {
            if actual_map.len() != expected_map.len() {
                return false;
            }
            expected_map.iter().all(|(key, expected_value)| {
                actual_map
                    .get(key)
                    .map(|actual_value| json_matches(actual_value, expected_value))
                    .unwrap_or(false)
            })
        }
        _ => false,
    }
}

fn load_vectors() -> VectorFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("management-wire-vectors.json");
    let data = fs::read_to_string(path).expect("read vectors");
    serde_json::from_str(&data).expect("parse vectors")
}

fn decode_hex(hex_str: &str) -> Vec<u8> {
    if hex_str.is_empty() {
        return Vec::new();
    }
    hex::decode(hex_str).expect("hex decode")
}
