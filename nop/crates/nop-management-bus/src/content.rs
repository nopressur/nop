// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::core::ManagementContext;
use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use async_trait::async_trait;
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use std::sync::Arc;

use nop_management_content::{
    CONTENT_ACTION_BINARY_PREVALIDATE, CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
    CONTENT_ACTION_BINARY_PREVALIDATE_OK, CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
    CONTENT_ACTION_BINARY_UPLOAD_INIT, CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
    CONTENT_ACTION_BINARY_UPLOAD_INIT_OK, CONTENT_ACTION_DELETE, CONTENT_ACTION_DELETE_ERR,
    CONTENT_ACTION_DELETE_OK, CONTENT_ACTION_LIST, CONTENT_ACTION_LIST_ERR, CONTENT_ACTION_LIST_OK,
    CONTENT_ACTION_NAV_INDEX, CONTENT_ACTION_NAV_INDEX_ERR, CONTENT_ACTION_NAV_INDEX_OK,
    CONTENT_ACTION_READ, CONTENT_ACTION_READ_ERR, CONTENT_ACTION_READ_OK, CONTENT_ACTION_UPDATE,
    CONTENT_ACTION_UPDATE_ERR, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPDATE_STREAM_COMMIT,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR, CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPDATE_STREAM_INIT, CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
    CONTENT_ACTION_UPDATE_STREAM_INIT_OK, CONTENT_ACTION_UPLOAD, CONTENT_ACTION_UPLOAD_ERR,
    CONTENT_ACTION_UPLOAD_OK, CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
    CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPLOAD_STREAM_INIT, CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
    CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, CONTENT_DOMAIN_ID, UploadBeginConfig, UploadInit,
    UploadKind, UploadRecord, UploadRegistryAccess, handle_content_request,
};

use crate::upload_registry;

fn to_registry_kind(kind: UploadKind) -> upload_registry::UploadKind {
    match kind {
        UploadKind::Binary(meta) => {
            upload_registry::UploadKind::Binary(upload_registry::BinaryUploadMeta {
                content_id: meta.content_id,
                version: meta.version,
                alias: meta.alias,
                title: meta.title,
                tags: meta.tags,
                filename: meta.filename,
                mime: meta.mime,
            })
        }
        UploadKind::MarkdownCreate(meta) => {
            upload_registry::UploadKind::MarkdownCreate(upload_registry::MarkdownUploadMeta {
                content_id: meta.content_id,
                version: meta.version,
                sidecar: meta.sidecar,
            })
        }
        UploadKind::MarkdownUpdate(meta) => {
            upload_registry::UploadKind::MarkdownUpdate(upload_registry::MarkdownUpdateMeta {
                content_id: meta.content_id,
                base_version: meta.base_version,
                sidecar: meta.sidecar,
                clear_children: meta.clear_children,
                nav_changed: meta.nav_changed,
            })
        }
    }
}

fn from_registry_kind(kind: upload_registry::UploadKind) -> UploadKind {
    match kind {
        upload_registry::UploadKind::Binary(meta) => {
            UploadKind::Binary(nop_management_content::BinaryUploadMeta {
                content_id: meta.content_id,
                version: meta.version,
                alias: meta.alias,
                title: meta.title,
                tags: meta.tags,
                filename: meta.filename,
                mime: meta.mime,
            })
        }
        upload_registry::UploadKind::MarkdownCreate(meta) => {
            UploadKind::MarkdownCreate(nop_management_content::MarkdownUploadMeta {
                content_id: meta.content_id,
                version: meta.version,
                sidecar: meta.sidecar,
            })
        }
        upload_registry::UploadKind::MarkdownUpdate(meta) => {
            UploadKind::MarkdownUpdate(nop_management_content::MarkdownUpdateMeta {
                content_id: meta.content_id,
                base_version: meta.base_version,
                sidecar: meta.sidecar,
                clear_children: meta.clear_children,
                nav_changed: meta.nav_changed,
            })
        }
    }
}

#[async_trait]
impl UploadRegistryAccess for ManagementContext {
    async fn begin_upload(&self, config: UploadBeginConfig) -> Result<UploadInit, String> {
        let UploadBeginConfig {
            connection_id,
            kind,
            temp_path,
            expected_bytes,
            max_bytes,
            chunk_bytes,
            validate_utf8,
        } = config;
        let builder = upload_registry::UploadBeginConfig::builder(
            connection_id,
            to_registry_kind(kind),
            temp_path,
            expected_bytes,
            max_bytes,
            chunk_bytes,
        )
        .validate_utf8(validate_utf8);
        let init = self
            .upload_registry
            .begin_upload(builder.build())
            .await
            .map_err(|err| err.to_string())?;
        Ok(UploadInit {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        })
    }

    async fn take_upload(&self, upload_id: u32) -> Result<UploadRecord, String> {
        let record = self
            .upload_registry
            .take_upload(upload_id)
            .await
            .map_err(|err| err.to_string())?;
        let upload_registry::UploadRecord {
            kind,
            stream_id,
            chunk_bytes,
            temp_path,
            bytes_written,
            expected_bytes,
            max_bytes,
            complete,
            connection_id,
            file,
            ..
        } = record;
        drop(file);
        Ok(UploadRecord {
            kind: from_registry_kind(kind),
            stream_id,
            chunk_bytes,
            temp_path,
            bytes_written,
            expected_bytes,
            max_bytes,
            complete,
            connection_id,
        })
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "content",
        id: CONTENT_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "list",
                id: CONTENT_ACTION_LIST,
            },
            ActionDescriptor {
                name: "read",
                id: CONTENT_ACTION_READ,
            },
            ActionDescriptor {
                name: "update",
                id: CONTENT_ACTION_UPDATE,
            },
            ActionDescriptor {
                name: "delete",
                id: CONTENT_ACTION_DELETE,
            },
            ActionDescriptor {
                name: "upload",
                id: CONTENT_ACTION_UPLOAD,
            },
            ActionDescriptor {
                name: "nav_index",
                id: CONTENT_ACTION_NAV_INDEX,
            },
            ActionDescriptor {
                name: "binary_prevalidate",
                id: CONTENT_ACTION_BINARY_PREVALIDATE,
            },
            ActionDescriptor {
                name: "binary_upload_init",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT,
            },
            ActionDescriptor {
                name: "binary_upload_commit",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
            },
            ActionDescriptor {
                name: "upload_stream_init",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT,
            },
            ActionDescriptor {
                name: "upload_stream_commit",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
            },
            ActionDescriptor {
                name: "update_stream_init",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT,
            },
            ActionDescriptor {
                name: "update_stream_commit",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT,
            },
            ActionDescriptor {
                name: "list_ok",
                id: CONTENT_ACTION_LIST_OK,
            },
            ActionDescriptor {
                name: "list_err",
                id: CONTENT_ACTION_LIST_ERR,
            },
            ActionDescriptor {
                name: "read_ok",
                id: CONTENT_ACTION_READ_OK,
            },
            ActionDescriptor {
                name: "read_err",
                id: CONTENT_ACTION_READ_ERR,
            },
            ActionDescriptor {
                name: "update_ok",
                id: CONTENT_ACTION_UPDATE_OK,
            },
            ActionDescriptor {
                name: "update_err",
                id: CONTENT_ACTION_UPDATE_ERR,
            },
            ActionDescriptor {
                name: "delete_ok",
                id: CONTENT_ACTION_DELETE_OK,
            },
            ActionDescriptor {
                name: "delete_err",
                id: CONTENT_ACTION_DELETE_ERR,
            },
            ActionDescriptor {
                name: "upload_ok",
                id: CONTENT_ACTION_UPLOAD_OK,
            },
            ActionDescriptor {
                name: "upload_err",
                id: CONTENT_ACTION_UPLOAD_ERR,
            },
            ActionDescriptor {
                name: "nav_index_ok",
                id: CONTENT_ACTION_NAV_INDEX_OK,
            },
            ActionDescriptor {
                name: "nav_index_err",
                id: CONTENT_ACTION_NAV_INDEX_ERR,
            },
            ActionDescriptor {
                name: "binary_prevalidate_ok",
                id: CONTENT_ACTION_BINARY_PREVALIDATE_OK,
            },
            ActionDescriptor {
                name: "binary_prevalidate_err",
                id: CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
            },
            ActionDescriptor {
                name: "binary_upload_init_ok",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
            },
            ActionDescriptor {
                name: "binary_upload_init_err",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
            },
            ActionDescriptor {
                name: "binary_upload_commit_ok",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
            },
            ActionDescriptor {
                name: "binary_upload_commit_err",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            },
            ActionDescriptor {
                name: "upload_stream_init_ok",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
            },
            ActionDescriptor {
                name: "upload_stream_init_err",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            },
            ActionDescriptor {
                name: "upload_stream_commit_ok",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
            },
            ActionDescriptor {
                name: "upload_stream_commit_err",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            },
            ActionDescriptor {
                name: "update_stream_init_ok",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
            },
            ActionDescriptor {
                name: "update_stream_init_err",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            },
            ActionDescriptor {
                name: "update_stream_commit_ok",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
            },
            ActionDescriptor {
                name: "update_stream_commit_err",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_content_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT),
        handler,
    )?;

    registry.register_request_codec(Arc::new(nop_management_content::ContentListRequestCodec))?;
    registry.register_request_codec(Arc::new(nop_management_content::ContentReadRequestCodec))?;
    registry.register_request_codec(Arc::new(nop_management_content::ContentUpdateRequestCodec))?;
    registry.register_request_codec(Arc::new(nop_management_content::ContentDeleteRequestCodec))?;
    registry.register_request_codec(Arc::new(nop_management_content::ContentUploadRequestCodec))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::ContentNavIndexRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::BinaryPrevalidateRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::BinaryUploadInitRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::BinaryUploadCommitRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::ContentUploadStreamInitRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::ContentUploadStreamCommitRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::ContentUpdateStreamInitRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(
        nop_management_content::ContentUpdateStreamCommitRequestCodec,
    ))?;

    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_LIST_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_READ_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPDATE_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPDATE_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_DELETE_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_DELETE_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPLOAD_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_NAV_INDEX_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_BINARY_PREVALIDATE_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::MessageResponseCodec::new(CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR),
    ))?;
    registry.register_response_codec(Arc::new(nop_management_content::ContentListResponseCodec))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::ContentNavIndexResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(nop_management_content::ContentReadResponseCodec))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::ContentUploadResponseCodec::new(CONTENT_ACTION_UPLOAD_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::ContentUploadResponseCodec::new(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        ),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::ContentUploadResponseCodec::new(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
        ),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::BinaryPrevalidateResponseCodec,
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::UploadStreamInitResponseCodec::new(
            CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
        ),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::UploadStreamInitResponseCodec::new(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
        ),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_content::UploadStreamInitResponseCodec::new(
            CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
        ),
    ))?;

    Ok(())
}
