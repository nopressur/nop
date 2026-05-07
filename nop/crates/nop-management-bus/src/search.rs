// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::{ManagementHandler, ManagementRegistry, RegistryError};
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use std::sync::Arc;

use nop_management_search::{
    SEARCH_ACTION_FIND, SEARCH_ACTION_FIND_ERR, SEARCH_ACTION_FIND_OK, SEARCH_ACTION_INVALIDATE,
    SEARCH_ACTION_INVALIDATE_ERR, SEARCH_ACTION_INVALIDATE_OK, SEARCH_ACTION_RESET,
    SEARCH_ACTION_RESET_ERR, SEARCH_ACTION_RESET_OK, SEARCH_DOMAIN_ID, handle_search_request,
};

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "search",
        id: SEARCH_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "find",
                id: SEARCH_ACTION_FIND,
            },
            ActionDescriptor {
                name: "invalidate",
                id: SEARCH_ACTION_INVALIDATE,
            },
            ActionDescriptor {
                name: "reset",
                id: SEARCH_ACTION_RESET,
            },
            ActionDescriptor {
                name: "find_ok",
                id: SEARCH_ACTION_FIND_OK,
            },
            ActionDescriptor {
                name: "find_err",
                id: SEARCH_ACTION_FIND_ERR,
            },
            ActionDescriptor {
                name: "invalidate_ok",
                id: SEARCH_ACTION_INVALIDATE_OK,
            },
            ActionDescriptor {
                name: "invalidate_err",
                id: SEARCH_ACTION_INVALIDATE_ERR,
            },
            ActionDescriptor {
                name: "reset_ok",
                id: SEARCH_ACTION_RESET_OK,
            },
            ActionDescriptor {
                name: "reset_err",
                id: SEARCH_ACTION_RESET_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_search_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_FIND),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_INVALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_RESET),
        handler,
    )?;

    registry.register_request_codec(Arc::new(nop_management_search::SearchFindRequestCodec))?;
    registry.register_request_codec(Arc::new(
        nop_management_search::SearchInvalidateRequestCodec,
    ))?;
    registry.register_request_codec(Arc::new(nop_management_search::SearchResetRequestCodec))?;

    registry.register_response_codec(Arc::new(nop_management_search::SearchFindResponseCodec))?;
    registry.register_response_codec(Arc::new(
        nop_management_search::MessageResponseCodec::new(SEARCH_ACTION_FIND_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_search::MessageResponseCodec::new(SEARCH_ACTION_INVALIDATE_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_search::MessageResponseCodec::new(SEARCH_ACTION_INVALIDATE_ERR),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_search::MessageResponseCodec::new(SEARCH_ACTION_RESET_OK),
    ))?;
    registry.register_response_codec(Arc::new(
        nop_management_search::MessageResponseCodec::new(SEARCH_ACTION_RESET_ERR),
    ))?;

    Ok(())
}
