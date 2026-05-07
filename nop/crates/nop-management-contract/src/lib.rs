// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub mod codec;
pub mod content;
pub mod core;
pub mod errors;
mod macros;
pub mod registry;
pub mod roles;
pub mod search;
pub mod system;
pub mod tags;
pub mod users;
pub mod wire;

pub use codec::{
    CodecError, FieldLimit, FieldLimits, FieldValue, FieldValues, RequestCodec, ResponseCodec,
    decode_payload, encode_payload, validate_field_limits,
};
pub use core::{
    ManagementCommand, ManagementRequest, ManagementResponse, MessageResponse, ResponsePayload,
};
pub use errors::{ManagementError, ManagementErrorKind};
pub use registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
pub use roles::AccessRule;
pub use wire::{OptionMap, WireDecode, WireEncode, WireError, WireReader, WireResult, WireWriter};
