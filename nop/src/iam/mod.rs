// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub mod jwt;
pub mod middleware;
mod password;
pub mod password_tokens;
mod service;
mod store;
pub(crate) mod types;
mod user_services;

pub use middleware::AuthRequest;
pub(crate) use password::validate_hex_field;
#[allow(unused_imports)]
pub use password::{
    build_password_provider_block, derive_back_end_hash, derive_front_end_hash, generate_salt_hex,
};
pub use service::IamService;
#[cfg(test)]
pub use store::MemoryUserStore;
pub use types::{PasswordProviderBlock, User};
pub use user_services::UserServices;
