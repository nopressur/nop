// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub use nop_management_contract::{ManagementError, ManagementErrorKind};
use std::fmt;

pub trait DomainError: fmt::Display + Send + Sync + 'static {
    fn kind(&self) -> ManagementErrorKind;
}

pub type DomainResult<T> = Result<T, Box<dyn DomainError>>;
