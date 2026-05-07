// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainActionKey {
    pub domain_id: u32,
    pub action_id: u32,
}

impl DomainActionKey {
    pub fn new(domain_id: u32, action_id: u32) -> Self {
        Self {
            domain_id,
            action_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    pub name: &'static str,
    pub id: u32,
}

#[derive(Debug, Clone)]
pub struct DomainDescriptor {
    pub name: &'static str,
    pub id: u32,
    pub actions: Vec<ActionDescriptor>,
}
