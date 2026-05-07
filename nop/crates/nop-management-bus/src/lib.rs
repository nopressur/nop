// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

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
mod mime;
mod registry;
mod roles;
mod search;
pub mod socket;
mod system;
mod tags;
mod upload_registry;
mod users;
mod workflow;
mod workflow_capabilities;
pub mod ws;

pub use blocking::{BlockingError, BlockingPool};
pub use bus::ManagementBus;
pub use codec::CodecRegistry;
pub use connection_ids::next_connection_id;
pub use core::{ManagementContext, VersionInfo};
pub use registry::{ManagementHandler, ManagementRegistry, RegistryError};
pub use upload_registry::UploadRegistry;

#[derive(Clone)]
pub struct ManagementTools {
    pub management_bus: ManagementBus,
    pub upload_registry: std::sync::Arc<UploadRegistry>,
}

impl ManagementTools {
    pub fn new(
        management_bus: ManagementBus,
        upload_registry: std::sync::Arc<UploadRegistry>,
    ) -> Self {
        Self {
            management_bus,
            upload_registry,
        }
    }
}
pub use workflow::{WorkflowCounter, WorkflowTracker};

pub fn build_default_registry() -> Result<ManagementRegistry, RegistryError> {
    let mut registry = ManagementRegistry::new();
    system::register(&mut registry)?;
    users::register(&mut registry)?;
    roles::register(&mut registry)?;
    tags::register(&mut registry)?;
    content::register(&mut registry)?;
    search::register(&mut registry)?;
    Ok(registry)
}
