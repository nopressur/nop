// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::sync::Arc;

use crate::login::LoginSessionStore;
use crate::management::{ManagementBus, UploadRegistry};
use crate::public::error::ErrorRenderer;
use crate::public::markdown::HtmlSanitizer;
use crate::runtime_paths::RuntimePaths;
use crate::security::{AuthActionLimiter, ThreatTracker};
use crate::templates::{MiniJinjaEngine, TemplateEngine};

pub struct AppState {
    pub templates: Arc<dyn TemplateEngine>,
    pub error_renderer: ErrorRenderer,
    pub html_sanitizer: HtmlSanitizer,
    pub threat_tracker: ThreatTracker,
    pub login_sessions: LoginSessionStore,
    pub auth_action_limiter: AuthActionLimiter,
    pub runtime_paths: RuntimePaths,
    pub management_bus: ManagementBus,
    pub upload_registry: Arc<UploadRegistry>,
}

impl AppState {
    pub fn new(
        app_name: &str,
        runtime_paths: RuntimePaths,
        management_bus: ManagementBus,
        upload_registry: Arc<UploadRegistry>,
    ) -> Self {
        Self {
            templates: Arc::new(MiniJinjaEngine::new()),
            error_renderer: ErrorRenderer::new(app_name.to_string()),
            html_sanitizer: HtmlSanitizer::new(),
            threat_tracker: ThreatTracker::new(),
            login_sessions: LoginSessionStore::new(),
            auth_action_limiter: AuthActionLimiter::new(),
            runtime_paths,
            management_bus,
            upload_registry,
        }
    }
}

#[cfg(test)]
impl AppState {
    pub fn new_for_tests(
        app_name: &str,
        runtime_paths: RuntimePaths,
        config: crate::config::ValidatedConfig,
    ) -> Self {
        let registry =
            crate::management::build_default_registry().expect("test management registry");
        let upload_registry = Arc::new(UploadRegistry::new());
        let context = crate::management::ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(config),
            runtime_paths.clone(),
        )
        .expect("test management context")
        .with_upload_registry(upload_registry.clone());
        let bus = crate::management::ManagementBus::start(registry, context);
        Self::new(app_name, runtime_paths, bus, upload_registry)
    }
}
