// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::HttpRequest;

use crate::RenderTools;
use crate::shortcode::ShortcodeRegistry;
use nop_config::ValidatedConfig;
use nop_rt_iam::types::User;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_paths::RuntimePaths;
use nop_rt_release::ReleaseTracker;
use nop_rt_templates::RequestTools;
use nop_rt_templates::TemplateEngine;

pub struct PublicRequestContext<'a> {
    pub config: &'a ValidatedConfig,
    pub cache: &'a PageMetaCache,
    pub shortcode_registry: &'a ShortcodeRegistry,
    pub release_tracker: &'a ReleaseTracker,
    pub runtime_paths: &'a RuntimePaths,
    pub request_tools: &'a RequestTools,
    pub render_tools: &'a RenderTools,
    pub req: &'a HttpRequest,
    user: Option<User>,
}

impl<'a> PublicRequestContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &'a ValidatedConfig,
        cache: &'a PageMetaCache,
        shortcode_registry: &'a ShortcodeRegistry,
        release_tracker: &'a ReleaseTracker,
        runtime_paths: &'a RuntimePaths,
        request_tools: &'a RequestTools,
        render_tools: &'a RenderTools,
        req: &'a HttpRequest,
        user: Option<User>,
    ) -> Self {
        Self {
            config,
            cache,
            shortcode_registry,
            release_tracker,
            runtime_paths,
            request_tools,
            render_tools,
            req,
            user,
        }
    }

    pub fn user(&self) -> Option<&User> {
        self.user.as_ref()
    }
}

pub struct PageRenderContext<'a> {
    pub config: &'a ValidatedConfig,
    pub runtime_paths: &'a RuntimePaths,
    pub theme: Option<&'a str>,
    pub release_tracker: &'a ReleaseTracker,
    pub template_engine: &'a dyn TemplateEngine,
}
