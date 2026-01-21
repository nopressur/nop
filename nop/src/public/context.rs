// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::HttpRequest;

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::iam::User;
use crate::public::page_meta_cache::PageMetaCache;
use crate::public::shortcode::ShortcodeRegistry;
use crate::runtime_paths::RuntimePaths;
use crate::templates::TemplateEngine;
use crate::util::ReleaseTracker;

pub struct PublicRequestContext<'a> {
    pub config: &'a ValidatedConfig,
    pub cache: &'a PageMetaCache,
    pub shortcode_registry: &'a ShortcodeRegistry,
    pub release_tracker: &'a ReleaseTracker,
    pub app_state: &'a AppState,
    pub req: &'a HttpRequest,
    user: Option<User>,
}

impl<'a> PublicRequestContext<'a> {
    pub fn new(
        config: &'a ValidatedConfig,
        cache: &'a PageMetaCache,
        shortcode_registry: &'a ShortcodeRegistry,
        release_tracker: &'a ReleaseTracker,
        app_state: &'a AppState,
        req: &'a HttpRequest,
        user: Option<User>,
    ) -> Self {
        Self {
            config,
            cache,
            shortcode_registry,
            release_tracker,
            app_state,
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
    pub user: Option<&'a User>,
    pub release_tracker: &'a ReleaseTracker,
    pub template_engine: &'a dyn TemplateEngine,
}
