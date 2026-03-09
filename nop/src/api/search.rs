// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpRequest, HttpResponse, web};
use log::error;
use serde::{Deserialize, Serialize};

use crate::config::ValidatedConfig;
use crate::iam::AuthRequest;
use crate::iam::roles::ADMIN_ROLE;
use crate::public::page_meta_cache::{PageMetaCache, check_file_access};
use crate::search::{QueryPublicRequest, SearchService};

const PUBLIC_SEARCH_QUERY_MIN_LEN: usize = 3;
const PUBLIC_SEARCH_QUERY_MAX_LEN: usize = 256;

#[derive(Serialize)]
struct ReindexResponse {
    message: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SearchQueryParams {
    #[serde(default)]
    q: String,
}

#[derive(Debug, Serialize)]
struct PublicSearchHitResponse {
    id: String,
    alias: String,
    title: String,
}

#[derive(Serialize)]
struct SearchErrorResponse {
    message: String,
}

fn query_char_len(value: &str) -> usize {
    value.trim().chars().count()
}

fn is_valid_public_query_len(value: &str) -> bool {
    let len = query_char_len(value);
    (PUBLIC_SEARCH_QUERY_MIN_LEN..=PUBLIC_SEARCH_QUERY_MAX_LEN).contains(&len)
}

pub(super) async fn search_public(
    req: HttpRequest,
    query: web::Query<SearchQueryParams>,
    search_service: web::Data<SearchService>,
    page_cache: web::Data<PageMetaCache>,
    config: web::Data<ValidatedConfig>,
) -> HttpResponse {
    if !is_valid_public_query_len(&query.q) {
        return HttpResponse::BadRequest().json(SearchErrorResponse {
            message: format!(
                "Search query must be between {} and {} characters.",
                PUBLIC_SEARCH_QUERY_MIN_LEN, PUBLIC_SEARCH_QUERY_MAX_LEN
            ),
        });
    }

    let user = req.user_info();
    let query_len = query_char_len(&query.q);
    let roles = user
        .as_ref()
        .map(|info| info.roles.clone())
        .unwrap_or_default();
    match search_service.query_public(QueryPublicRequest {
        query: query.q.clone(),
        roles,
    }) {
        Ok(hits) => {
            let user_ref = user.as_ref();
            let mut filtered = Vec::new();
            for hit in hits {
                if hit.id.is_empty() {
                    continue;
                }
                let lookup = format!("id/{}", hit.id);
                let (found, allowed) = check_file_access(
                    &page_cache,
                    &lookup,
                    user_ref,
                    Some(&req),
                    Some(config.get_ref()),
                );
                if found && allowed {
                    filtered.push(hit);
                }
            }
            filtered.sort_by_cached_key(|hit| (hit.title.to_ascii_lowercase(), hit.id.clone()));
            let response: Vec<PublicSearchHitResponse> = filtered
                .into_iter()
                .map(|hit| PublicSearchHitResponse {
                    id: hit.id,
                    alias: hit.alias,
                    title: hit.title,
                })
                .collect();
            HttpResponse::Ok().json(response)
        }
        Err(err) => {
            error!(
                "Public search query failed (query_len={}): {}",
                query_len, err
            );
            HttpResponse::InternalServerError().json(SearchErrorResponse {
                message: "Search query failed.".to_string(),
            })
        }
    }
}

pub(super) async fn force_reindex(
    req: HttpRequest,
    search_service: web::Data<SearchService>,
) -> HttpResponse {
    let Some(user) = req.user_info() else {
        return HttpResponse::Unauthorized().json(ReindexResponse {
            message: "Authentication required".to_string(),
        });
    };
    if !user.roles.iter().any(|role| role == ADMIN_ROLE) {
        return HttpResponse::Forbidden().json(ReindexResponse {
            message: "Admin role required".to_string(),
        });
    }

    match search_service.internal_force_reindex_endpoint() {
        Ok(()) => HttpResponse::Ok().json(ReindexResponse {
            message: "Search reindex completed".to_string(),
        }),
        Err(err) => {
            error!("Search reindex failed: {}", err);
            HttpResponse::InternalServerError().json(ReindexResponse {
                message: "Search reindex failed.".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_query_len_validation_enforces_bounds() {
        assert!(!is_valid_public_query_len(""));
        assert!(!is_valid_public_query_len("ab"));
        assert!(is_valid_public_query_len("abc"));
        assert!(is_valid_public_query_len(
            &"x".repeat(PUBLIC_SEARCH_QUERY_MAX_LEN)
        ));
        assert!(!is_valid_public_query_len(
            &"x".repeat(PUBLIC_SEARCH_QUERY_MAX_LEN + 1)
        ));
    }
}
