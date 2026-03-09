// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::cli::parse_utils::{next_value, parse_required_arg};
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::CliCommand;
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::management::search::{
    MAX_QUERY_CHARS, MIN_QUERY_CHARS, SEARCH_ACTION_FIND_OK, SEARCH_ACTION_INVALIDATE_OK,
    SEARCH_ACTION_RESET_OK, SEARCH_DOMAIN_ID, SearchCommand, SearchFindRequest,
    SearchInvalidateRequest, SearchResetRequest,
};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "search",
        aliases: &["s"],
        commands: vec![
            CommandSpec {
                name: "find",
                aliases: &["f"],
                usage: &["search find [--tag <tag> ...] [--markdown-only] [--] <query words...>"],
                parser: parse_find,
            },
            CommandSpec {
                name: "invalidate",
                aliases: &["inv"],
                usage: &["search invalidate <id>"],
                parser: parse_invalidate,
            },
            CommandSpec {
                name: "reset",
                aliases: &[],
                usage: &["search reset"],
                parser: parse_reset,
            },
        ],
    }
}

fn parse_find(args: &[String]) -> Result<CliCommand, CliError> {
    let mut tags: Vec<String> = Vec::new();
    let mut markdown_only = false;
    let mut query_parts: Vec<String> = Vec::new();
    let mut idx = 0;
    let mut parsing_flags = true;

    while idx < args.len() {
        let token = &args[idx];
        if parsing_flags {
            match token.as_str() {
                "--" => {
                    parsing_flags = false;
                    idx += 1;
                    continue;
                }
                "--tag" => {
                    idx += 1;
                    tags.push(next_value(args, &mut idx, "--tag")?);
                    continue;
                }
                "--markdown-only" => {
                    if markdown_only {
                        return Err(CliError::usage("Duplicate --markdown-only"));
                    }
                    markdown_only = true;
                    idx += 1;
                    continue;
                }
                _ => {
                    if token.starts_with('-') {
                        return Err(CliError::usage(format!(
                            "Unknown flag for search find: {}",
                            token
                        )));
                    }
                    parsing_flags = false;
                }
            }
        }
        query_parts.push(token.clone());
        idx += 1;
    }

    if query_parts.is_empty() {
        return Err(CliError::usage("search find requires a query"));
    }

    let query = query_parts.join(" ").trim().to_string();
    if query.is_empty() {
        return Err(CliError::usage("search find requires a query"));
    }
    let query_len = query.chars().count();
    if !(MIN_QUERY_CHARS..=MAX_QUERY_CHARS).contains(&query_len) {
        return Err(CliError::usage(format!(
            "search find query must be {}..={} characters",
            MIN_QUERY_CHARS, MAX_QUERY_CHARS
        )));
    }

    let tags = if tags.is_empty() { None } else { Some(tags) };

    Ok(CliCommand {
        command: ManagementCommand::Search(SearchCommand::Find(SearchFindRequest {
            query,
            tags,
            markdown_only,
        })),
        success_actions: vec![DomainActionKey::new(
            SEARCH_DOMAIN_ID,
            SEARCH_ACTION_FIND_OK,
        )],
        stream_target: None,
    })
}

fn parse_invalidate(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "id")?;
    if !rest.is_empty() {
        return Err(CliError::usage("search invalidate takes only <id>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Search(SearchCommand::Invalidate(SearchInvalidateRequest {
            id,
        })),
        success_actions: vec![DomainActionKey::new(
            SEARCH_DOMAIN_ID,
            SEARCH_ACTION_INVALIDATE_OK,
        )],
        stream_target: None,
    })
}

fn parse_reset(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("search reset takes no arguments"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Search(SearchCommand::Reset(SearchResetRequest {})),
        success_actions: vec![DomainActionKey::new(
            SEARCH_DOMAIN_ID,
            SEARCH_ACTION_RESET_OK,
        )],
        stream_target: None,
    })
}
