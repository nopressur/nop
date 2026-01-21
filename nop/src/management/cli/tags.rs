// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::cli::parse_utils::{next_value, parse_required_arg};
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::CliCommand;
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::management::tags::{
    AccessRule, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE_OK, TAG_ACTION_LIST_OK,
    TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest, TagChangeRequest, TagCommand,
    TagDeleteRequest, TagListRequest, TagShowRequest,
};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "tag",
        aliases: &["t"],
        commands: vec![
            CommandSpec {
                name: "add",
                aliases: &[],
                usage: &[
                    "tag add <id> --name <name> [--roles <role> ...] [--access <union|intersect>]",
                ],
                parser: parse_add,
            },
            CommandSpec {
                name: "change",
                aliases: &[],
                usage: &[
                    "tag change <id> [--new-id <id>] [--name <name>] [--roles <role> ...] [--clear-roles] [--access <union|intersect>] [--clear-access]",
                ],
                parser: parse_change,
            },
            CommandSpec {
                name: "delete",
                aliases: &[],
                usage: &["tag delete <id>"],
                parser: parse_delete,
            },
            CommandSpec {
                name: "list",
                aliases: &[],
                usage: &["tag list"],
                parser: parse_list,
            },
            CommandSpec {
                name: "show",
                aliases: &[],
                usage: &["tag show <id>"],
                parser: parse_show,
            },
        ],
    }
}

fn parse_add(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "tag id")?;
    let mut name = None;
    let mut roles: Vec<String> = Vec::new();
    let mut access_rule = None;

    let mut idx = 0;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--name" => {
                idx += 1;
                name = Some(next_value(rest, &mut idx, "--name")?);
            }
            "--roles" => {
                idx += 1;
                roles.push(next_value(rest, &mut idx, "--roles")?);
            }
            "--access" => {
                idx += 1;
                let raw = next_value(rest, &mut idx, "--access")?;
                access_rule = Some(parse_access_rule(&raw)?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for tag add: {}",
                    flag
                )));
            }
        }
    }

    let name = name.ok_or_else(|| CliError::usage("tag add requires --name"))?;

    Ok(CliCommand {
        command: ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id,
            name,
            roles,
            access_rule,
        })),
        success_actions: vec![DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_ADD_OK)],
    })
}

fn parse_change(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "tag id")?;
    let mut new_id = None;
    let mut name = None;
    let mut roles: Option<Vec<String>> = None;
    let mut clear_roles = false;
    let mut access_rule = None;
    let mut clear_access = false;

    let mut idx = 0;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--new-id" => {
                if new_id.is_some() {
                    return Err(CliError::usage("Duplicate --new-id"));
                }
                idx += 1;
                new_id = Some(next_value(rest, &mut idx, "--new-id")?);
            }
            "--name" => {
                idx += 1;
                name = Some(next_value(rest, &mut idx, "--name")?);
            }
            "--roles" => {
                if clear_roles {
                    return Err(CliError::usage("--roles cannot be used with --clear-roles"));
                }
                idx += 1;
                if roles.is_none() {
                    roles = Some(Vec::new());
                }
                let role = next_value(rest, &mut idx, "--roles")?;
                if let Some(roles_list) = roles.as_mut() {
                    roles_list.push(role);
                }
            }
            "--clear-roles" => {
                if clear_roles {
                    return Err(CliError::usage("Duplicate --clear-roles"));
                }
                if roles.is_some() {
                    return Err(CliError::usage("--clear-roles cannot be used with --roles"));
                }
                clear_roles = true;
                idx += 1;
            }
            "--access" => {
                if clear_access {
                    return Err(CliError::usage(
                        "--access cannot be used with --clear-access",
                    ));
                }
                idx += 1;
                let raw = next_value(rest, &mut idx, "--access")?;
                access_rule = Some(parse_access_rule(&raw)?);
            }
            "--clear-access" => {
                if clear_access {
                    return Err(CliError::usage("Duplicate --clear-access"));
                }
                if access_rule.is_some() {
                    return Err(CliError::usage(
                        "--clear-access cannot be used with --access",
                    ));
                }
                clear_access = true;
                idx += 1;
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for tag change: {}",
                    flag
                )));
            }
        }
    }

    if clear_roles {
        roles = Some(Vec::new());
    }

    if name.is_none()
        && roles.is_none()
        && access_rule.is_none()
        && !clear_access
        && new_id.is_none()
    {
        return Err(CliError::usage(
            "tag change requires --new-id, --name, --roles, --clear-roles, --access, or --clear-access",
        ));
    }

    Ok(CliCommand {
        command: ManagementCommand::Tags(TagCommand::Change(TagChangeRequest {
            id,
            new_id,
            name,
            roles,
            access_rule,
            clear_access,
        })),
        success_actions: vec![DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_CHANGE_OK)],
    })
}

fn parse_delete(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "tag id")?;
    if !rest.is_empty() {
        return Err(CliError::usage("tag delete takes only <id>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Tags(TagCommand::Delete(TagDeleteRequest { id })),
        success_actions: vec![DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_DELETE_OK)],
    })
}

fn parse_list(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("tag list does not take any arguments"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Tags(TagCommand::List(TagListRequest {})),
        success_actions: vec![DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_LIST_OK)],
    })
}

fn parse_show(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "tag id")?;
    if !rest.is_empty() {
        return Err(CliError::usage("tag show takes only <id>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Tags(TagCommand::Show(TagShowRequest { id })),
        success_actions: vec![DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_SHOW_OK)],
    })
}

fn parse_access_rule(value: &str) -> Result<AccessRule, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "union" => Ok(AccessRule::Union),
        "intersect" => Ok(AccessRule::Intersect),
        _ => Err(CliError::usage(
            "--access must be either 'union' or 'intersect'",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_add_requires_name() {
        let args = vec!["tag-id".to_string()];
        let err = parse_add(&args).unwrap_err();
        assert!(err.to_string().contains("--name"));
    }

    #[test]
    fn parse_change_requires_flag() {
        let args = vec!["tag-id".to_string()];
        let err = parse_change(&args).unwrap_err();
        assert!(err.to_string().contains(
            "requires --new-id, --name, --roles, --clear-roles, --access, or --clear-access"
        ));
    }

    #[test]
    fn parse_change_accepts_new_id() {
        let args = vec![
            "tag-id".to_string(),
            "--new-id".to_string(),
            "tag-new".to_string(),
        ];
        let command = parse_change(&args).expect("parse change");
        match command.command {
            ManagementCommand::Tags(TagCommand::Change(request)) => {
                assert_eq!(request.id, "tag-id");
                assert_eq!(request.new_id.as_deref(), Some("tag-new"));
            }
            other => panic!("Expected tag change command, got {:?}", other),
        }
    }

    #[test]
    fn parse_delete_rejects_extra_args() {
        let args = vec!["tag-id".to_string(), "extra".to_string()];
        let err = parse_delete(&args).unwrap_err();
        assert!(err.to_string().contains("takes only"));
    }

    #[test]
    fn parse_list_rejects_args() {
        let args = vec!["extra".to_string()];
        let err = parse_list(&args).unwrap_err();
        assert!(err.to_string().contains("does not take"));
    }

    #[test]
    fn parse_show_rejects_extra_args() {
        let args = vec!["tag-id".to_string(), "extra".to_string()];
        let err = parse_show(&args).unwrap_err();
        assert!(err.to_string().contains("takes only"));
    }
}
