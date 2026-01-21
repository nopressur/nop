// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::cli::parse_utils::{next_value, parse_required_arg};
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::CliCommand;
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::management::roles::{
    ROLE_ACTION_ADD_OK, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST_OK,
    ROLE_ACTION_SHOW_OK, ROLES_DOMAIN_ID, RoleAddRequest, RoleChangeRequest, RoleCommand,
    RoleDeleteRequest, RoleListRequest, RoleShowRequest,
};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "role",
        aliases: &["r"],
        commands: vec![
            CommandSpec {
                name: "add",
                aliases: &[],
                usage: &["role add <role>"],
                parser: parse_add,
            },
            CommandSpec {
                name: "change",
                aliases: &[],
                usage: &["role change <role> --new-role <role>"],
                parser: parse_change,
            },
            CommandSpec {
                name: "delete",
                aliases: &[],
                usage: &["role delete <role>"],
                parser: parse_delete,
            },
            CommandSpec {
                name: "list",
                aliases: &[],
                usage: &["role list"],
                parser: parse_list,
            },
            CommandSpec {
                name: "show",
                aliases: &[],
                usage: &["role show <role>"],
                parser: parse_show,
            },
        ],
    }
}

fn parse_add(args: &[String]) -> Result<CliCommand, CliError> {
    let (role, rest) = parse_required_arg(args, "role")?;
    if !rest.is_empty() {
        return Err(CliError::usage("role add takes only <role>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Roles(RoleCommand::Add(RoleAddRequest { role })),
        success_actions: vec![DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_ADD_OK)],
    })
}

fn parse_change(args: &[String]) -> Result<CliCommand, CliError> {
    let (role, rest) = parse_required_arg(args, "role")?;
    let mut new_role = None;

    let mut idx = 0;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--new-role" => {
                idx += 1;
                new_role = Some(next_value(rest, &mut idx, "--new-role")?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for role change: {}",
                    flag
                )));
            }
        }
    }

    let new_role = new_role.ok_or_else(|| CliError::usage("role change requires --new-role"))?;

    Ok(CliCommand {
        command: ManagementCommand::Roles(RoleCommand::Change(RoleChangeRequest {
            role,
            new_role,
        })),
        success_actions: vec![DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE_OK)],
    })
}

fn parse_delete(args: &[String]) -> Result<CliCommand, CliError> {
    let (role, rest) = parse_required_arg(args, "role")?;
    if !rest.is_empty() {
        return Err(CliError::usage("role delete takes only <role>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Roles(RoleCommand::Delete(RoleDeleteRequest { role })),
        success_actions: vec![DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_DELETE_OK)],
    })
}

fn parse_list(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("role list does not take any arguments"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Roles(RoleCommand::List(RoleListRequest {})),
        success_actions: vec![DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_LIST_OK)],
    })
}

fn parse_show(args: &[String]) -> Result<CliCommand, CliError> {
    let (role, rest) = parse_required_arg(args, "role")?;
    if !rest.is_empty() {
        return Err(CliError::usage("role show takes only <role>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Roles(RoleCommand::Show(RoleShowRequest { role })),
        success_actions: vec![DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_SHOW_OK)],
    })
}
