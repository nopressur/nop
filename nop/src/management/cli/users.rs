// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::cli::parse_utils::{next_value, parse_required_arg};
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::CliCommand;
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::management::users::{
    PasswordPayload, USER_ACTION_ADD_OK, USER_ACTION_CHANGE_OK, USER_ACTION_DELETE_OK,
    USER_ACTION_LIST_OK, USER_ACTION_PASSWORD_SET_OK, USER_ACTION_SHOW_OK, USERS_DOMAIN_ID,
    UserAddRequest, UserChangeRequest, UserCommand, UserDeleteRequest, UserListRequest,
    UserPasswordSetRequest, UserShowRequest,
};
use rpassword::read_password;
use std::io::Write;

const MAX_PASSWORD_CHARS: usize = 1024;

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "user",
        aliases: &["u"],
        commands: vec![
            CommandSpec {
                name: "add",
                aliases: &[],
                usage: &[
                    "user add <email> --name <display-name> [--roles <role> ...] [--password <password>]",
                ],
                parser: parse_add,
            },
            CommandSpec {
                name: "change",
                aliases: &[],
                usage: &[
                    "user change <email> [--name <display-name>] [--roles <role> ...] [--clear-roles]",
                ],
                parser: parse_change,
            },
            CommandSpec {
                name: "delete",
                aliases: &[],
                usage: &["user delete <email>"],
                parser: parse_delete,
            },
            CommandSpec {
                name: "password",
                aliases: &[],
                usage: &["user password <email> [--password <password>]"],
                parser: parse_password,
            },
            CommandSpec {
                name: "list",
                aliases: &[],
                usage: &["user list"],
                parser: parse_list,
            },
            CommandSpec {
                name: "show",
                aliases: &[],
                usage: &["user show <email>"],
                parser: parse_show,
            },
        ],
    }
}

fn parse_add(args: &[String]) -> Result<CliCommand, CliError> {
    let (email, rest) = parse_required_arg(args, "email")?;
    let mut name = None;
    let mut roles: Vec<String> = Vec::new();
    let mut password = None;

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
            "--password" => {
                idx += 1;
                password = Some(next_value(rest, &mut idx, "--password")?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for user add: {}",
                    flag
                )));
            }
        }
    }

    let name = name.ok_or_else(|| CliError::usage("user add requires --name"))?;
    let password = match password {
        Some(value) => value,
        None => prompt_password("Enter password: ", "Confirm password: ")?,
    };
    validate_plain_password(&password)?;
    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::Add(UserAddRequest {
            email,
            name,
            password: PasswordPayload::Plaintext {
                plaintext: password,
            },
            roles,
            change_token: None,
        })),
        success_actions: vec![DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ADD_OK)],
    })
}

fn parse_change(args: &[String]) -> Result<CliCommand, CliError> {
    let (email, rest) = parse_required_arg(args, "email")?;
    let mut name = None;
    let mut roles: Option<Vec<String>> = None;
    let mut clear_roles = false;

    let mut idx = 0;
    while idx < rest.len() {
        match rest[idx].as_str() {
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
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for user change: {}",
                    flag
                )));
            }
        }
    }

    if clear_roles {
        roles = Some(Vec::new());
    }

    if name.is_none() && roles.is_none() {
        return Err(CliError::usage(
            "user change requires --name, --roles, or --clear-roles",
        ));
    }

    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::Change(UserChangeRequest {
            email,
            name,
            roles,
        })),
        success_actions: vec![DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_CHANGE_OK)],
    })
}

fn parse_delete(args: &[String]) -> Result<CliCommand, CliError> {
    let (email, rest) = parse_required_arg(args, "email")?;
    if !rest.is_empty() {
        return Err(CliError::usage("user delete takes only <email>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::Delete(UserDeleteRequest { email })),
        success_actions: vec![DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_DELETE_OK)],
    })
}

fn parse_password(args: &[String]) -> Result<CliCommand, CliError> {
    let (email, rest) = parse_required_arg(args, "email")?;
    let mut password = None;
    let mut idx = 0;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--password" => {
                idx += 1;
                password = Some(next_value(rest, &mut idx, "--password")?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for user password: {}",
                    flag
                )));
            }
        }
    }

    let password = match password {
        Some(value) => value,
        None => prompt_password("Enter password: ", "Confirm password: ")?,
    };
    validate_plain_password(&password)?;
    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::PasswordSet(UserPasswordSetRequest {
            email,
            password: PasswordPayload::Plaintext {
                plaintext: password,
            },
            change_token: None,
        })),
        success_actions: vec![DomainActionKey::new(
            USERS_DOMAIN_ID,
            USER_ACTION_PASSWORD_SET_OK,
        )],
    })
}

fn parse_list(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("user list does not take any arguments"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::List(UserListRequest {})),
        success_actions: vec![DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_LIST_OK)],
    })
}

fn parse_show(args: &[String]) -> Result<CliCommand, CliError> {
    let (email, rest) = parse_required_arg(args, "email")?;
    if !rest.is_empty() {
        return Err(CliError::usage("user show takes only <email>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Users(UserCommand::Show(UserShowRequest { email })),
        success_actions: vec![DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_SHOW_OK)],
    })
}

fn prompt_password(prompt: &str, confirm: &str) -> Result<String, CliError> {
    let password1 = read_password_line(prompt)?;
    let password2 = read_password_line(confirm)?;
    if password1 != password2 {
        return Err(CliError::usage("Passwords do not match"));
    }
    Ok(password1)
}

fn read_password_line(prompt: &str) -> Result<String, CliError> {
    print!("{}", prompt);
    std::io::stdout()
        .flush()
        .map_err(|err| CliError::usage(format!("Failed to read password: {}", err)))?;
    read_password().map_err(|err| CliError::usage(format!("Failed to read password: {}", err)))
}

fn validate_plain_password(password: &str) -> Result<(), CliError> {
    if password.is_empty() {
        return Err(CliError::usage("Password is required"));
    }
    if password.chars().count() > MAX_PASSWORD_CHARS {
        return Err(CliError::usage(format!(
            "Password must be at most {} characters",
            MAX_PASSWORD_CHARS
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_add_requires_name() {
        let args = vec!["user@example.com".to_string()];
        let err = parse_add(&args).unwrap_err();
        assert!(err.to_string().contains("--name"));
    }

    #[test]
    fn parse_change_requires_flag() {
        let args = vec!["user@example.com".to_string()];
        let err = parse_change(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires --name, --roles, or --clear-roles")
        );
    }

    #[test]
    fn parse_delete_rejects_extra_args() {
        let args = vec!["user@example.com".to_string(), "extra".to_string()];
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
        let args = vec!["user@example.com".to_string(), "extra".to_string()];
        let err = parse_show(&args).unwrap_err();
        assert!(err.to_string().contains("takes only"));
    }
}
