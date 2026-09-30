// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::cli::parse_utils::next_value;
use crate::cli::{CliError, CommandSpec, DomainSpec};
use crate::cli_helper::CliCommand;
use nop_config::{
    WEBSITE_DESCRIPTION_MAX_CHARS, WEBSITE_NAME_MAX_CHARS, WEBSITE_TITLE_MAX_CHARS,
    normalize_optional_setting, normalize_required_setting,
};
use nop_management_contract::DomainActionKey;
use nop_management_contract::ManagementCommand;
use nop_management_contract::settings::{
    SETTINGS_ACTION_GET_OK, SETTINGS_ACTION_SET_DESCRIPTION_OK, SETTINGS_ACTION_SET_NAME_OK,
    SETTINGS_ACTION_SET_TITLE_OK, SETTINGS_DOMAIN_ID, SettingsCommand, SettingsGetRequest,
    SettingsSetDescriptionRequest, SettingsSetNameRequest, SettingsSetTitleRequest,
};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "settings",
        aliases: &["setting"],
        commands: vec![
            CommandSpec {
                name: "show",
                aliases: &[],
                usage: &["settings show"],
                parser: parse_show,
            },
            CommandSpec {
                name: "name",
                aliases: &[],
                usage: &["settings name set --name <name>"],
                parser: parse_name,
            },
            CommandSpec {
                name: "title",
                aliases: &["website-title"],
                usage: &["settings title set --title <title>", "settings title clear"],
                parser: parse_title,
            },
            CommandSpec {
                name: "description",
                aliases: &[],
                usage: &[
                    "settings description set --description <description>",
                    "settings description clear",
                ],
                parser: parse_description,
            },
        ],
    }
}

fn parse_show(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("settings show takes no arguments"));
    }
    Ok(CliCommand {
        command: ManagementCommand::Settings(SettingsCommand::Get(SettingsGetRequest {})),
        success_actions: vec![DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_GET_OK,
        )],
        stream_target: None,
    })
}

fn parse_name(args: &[String]) -> Result<CliCommand, CliError> {
    if args.is_empty() {
        return Err(CliError::usage("settings name requires: set"));
    }
    let command = args[0].to_ascii_lowercase();
    match command.as_str() {
        "set" => parse_name_set(&args[1..]),
        value => Err(CliError::usage(format!(
            "Unknown settings name command '{}'",
            value
        ))),
    }
}

fn parse_name_set(args: &[String]) -> Result<CliCommand, CliError> {
    let name = parse_required_flag(args, "--name", "settings name set")?;
    let name = normalize_required_setting("settings.name", &name, WEBSITE_NAME_MAX_CHARS)
        .map_err(|err| CliError::usage(err.to_string()))?;
    Ok(CliCommand {
        command: ManagementCommand::Settings(SettingsCommand::SetName(SettingsSetNameRequest {
            name,
        })),
        success_actions: vec![DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_NAME_OK,
        )],
        stream_target: None,
    })
}

fn parse_title(args: &[String]) -> Result<CliCommand, CliError> {
    if args.is_empty() {
        return Err(CliError::usage(
            "settings title requires one of: set, clear",
        ));
    }
    let command = args[0].to_ascii_lowercase();
    match command.as_str() {
        "set" => parse_title_set(&args[1..]),
        "clear" => parse_title_clear(&args[1..]),
        value => Err(CliError::usage(format!(
            "Unknown settings title command '{}'",
            value
        ))),
    }
}

fn parse_title_set(args: &[String]) -> Result<CliCommand, CliError> {
    let title = parse_required_flag(args, "--title", "settings title set")?;
    let title = normalize_optional_setting("settings.title", Some(&title), WEBSITE_TITLE_MAX_CHARS)
        .map_err(|err| CliError::usage(err.to_string()))?;

    Ok(set_title_command(title))
}

fn parse_title_clear(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("settings title clear takes no arguments"));
    }
    Ok(set_title_command(None))
}

fn set_title_command(title: Option<String>) -> CliCommand {
    CliCommand {
        command: ManagementCommand::Settings(SettingsCommand::SetTitle(SettingsSetTitleRequest {
            title,
        })),
        success_actions: vec![DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_TITLE_OK,
        )],
        stream_target: None,
    }
}

fn parse_description(args: &[String]) -> Result<CliCommand, CliError> {
    if args.is_empty() {
        return Err(CliError::usage(
            "settings description requires one of: set, clear",
        ));
    }
    let command = args[0].to_ascii_lowercase();
    match command.as_str() {
        "set" => parse_description_set(&args[1..]),
        "clear" => parse_description_clear(&args[1..]),
        value => Err(CliError::usage(format!(
            "Unknown settings description command '{}'",
            value
        ))),
    }
}

fn parse_description_set(args: &[String]) -> Result<CliCommand, CliError> {
    let description = parse_required_flag(args, "--description", "settings description set")?;
    let description = normalize_optional_setting(
        "settings.description",
        Some(&description),
        WEBSITE_DESCRIPTION_MAX_CHARS,
    )
    .map_err(|err| CliError::usage(err.to_string()))?;

    Ok(CliCommand {
        command: ManagementCommand::Settings(SettingsCommand::SetDescription(
            SettingsSetDescriptionRequest { description },
        )),
        success_actions: vec![DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_DESCRIPTION_OK,
        )],
        stream_target: None,
    })
}

fn parse_description_clear(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage(
            "settings description clear takes no arguments",
        ));
    }
    Ok(CliCommand {
        command: ManagementCommand::Settings(SettingsCommand::SetDescription(
            SettingsSetDescriptionRequest { description: None },
        )),
        success_actions: vec![DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_DESCRIPTION_OK,
        )],
        stream_target: None,
    })
}

fn parse_required_flag(
    args: &[String],
    flag_name: &'static str,
    command_name: &'static str,
) -> Result<String, CliError> {
    let mut value: Option<String> = None;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            flag if flag == flag_name => {
                if value.is_some() {
                    return Err(CliError::usage(format!("Duplicate {}", flag_name)));
                }
                idx += 1;
                value = Some(next_value(args, &mut idx, flag_name)?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for {}: {}",
                    command_name, flag
                )));
            }
        }
    }

    value.ok_or_else(|| CliError::usage(format!("{} requires {} <value>", command_name, flag_name)))
}

#[allow(dead_code)]
fn parse_website_title_set(args: &[String]) -> Result<CliCommand, CliError> {
    let mut title: Option<String> = None;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--title" => {
                if title.is_some() {
                    return Err(CliError::usage("Duplicate --title"));
                }
                idx += 1;
                title = Some(next_value(args, &mut idx, "--title")?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for settings website-title set: {}",
                    flag
                )));
            }
        }
    }

    let title = title
        .ok_or_else(|| CliError::usage("settings website-title set requires --title <title>"))?;
    let website_title =
        normalize_optional_setting("settings.title", Some(&title), WEBSITE_TITLE_MAX_CHARS)
            .map_err(|err| CliError::usage(err.to_string()))?;

    Ok(set_title_command(website_title))
}

#[allow(dead_code)]
fn parse_website_title_clear(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage(
            "settings website-title clear takes no arguments",
        ));
    }
    Ok(set_title_command(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_show_builds_command() {
        let command = parse_show(&[]).expect("settings show command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_GET_OK
        )));
        match command.command {
            ManagementCommand::Settings(SettingsCommand::Get(_)) => {}
            _ => panic!("expected settings get command"),
        }
    }

    #[test]
    fn parse_name_set_builds_command() {
        let args = vec!["--name".to_string(), "  Example Name  ".to_string()];
        let command = parse_name_set(&args).expect("settings name set command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_NAME_OK
        )));
        match command.command {
            ManagementCommand::Settings(SettingsCommand::SetName(request)) => {
                assert_eq!(request.name, "Example Name");
            }
            _ => panic!("expected settings name set command"),
        }
    }

    #[test]
    fn parse_title_set_builds_command() {
        let args = vec!["--title".to_string(), "  Example Site  ".to_string()];
        let command = parse_title_set(&args).expect("settings title set command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_TITLE_OK
        )));
        match command.command {
            ManagementCommand::Settings(SettingsCommand::SetTitle(request)) => {
                assert_eq!(request.title.as_deref(), Some("Example Site"));
            }
            _ => panic!("expected settings title set command"),
        }
    }

    #[test]
    fn parse_title_clear_builds_command() {
        let command = parse_title_clear(&[]).expect("settings title clear command");
        match command.command {
            ManagementCommand::Settings(SettingsCommand::SetTitle(request)) => {
                assert_eq!(request.title, None);
            }
            _ => panic!("expected settings title set command"),
        }
    }

    #[test]
    fn parse_description_set_builds_command() {
        let args = vec![
            "--description".to_string(),
            "  Example description  ".to_string(),
        ];
        let command = parse_description_set(&args).expect("settings description set command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SETTINGS_DOMAIN_ID,
            SETTINGS_ACTION_SET_DESCRIPTION_OK
        )));
        match command.command {
            ManagementCommand::Settings(SettingsCommand::SetDescription(request)) => {
                assert_eq!(request.description.as_deref(), Some("Example description"));
            }
            _ => panic!("expected settings description set command"),
        }
    }

    #[test]
    fn parse_title_set_rejects_missing_title() {
        let err = parse_title_set(&[]).expect_err("should reject missing title");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("--title"));
    }

    #[test]
    fn parse_title_set_rejects_invalid_flags() {
        let args = vec!["--name".to_string(), "Example".to_string()];
        let err = parse_title_set(&args).expect_err("should reject invalid flag");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("Unknown flag"));
    }

    #[test]
    fn parse_title_set_rejects_invalid_title() {
        let args = vec![
            "--title".to_string(),
            "x".repeat(WEBSITE_TITLE_MAX_CHARS + 1),
        ];
        let err = parse_title_set(&args).expect_err("should reject long title");
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("settings.title"));
    }
}
