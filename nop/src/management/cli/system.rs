// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::VersionInfo;
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::CliCommand;
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::management::system::{
    ClearLogsRequest, GetLoggingConfigRequest, PingRequest, SYSTEM_ACTION_LOGGING_CLEAR_OK,
    SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_LOGGING_SET_OK, SYSTEM_ACTION_PONG,
    SYSTEM_DOMAIN_ID, SetLoggingConfigRequest, SystemCommand,
};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "system",
        aliases: &["sys"],
        commands: vec![
            CommandSpec {
                name: "ping",
                aliases: &["p"],
                usage: &["system ping"],
                parser: parse_ping,
            },
            CommandSpec {
                name: "logging",
                aliases: &["log"],
                usage: &[
                    "system logging show",
                    "system logging set --max-size-mb <mb> --max-files <count>",
                    "system logging clear",
                ],
                parser: parse_logging,
            },
        ],
    }
}

pub fn ping_command() -> Result<CliCommand, CliError> {
    let version =
        VersionInfo::from_pkg_version().map_err(|err| CliError::connector(err.to_string()))?;
    Ok(CliCommand {
        command: ManagementCommand::System(SystemCommand::Ping(PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        })),
        success_actions: vec![DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG)],
    })
}

fn parse_ping(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("system ping takes no arguments"));
    }
    ping_command()
}

fn parse_logging(args: &[String]) -> Result<CliCommand, CliError> {
    if args.is_empty() {
        return Err(CliError::usage(
            "system logging requires one of: show, set, clear",
        ));
    }
    let command = args[0].to_ascii_lowercase();
    match command.as_str() {
        "show" => parse_logging_show(&args[1..]),
        "set" => parse_logging_set(&args[1..]),
        "clear" => parse_logging_clear(&args[1..]),
        value => Err(CliError::usage(format!(
            "Unknown system logging command '{}'",
            value
        ))),
    }
}

fn parse_logging_show(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("system logging show takes no arguments"));
    }
    Ok(CliCommand {
        command: ManagementCommand::System(SystemCommand::GetLoggingConfig(
            GetLoggingConfigRequest {},
        )),
        success_actions: vec![DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_GET_OK,
        )],
    })
}

fn parse_logging_set(args: &[String]) -> Result<CliCommand, CliError> {
    let mut max_size_mb: Option<u64> = None;
    let mut max_files: Option<u32> = None;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--max-size-mb" => {
                idx += 1;
                let value = next_value(args, &mut idx, "--max-size-mb")?;
                max_size_mb = Some(value.parse::<u64>().map_err(|_| {
                    CliError::usage("system logging set --max-size-mb must be a number")
                })?);
            }
            "--max-files" => {
                idx += 1;
                let value = next_value(args, &mut idx, "--max-files")?;
                max_files = Some(value.parse::<u32>().map_err(|_| {
                    CliError::usage("system logging set --max-files must be a number")
                })?);
            }
            flag => {
                return Err(CliError::usage(format!(
                    "Unknown flag for system logging set: {}",
                    flag
                )));
            }
        }
        idx += 1;
    }

    let max_size_mb = max_size_mb.ok_or_else(|| {
        CliError::usage("system logging set requires --max-size-mb and --max-files")
    })?;
    let max_files = max_files.ok_or_else(|| {
        CliError::usage("system logging set requires --max-size-mb and --max-files")
    })?;

    Ok(CliCommand {
        command: ManagementCommand::System(SystemCommand::SetLoggingConfig(
            SetLoggingConfigRequest {
                rotation_max_size_mb: max_size_mb,
                rotation_max_files: max_files,
            },
        )),
        success_actions: vec![DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_SET_OK,
        )],
    })
}

fn parse_logging_clear(args: &[String]) -> Result<CliCommand, CliError> {
    if !args.is_empty() {
        return Err(CliError::usage("system logging clear takes no arguments"));
    }
    Ok(CliCommand {
        command: ManagementCommand::System(SystemCommand::ClearLogs(ClearLogsRequest {})),
        success_actions: vec![DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_CLEAR_OK,
        )],
    })
}

fn next_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str, CliError> {
    let value = args
        .get(*idx)
        .ok_or_else(|| CliError::usage(format!("Missing value for {}", flag)))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_logging_show_builds_command() {
        let command = parse_logging_show(&[]).expect("logging show command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_GET_OK
        )));
        match command.command {
            ManagementCommand::System(SystemCommand::GetLoggingConfig(_)) => {}
            _ => panic!("expected logging get command"),
        }
    }

    #[test]
    fn parse_logging_set_builds_command() {
        let args = vec![
            "--max-size-mb".to_string(),
            "20".to_string(),
            "--max-files".to_string(),
            "5".to_string(),
        ];
        let command = parse_logging_set(&args).expect("logging set command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_SET_OK
        )));
        match command.command {
            ManagementCommand::System(SystemCommand::SetLoggingConfig(request)) => {
                assert_eq!(request.rotation_max_size_mb, 20);
                assert_eq!(request.rotation_max_files, 5);
            }
            _ => panic!("expected logging set command"),
        }
    }

    #[test]
    fn parse_logging_clear_builds_command() {
        let command = parse_logging_clear(&[]).expect("logging clear command");
        assert!(command.success_actions.contains(&DomainActionKey::new(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_LOGGING_CLEAR_OK
        )));
        match command.command {
            ManagementCommand::System(SystemCommand::ClearLogs(_)) => {}
            _ => panic!("expected logging clear command"),
        }
    }

    #[test]
    fn parse_logging_set_requires_flags() {
        let args = vec!["--max-size-mb".to_string(), "20".to_string()];
        let err = parse_logging_set(&args).expect_err("should reject missing flag");
        assert!(err.to_string().contains("--max-size-mb"));
    }
}
