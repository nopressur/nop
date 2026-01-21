// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub(crate) mod parse_utils;
pub mod roles;
pub mod system;
pub mod tags;
pub mod users;

use crate::management::cli_helper::CliCommand;
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliErrorKind {
    Usage,
    Connector,
}

#[derive(Debug, Clone)]
pub struct CliError {
    kind: CliErrorKind,
    message: String,
}

impl CliError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Usage,
            message: message.into(),
        }
    }

    pub fn connector(message: impl Into<String>) -> Self {
        Self {
            kind: CliErrorKind::Connector,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.kind {
            CliErrorKind::Usage => 2,
            CliErrorKind::Connector => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub struct CliRegistry {
    domains: Vec<DomainSpec>,
    aliases: BTreeSet<String>,
}

impl Default for CliRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CliRegistry {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            aliases: BTreeSet::new(),
        }
    }

    pub fn register_domain(&mut self, domain: DomainSpec) -> Result<(), CliError> {
        let domain_key = domain.name_lower();
        if self.aliases.contains(&domain_key) {
            return Err(CliError::usage(format!(
                "Duplicate domain alias or name '{}'",
                domain.name
            )));
        }
        self.aliases.insert(domain_key);
        for alias in domain.aliases.iter() {
            let alias_lower = alias.to_ascii_lowercase();
            if self.aliases.contains(&alias_lower) {
                return Err(CliError::usage(format!(
                    "Duplicate domain alias '{}'",
                    alias
                )));
            }
            self.aliases.insert(alias_lower);
        }

        domain.validate_commands()?;
        self.domains.push(domain);
        Ok(())
    }

    pub fn resolve_command(&self, tokens: &[String]) -> Result<CliCommand, CliError> {
        if tokens.is_empty() {
            return Err(CliError::usage("Missing command domain"));
        }
        let domain_token = tokens[0].to_ascii_lowercase();
        let domain = resolve_domain(&domain_token, &self.domains)?;
        if tokens.len() < 2 {
            return Err(CliError::usage(format!(
                "Missing command for domain '{}'",
                domain.name
            )));
        }
        let command_token = tokens[1].to_ascii_lowercase();
        let command = resolve_command_spec(&command_token, domain)?;
        let args = &tokens[2..];
        (command.parser)(args)
    }
}

pub struct DomainSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub commands: Vec<CommandSpec>,
}

impl DomainSpec {
    fn name_lower(&self) -> String {
        self.name.to_ascii_lowercase()
    }

    fn validate_commands(&self) -> Result<(), CliError> {
        let mut seen = BTreeSet::new();
        for command in self.commands.iter() {
            let name = command.name.to_ascii_lowercase();
            if !seen.insert(name.clone()) {
                return Err(CliError::usage(format!(
                    "Duplicate command name '{}' in domain '{}'",
                    command.name, self.name
                )));
            }
            for alias in command.aliases.iter() {
                let alias_lower = alias.to_ascii_lowercase();
                if !seen.insert(alias_lower.clone()) {
                    return Err(CliError::usage(format!(
                        "Duplicate command alias '{}' in domain '{}'",
                        alias, self.name
                    )));
                }
            }
        }
        Ok(())
    }
}

pub struct CommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub usage: &'static [&'static str],
    pub parser: fn(&[String]) -> Result<CliCommand, CliError>,
}

pub fn build_registry() -> Result<CliRegistry, CliError> {
    let mut registry = CliRegistry::new();
    registry.register_domain(system::domain())?;
    registry.register_domain(users::domain())?;
    registry.register_domain(roles::domain())?;
    registry.register_domain(tags::domain())?;
    Ok(registry)
}

pub fn help_text() -> String {
    let registry = match build_registry() {
        Ok(registry) => registry,
        Err(err) => {
            return format!("Failed to build CLI registry: {}", err);
        }
    };

    let mut out = String::new();
    push_line(&mut out, "Usage:");
    push_line(&mut out, "  nop [options]");
    push_line(&mut out, "  nop -F [options]");
    push_line(&mut out, "  nop [options] <domain> <command> [args]");
    push_line(&mut out, "  nop help");
    push_line(&mut out, "");
    push_line(&mut out, "Options:");
    push_line(&mut out, "  -C <root>   Set the runtime root (default: .).");
    push_line(
        &mut out,
        "  -F          Run the server in the foreground (only when no CLI command is provided).",
    );
    push_line(&mut out, "  -h, --help  Show this help.");
    push_line(&mut out, "");
    push_line(&mut out, "Domains and commands:");
    for domain in registry.domains.iter() {
        let domain_aliases = format_aliases(domain.aliases);
        push_line(&mut out, &format!("  {}{}", domain.name, domain_aliases));
        for command in domain.commands.iter() {
            let command_aliases = format_aliases(command.aliases);
            push_line(
                &mut out,
                &format!("    {}{}", command.name, command_aliases),
            );
            for usage in command.usage.iter() {
                push_line(&mut out, &format!("      {}", usage));
            }
        }
    }
    push_line(&mut out, "");
    push_line(&mut out, "Notes:");
    push_line(
        &mut out,
        "  Domains and commands are case-insensitive and accept unambiguous prefixes.",
    );
    out
}

pub async fn run_cli(runtime_root: &Path, tokens: Vec<String>) -> i32 {
    let registry = match build_registry() {
        Ok(registry) => registry,
        Err(err) => {
            eprintln!("{}", err);
            return err.exit_code();
        }
    };

    let command = match registry.resolve_command(&tokens) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("{}", err);
            return err.exit_code();
        }
    };

    match crate::management::cli_helper::execute(runtime_root, command).await {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("{}", err);
            err.exit_code()
        }
    }
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn format_aliases(aliases: &[&str]) -> String {
    if aliases.is_empty() {
        String::new()
    } else {
        format!(" (aliases: {})", aliases.join(", "))
    }
}

fn resolve_domain<'a>(token: &str, domains: &'a [DomainSpec]) -> Result<&'a DomainSpec, CliError> {
    if let Some(domain) = domains.iter().find(|domain| domain.matches_exact(token)) {
        return Ok(domain);
    }
    resolve_prefix(
        token,
        domains,
        |domain| domain.matches_prefix(token),
        |domain| domain.name,
        "domain",
    )
}

fn resolve_command_spec<'a>(
    token: &str,
    domain: &'a DomainSpec,
) -> Result<&'a CommandSpec, CliError> {
    if let Some(command) = domain.commands.iter().find(|cmd| cmd.matches_exact(token)) {
        return Ok(command);
    }
    resolve_prefix(
        token,
        &domain.commands,
        |command| command.matches_prefix(token),
        |command| command.name,
        "command",
    )
}

fn resolve_prefix<'a, T>(
    token: &str,
    items: &'a [T],
    matches: impl Fn(&T) -> bool,
    name: impl Fn(&T) -> &'static str,
    kind: &str,
) -> Result<&'a T, CliError> {
    let mut matched = items.iter().filter(|item| matches(item));
    let first = matched.next();
    let second = matched.next();
    match (first, second) {
        (Some(item), None) => Ok(item),
        (Some(_), Some(_)) => {
            let mut names: Vec<&'static str> = items
                .iter()
                .filter(|item| matches(item))
                .map(name)
                .collect();
            names.sort();
            Err(CliError::usage(format!(
                "Ambiguous {} prefix '{}': {}",
                kind,
                token,
                names.join(", ")
            )))
        }
        _ => Err(CliError::usage(format!("Unknown {} '{}'", kind, token))),
    }
}

impl DomainSpec {
    fn matches_exact(&self, token: &str) -> bool {
        if self.name.eq_ignore_ascii_case(token) {
            return true;
        }
        self.aliases
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(token))
    }

    fn matches_prefix(&self, token: &str) -> bool {
        let token = token.to_ascii_lowercase();
        self.name.to_ascii_lowercase().starts_with(&token)
            || self
                .aliases
                .iter()
                .any(|alias| alias.to_ascii_lowercase().starts_with(&token))
    }
}

impl CommandSpec {
    fn matches_exact(&self, token: &str) -> bool {
        if self.name.eq_ignore_ascii_case(token) {
            return true;
        }
        self.aliases
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(token))
    }

    fn matches_prefix(&self, token: &str) -> bool {
        let token = token.to_ascii_lowercase();
        self.name.to_ascii_lowercase().starts_with(&token)
            || self
                .aliases
                .iter()
                .any(|alias| alias.to_ascii_lowercase().starts_with(&token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_registry() -> CliRegistry {
        let mut registry = CliRegistry::new();
        registry
            .register_domain(DomainSpec {
                name: "alpha",
                aliases: &["a"],
                commands: vec![
                    CommandSpec {
                        name: "first",
                        aliases: &["f"],
                        usage: &["alpha first"],
                        parser: |_args| Err(CliError::usage("parser should not run")),
                    },
                    CommandSpec {
                        name: "second",
                        aliases: &["s"],
                        usage: &["alpha second"],
                        parser: |_args| Err(CliError::usage("parser should not run")),
                    },
                ],
            })
            .unwrap();
        registry
    }

    #[test]
    fn resolves_unambiguous_prefix() {
        let registry = build_test_registry();
        let command = registry.resolve_command(&vec!["al".into(), "fir".into()]);
        assert!(command.is_err());
        assert!(command.unwrap_err().to_string().contains("parser"));
    }

    #[test]
    fn detects_ambiguous_command_prefix() {
        let mut registry = CliRegistry::new();
        registry
            .register_domain(DomainSpec {
                name: "alpha",
                aliases: &[],
                commands: vec![
                    CommandSpec {
                        name: "list",
                        aliases: &[],
                        usage: &["alpha list"],
                        parser: |_args| Err(CliError::usage("no")),
                    },
                    CommandSpec {
                        name: "link",
                        aliases: &[],
                        usage: &["alpha link"],
                        parser: |_args| Err(CliError::usage("no")),
                    },
                ],
            })
            .unwrap();

        let err = registry
            .resolve_command(&vec!["alpha".into(), "li".into()])
            .unwrap_err();
        assert!(err.to_string().contains("Ambiguous"));
    }

    #[test]
    fn detects_unknown_domain() {
        let registry = build_test_registry();
        let err = registry
            .resolve_command(&vec!["unknown".into(), "first".into()])
            .unwrap_err();
        assert!(err.to_string().contains("Unknown domain"));
    }
}
