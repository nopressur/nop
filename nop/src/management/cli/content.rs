// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::cli::parse_utils::{next_value, parse_required_arg};
use crate::management::cli::{CliError, CommandSpec, DomainSpec};
use crate::management::cli_helper::{CliCommand, ContentStreamTarget};
use crate::management::content::{
    CONTENT_ACTION_DELETE_OK, CONTENT_ACTION_READ_OK, CONTENT_ACTION_UPDATE_OK,
    CONTENT_ACTION_UPLOAD_OK, CONTENT_DOMAIN_ID, ContentCommand, ContentDeleteRequest,
    ContentReadRequest, ContentUpdateRequest, ContentUploadRequest,
};
use crate::management::core::ManagementCommand;
use crate::management::registry::DomainActionKey;
use crate::util::detect_mime_type;
use chrono::Local;
use mime_guess::get_mime_extensions_str;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn domain() -> DomainSpec {
    DomainSpec {
        name: "content",
        aliases: &["c"],
        commands: vec![
            CommandSpec {
                name: "store",
                aliases: &[],
                usage: &[
                    "content store [--alias <alias>] [--title <title>] [--tag <tag> ...] [--theme <theme>] [--nav-title <title>] [--nav-parent <id>] [--nav-order <order>] <file|->",
                ],
                parser: parse_store,
            },
            CommandSpec {
                name: "change",
                aliases: &[],
                usage: &[
                    "content change <id> [--alias <alias>] [--title <title>] [--tag <tag> ...] [--clear-tags] [--theme <theme>] [--nav-title <title>] [--nav-parent <id>] [--nav-order <order>] [<file|->]",
                ],
                parser: parse_change,
            },
            CommandSpec {
                name: "stream",
                aliases: &[],
                usage: &["content stream <id> <file|->"],
                parser: parse_stream,
            },
            CommandSpec {
                name: "delete",
                aliases: &[],
                usage: &["content delete <id>"],
                parser: parse_delete,
            },
        ],
    }
}

fn parse_store(args: &[String]) -> Result<CliCommand, CliError> {
    let mut alias: Option<String> = None;
    let mut title: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut theme: Option<String> = None;
    let mut nav_title: Option<String> = None;
    let mut nav_parent_id: Option<String> = None;
    let mut nav_order: Option<i32> = None;
    let mut file_arg: Option<String> = None;

    let mut idx = 0;
    while idx < args.len() {
        let token = &args[idx];
        if token.starts_with("--") {
            match token.as_str() {
                "--alias" => {
                    if alias.is_some() {
                        return Err(CliError::usage("Duplicate --alias"));
                    }
                    idx += 1;
                    alias = Some(next_value(args, &mut idx, "--alias")?);
                }
                "--title" => {
                    if title.is_some() {
                        return Err(CliError::usage("Duplicate --title"));
                    }
                    idx += 1;
                    title = Some(next_value(args, &mut idx, "--title")?);
                }
                "--tag" => {
                    idx += 1;
                    tags.push(next_value(args, &mut idx, "--tag")?);
                }
                "--theme" => {
                    if theme.is_some() {
                        return Err(CliError::usage("Duplicate --theme"));
                    }
                    idx += 1;
                    theme = Some(next_value(args, &mut idx, "--theme")?);
                }
                "--nav-title" => {
                    if nav_title.is_some() {
                        return Err(CliError::usage("Duplicate --nav-title"));
                    }
                    idx += 1;
                    nav_title = Some(next_value(args, &mut idx, "--nav-title")?);
                }
                "--nav-parent" => {
                    if nav_parent_id.is_some() {
                        return Err(CliError::usage("Duplicate --nav-parent"));
                    }
                    idx += 1;
                    nav_parent_id = Some(next_value(args, &mut idx, "--nav-parent")?);
                }
                "--nav-order" => {
                    if nav_order.is_some() {
                        return Err(CliError::usage("Duplicate --nav-order"));
                    }
                    idx += 1;
                    let value = next_value(args, &mut idx, "--nav-order")?;
                    nav_order = Some(parse_i32(&value, "--nav-order")?);
                }
                flag => {
                    return Err(CliError::usage(format!(
                        "Unknown flag for content store: {}",
                        flag
                    )));
                }
            }
        } else {
            if file_arg.is_some() {
                return Err(CliError::usage(
                    "content store takes a single file argument",
                ));
            }
            file_arg = Some(token.clone());
            idx += 1;
            if idx < args.len() {
                return Err(CliError::usage("content store file argument must be last"));
            }
            break;
        }
    }

    let file_arg = file_arg.ok_or_else(|| CliError::usage("content store requires a file"))?;
    let markdown_hint =
        theme.is_some() || nav_title.is_some() || nav_parent_id.is_some() || nav_order.is_some();
    let (content, original_filename, mime) = read_store_payload(&file_arg, markdown_hint)?;
    let is_markdown = mime.eq_ignore_ascii_case("text/markdown");

    if !is_markdown
        && (theme.is_some()
            || nav_title.is_some()
            || nav_parent_id.is_some()
            || nav_order.is_some())
    {
        return Err(CliError::usage(
            "content store nav/theme flags require markdown content",
        ));
    }
    if nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return Err(CliError::usage(
            "content store --nav-parent/--nav-order require --nav-title",
        ));
    }
    if is_markdown {
        let title_value = title.as_deref().unwrap_or("").trim();
        if title_value.is_empty() {
            return Err(CliError::usage(
                "content store requires --title for markdown content",
            ));
        }
    }

    Ok(CliCommand {
        command: ManagementCommand::Content(ContentCommand::Upload(ContentUploadRequest {
            alias,
            title,
            mime,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename: Some(original_filename),
            theme,
            content,
        })),
        success_actions: vec![DomainActionKey::new(
            CONTENT_DOMAIN_ID,
            CONTENT_ACTION_UPLOAD_OK,
        )],
        stream_target: None,
    })
}

fn parse_change(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "content id")?;
    let mut new_alias: Option<String> = None;
    let mut title: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut tags_set = false;
    let mut clear_tags = false;
    let mut theme: Option<String> = None;
    let mut nav_title: Option<String> = None;
    let mut nav_parent_id: Option<String> = None;
    let mut nav_order: Option<i32> = None;
    let mut file_arg: Option<String> = None;

    let mut idx = 0;
    while idx < rest.len() {
        let token = &rest[idx];
        if token.starts_with("--") {
            match token.as_str() {
                "--alias" => {
                    if new_alias.is_some() {
                        return Err(CliError::usage("Duplicate --alias"));
                    }
                    idx += 1;
                    new_alias = Some(next_value(rest, &mut idx, "--alias")?);
                }
                "--title" => {
                    if title.is_some() {
                        return Err(CliError::usage("Duplicate --title"));
                    }
                    idx += 1;
                    title = Some(next_value(rest, &mut idx, "--title")?);
                }
                "--tag" => {
                    if clear_tags {
                        return Err(CliError::usage("--tag cannot be used with --clear-tags"));
                    }
                    idx += 1;
                    tags.push(next_value(rest, &mut idx, "--tag")?);
                    tags_set = true;
                }
                "--clear-tags" => {
                    if clear_tags {
                        return Err(CliError::usage("Duplicate --clear-tags"));
                    }
                    if tags_set {
                        return Err(CliError::usage("--clear-tags cannot be used with --tag"));
                    }
                    clear_tags = true;
                    idx += 1;
                }
                "--theme" => {
                    if theme.is_some() {
                        return Err(CliError::usage("Duplicate --theme"));
                    }
                    idx += 1;
                    theme = Some(next_value(rest, &mut idx, "--theme")?);
                }
                "--nav-title" => {
                    if nav_title.is_some() {
                        return Err(CliError::usage("Duplicate --nav-title"));
                    }
                    idx += 1;
                    nav_title = Some(next_value(rest, &mut idx, "--nav-title")?);
                }
                "--nav-parent" => {
                    if nav_parent_id.is_some() {
                        return Err(CliError::usage("Duplicate --nav-parent"));
                    }
                    idx += 1;
                    nav_parent_id = Some(next_value(rest, &mut idx, "--nav-parent")?);
                }
                "--nav-order" => {
                    if nav_order.is_some() {
                        return Err(CliError::usage("Duplicate --nav-order"));
                    }
                    idx += 1;
                    let value = next_value(rest, &mut idx, "--nav-order")?;
                    nav_order = Some(parse_i32(&value, "--nav-order")?);
                }
                flag => {
                    return Err(CliError::usage(format!(
                        "Unknown flag for content change: {}",
                        flag
                    )));
                }
            }
        } else {
            if file_arg.is_some() {
                return Err(CliError::usage(
                    "content change takes a single file argument",
                ));
            }
            file_arg = Some(token.clone());
            idx += 1;
            if idx < rest.len() {
                return Err(CliError::usage("content change file argument must be last"));
            }
            break;
        }
    }

    let tags = if clear_tags {
        Some(Vec::new())
    } else if tags_set {
        Some(tags)
    } else {
        None
    };

    let content = match file_arg.as_deref() {
        Some(path) => Some(read_markdown_content(path)?),
        None => None,
    };

    if new_alias.is_none()
        && title.is_none()
        && tags.is_none()
        && theme.is_none()
        && nav_title.is_none()
        && nav_parent_id.is_none()
        && nav_order.is_none()
        && content.is_none()
    {
        return Err(CliError::usage(
            "content change requires at least one field or file",
        ));
    }

    Ok(CliCommand {
        command: ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
            id,
            new_alias,
            title,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            theme,
            content,
        })),
        success_actions: vec![DomainActionKey::new(
            CONTENT_DOMAIN_ID,
            CONTENT_ACTION_UPDATE_OK,
        )],
        stream_target: None,
    })
}

fn parse_stream(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "content id")?;
    if rest.len() != 1 {
        return Err(CliError::usage("content stream requires <id> <file|->"));
    }
    let file_arg = &rest[0];
    if file_arg.starts_with("--") {
        return Err(CliError::usage("content stream requires <id> <file|->"));
    }

    let stream_target = if file_arg == "-" {
        ContentStreamTarget::Stdout
    } else {
        let path = PathBuf::from(file_arg);
        ensure_extension(&path, "content stream")?;
        ContentStreamTarget::File(path)
    };

    Ok(CliCommand {
        command: ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
            id,
            stream_content: Some(true),
        })),
        success_actions: vec![DomainActionKey::new(
            CONTENT_DOMAIN_ID,
            CONTENT_ACTION_READ_OK,
        )],
        stream_target: Some(stream_target),
    })
}

fn parse_delete(args: &[String]) -> Result<CliCommand, CliError> {
    let (id, rest) = parse_required_arg(args, "content id")?;
    if !rest.is_empty() {
        return Err(CliError::usage("content delete takes only <id>"));
    }

    Ok(CliCommand {
        command: ManagementCommand::Content(ContentCommand::Delete(ContentDeleteRequest { id })),
        success_actions: vec![DomainActionKey::new(
            CONTENT_DOMAIN_ID,
            CONTENT_ACTION_DELETE_OK,
        )],
        stream_target: None,
    })
}

fn parse_i32(value: &str, flag: &str) -> Result<i32, CliError> {
    value
        .parse::<i32>()
        .map_err(|_| CliError::usage(format!("{} must be a number", flag)))
}

fn ensure_extension(path: &Path, label: &str) -> Result<(), CliError> {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if extension.is_empty() {
        return Err(CliError::usage(format!(
            "{} file name must include an extension",
            label
        )));
    }
    Ok(())
}

fn read_store_payload(
    file_arg: &str,
    markdown_hint: bool,
) -> Result<(Vec<u8>, String, String), CliError> {
    if file_arg == "-" {
        let content = read_stdin_bytes("content store")?;
        if content.is_empty() {
            return Err(CliError::usage("content store requires non-empty input"));
        }
        let mime = if markdown_hint {
            "text/markdown".to_string()
        } else {
            detect_mime_type(Path::new("stdin"), &content)
        };
        let filename = generate_filename(&mime);
        return Ok((content, filename, mime));
    }

    let path = Path::new(file_arg);
    ensure_extension(path, "content store")?;
    let content = std::fs::read(path)
        .map_err(|err| CliError::usage(format!("Failed to read {}: {}", file_arg, err)))?;
    if content.is_empty() {
        return Err(CliError::usage("content store requires non-empty input"));
    }
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .ok_or_else(|| CliError::usage("content store requires a file name"))?;
    let mime = if markdown_hint || is_markdown_extension(path) {
        "text/markdown".to_string()
    } else {
        detect_mime_type(path, &content)
    };
    Ok((content, filename, mime))
}

fn read_markdown_content(file_arg: &str) -> Result<String, CliError> {
    let content = if file_arg == "-" {
        read_stdin_bytes("content change")?
    } else {
        let path = Path::new(file_arg);
        ensure_extension(path, "content change")?;
        if !is_markdown_extension(path) {
            return Err(CliError::usage(
                "content change requires a markdown (.md/.markdown) file",
            ));
        }
        std::fs::read(path)
            .map_err(|err| CliError::usage(format!("Failed to read {}: {}", file_arg, err)))?
    };

    if content.is_empty() {
        return Err(CliError::usage("content change requires non-empty input"));
    }

    String::from_utf8(content).map_err(|_| CliError::usage("Markdown content must be valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_file(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    fn parse_store_requires_title_for_markdown() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_file(&temp, "note.md", b"Hello\n");
        let args = vec!["--alias", "docs/note", path.to_str().unwrap()]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();

        let err = parse_store(&args).expect_err("expected error");
        assert!(err.to_string().contains("requires --title"));
    }

    #[test]
    fn parse_store_allows_binary_without_title() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_file(&temp, "blob.bin", b"\x00\x01\x02");
        let args = vec![path.to_str().unwrap()]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();

        let command = parse_store(&args).expect("parse store");
        match command.command {
            ManagementCommand::Content(ContentCommand::Upload(_)) => {}
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn read_markdown_content_rejects_non_markdown_extension() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_file(&temp, "note.txt", b"Hello\n");
        let err = read_markdown_content(path.to_str().unwrap()).expect_err("expected error");
        assert!(err.to_string().contains("markdown"));
    }

    #[test]
    fn read_markdown_content_rejects_empty_file() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = write_temp_file(&temp, "empty.md", b"");
        let err = read_markdown_content(path.to_str().unwrap()).expect_err("expected error");
        assert!(err.to_string().contains("non-empty"));
    }
}

fn read_stdin_bytes(label: &str) -> Result<Vec<u8>, CliError> {
    let mut buffer = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(|err| CliError::usage(format!("Failed to read {}: {}", label, err)))?;
    Ok(buffer)
}

fn is_markdown_extension(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => matches!(ext.to_ascii_lowercase().as_str(), "md" | "markdown"),
        None => false,
    }
}

fn generate_filename(mime: &str) -> String {
    let ext = extension_for_mime(mime);
    let timestamp = Local::now().format("%Y-%m-%d-%H-%M-%S");
    format!("cli-store-{}.{}", timestamp, ext)
}

fn extension_for_mime(mime: &str) -> String {
    if mime.eq_ignore_ascii_case("application/octet-stream") {
        return "bin".to_string();
    }
    if let Some(exts) = get_mime_extensions_str(mime)
        && let Some(ext) = exts.first()
    {
        return ext.to_string();
    }
    "bin".to_string()
}
