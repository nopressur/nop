// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::CliError;

pub(crate) fn parse_required_arg<'a>(
    args: &'a [String],
    label: &str,
) -> Result<(String, &'a [String]), CliError> {
    if args.is_empty() {
        return Err(CliError::usage(format!("Missing {}", label)));
    }
    Ok((args[0].clone(), &args[1..]))
}

pub(crate) fn next_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, CliError> {
    if *idx >= args.len() {
        return Err(CliError::usage(format!("{} requires a value", flag)));
    }
    let value = args[*idx].clone();
    *idx += 1;
    Ok(value)
}
