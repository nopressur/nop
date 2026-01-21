# Filesystem Security

This document covers filesystem safety helpers in `nop/src/security/` that enforce canonical paths
and safe file creation. These guards are shared by public and admin code paths and return standard
public error pages; API routes should use their own response formats.

## Path Canonicalization and Root Enforcement

- `canonical_path_checks(file_path, content_dir)`:
  - Canonicalizes both the target path and the allowed root.
  - Ensures the file resides inside the root (via `strip_prefix`) and has no lingering suspicious
    segments.
  - Returns the canonical path on success or a 404/500 response on failure.
- `new_directory_canonical_path_checks(new_path, base_dir)`:
  - Designed for directories that might not exist yet (creation scenarios).
  - Rejects attempts to create the root directory or step outside the base directory.

## Safe File Naming

- `validate_new_file_path` and `validate_new_file_name` reinforce safe naming for uploads and page
  creation, blocking attempts to create unexpected paths or filenames.

## Error Handling

- Propagate filesystem validation errors using `shared::json_error_response` or 404s to avoid
  exposing internal paths.
- Keep detailed failure context in logs and return generic wire messages (see
  `docs/standards/coding.md`, “Error Handling”).

## Integration Notes

- Admin modules should rely on these validators before reading or writing any paths (for example,
  content edits, theme updates, and uploads).
- Content and tag management flows should use `validate_new_file_path` to prevent arbitrary file
  creation.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
