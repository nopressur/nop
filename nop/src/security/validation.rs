// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use validator::ValidateEmail;

pub const MAX_EMAIL_CHARS: usize = 128;
pub const MAX_NAME_CHARS: usize = 256;

/// Validate user email input
pub fn validate_email_field(email: &str) -> Result<(), String> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err("Email is required".to_string());
    }
    if trimmed.chars().count() > MAX_EMAIL_CHARS {
        return Err(format!(
            "Email must be at most {} characters",
            MAX_EMAIL_CHARS
        ));
    }
    if !trimmed.validate_email() {
        return Err("Email format is invalid".to_string());
    }
    Ok(())
}

/// Validates a file name for creation (themes and pages)
/// Name must only contain lowercase alphanumeric characters (lowercase letters and numbers), dashes, and underscores
/// Must be between 1 and 128 characters
/// Must not contain dots or extensions
pub fn validate_new_file_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".to_string());
    }

    if name.len() > 128 {
        return Err("Name cannot exceed 128 characters".to_string());
    }

    if name.contains('.') {
        return Err(
            "Name cannot contain dots (extensions will be added automatically)".to_string(),
        );
    }

    // Check if name contains only allowed characters: lowercase letters, numbers, dashes, underscores
    for char in name.chars() {
        if !char.is_ascii_lowercase() && !char.is_ascii_digit() && char != '-' && char != '_' {
            return Err(
                "Name can only contain lowercase letters and numbers, dashes, and underscores"
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Validate and sanitize user names for display safety
/// Allows letters, numbers, spaces, apostrophes, hyphens, and periods
/// Replaces invalid characters with spaces and collapses multiple spaces
/// Trims leading/trailing spaces and enforces length limits
pub fn validate_and_sanitize_user_name(name: &str) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("Name cannot be empty".to_string());
    }

    // Replace invalid characters with spaces
    let sanitized = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' || c == '\'' || c == '-' || c == '.' {
                c
            } else {
                ' '
            }
        })
        .collect::<String>();

    // Collapse multiple consecutive spaces into single space
    let sanitized = sanitized
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Check length after sanitization
    let sanitized_len = sanitized.chars().count();
    if !(2..=MAX_NAME_CHARS).contains(&sanitized_len) {
        return Err(format!(
            "Name must be between 2 and {} characters",
            MAX_NAME_CHARS
        ));
    }

    Ok(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_new_file_name() {
        // Valid names
        assert!(validate_new_file_name("valid-name").is_ok());
        assert!(validate_new_file_name("valid_name").is_ok());
        assert!(validate_new_file_name("validname123").is_ok());
        assert!(validate_new_file_name("a").is_ok());

        // Invalid names
        assert!(validate_new_file_name("").is_err());
        assert!(validate_new_file_name("Invalid Name").is_err()); // uppercase
        assert!(validate_new_file_name("invalid.name").is_err()); // dots
        assert!(validate_new_file_name("invalid@name").is_err()); // special chars
        assert!(validate_new_file_name("invalid/name").is_err()); // slashes
        assert!(validate_new_file_name("invalid\\name").is_err()); // backslashes
        assert!(validate_new_file_name(&"a".repeat(129)).is_err()); // too long
    }

    #[test]
    fn test_directory_creation_restrictions() {
        // These should be rejected by directory creation logic (not this function, but tested here for clarity)
        // Directory names with paths should be invalid for single-level creation
        assert!(validate_new_file_name("dir1/dir2").is_err()); // nested path
        assert!(validate_new_file_name("dir1\\dir2").is_err()); // nested path with backslash

        // But single directory names should be valid
        assert!(validate_new_file_name("valid-dir").is_ok());
        assert!(validate_new_file_name("valid_dir").is_ok());
    }

    #[test]
    fn test_validate_email_field() {
        assert!(validate_email_field("user@example.com").is_ok());
        assert!(validate_email_field("").is_err());
        assert!(validate_email_field("not-an-email").is_err());
        let long_email = format!("{}@example.com", "a".repeat(MAX_EMAIL_CHARS));
        assert!(validate_email_field(&long_email).is_err());
    }

    #[test]
    fn test_validate_and_sanitize_user_name() {
        // Valid names
        assert_eq!(
            validate_and_sanitize_user_name("John Doe").unwrap(),
            "John Doe"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Mary O'Connor").unwrap(),
            "Mary O'Connor"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Jean-Pierre").unwrap(),
            "Jean-Pierre"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Dr. Smith").unwrap(),
            "Dr. Smith"
        );
        assert_eq!(
            validate_and_sanitize_user_name("  Alice  ").unwrap(),
            "Alice"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Renée Élodie").unwrap(),
            "Renée Élodie"
        );

        // Sanitization tests
        assert_eq!(
            validate_and_sanitize_user_name("John@Doe").unwrap(),
            "John Doe"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Mary&Bob").unwrap(),
            "Mary Bob"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Test<script>").unwrap(),
            "Test script"
        );
        assert_eq!(
            validate_and_sanitize_user_name("John   Multiple   Spaces").unwrap(),
            "John Multiple Spaces"
        );
        assert_eq!(
            validate_and_sanitize_user_name("User123").unwrap(),
            "User123"
        );

        // Edge cases
        assert!(validate_and_sanitize_user_name("").is_err());
        assert!(validate_and_sanitize_user_name("   ").is_err());
        assert!(validate_and_sanitize_user_name("A").is_err()); // Too short after trim
        assert!(validate_and_sanitize_user_name(&"A".repeat(257)).is_err()); // Too long

        // Special characters that should be preserved
        assert_eq!(
            validate_and_sanitize_user_name("O'Reilly-Jones").unwrap(),
            "O'Reilly-Jones"
        );
        assert_eq!(
            validate_and_sanitize_user_name("Prof. Dr. Smith").unwrap(),
            "Prof. Dr. Smith"
        );
    }
}
