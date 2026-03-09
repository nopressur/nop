// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

const MIN_PASSWORD_CHARS: usize = 8;

pub const PASSWORD_COMPLEXITY_MESSAGE_UNCASED: &str =
    "Password needs to be at least 8 long with letters and numbers.";
pub const PASSWORD_COMPLEXITY_MESSAGE_CASED: &str =
    "Password needs to be at least 8 long with lowercase and uppercase letters and numbers.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordComplexityCase {
    Uncased,
    Cased,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordComplexityReport {
    pub valid: bool,
    pub case_kind: PasswordComplexityCase,
}

pub fn evaluate_password_complexity(password: &str) -> PasswordComplexityReport {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_letter = false;
    let mut has_uncased = false;
    let mut has_number = false;
    let mut length = 0usize;

    for ch in password.chars() {
        length += 1;
        let is_lower = ch.is_lowercase();
        let is_upper = ch.is_uppercase();
        if is_lower {
            has_lower = true;
            has_letter = true;
        } else if is_upper {
            has_upper = true;
            has_letter = true;
        } else if ch.is_alphabetic() {
            has_letter = true;
            has_uncased = true;
        }
        if ch.to_digit(10).is_some() {
            has_number = true;
        }
    }

    let case_kind = if has_lower || has_upper {
        if has_uncased {
            PasswordComplexityCase::Mixed
        } else {
            PasswordComplexityCase::Cased
        }
    } else {
        PasswordComplexityCase::Uncased
    };

    let length_ok = length >= MIN_PASSWORD_CHARS;
    let number_ok = has_number;
    let letter_ok = has_letter;
    let case_ok = match case_kind {
        PasswordComplexityCase::Cased => has_lower && has_upper,
        PasswordComplexityCase::Mixed | PasswordComplexityCase::Uncased => true,
    };

    PasswordComplexityReport {
        valid: length_ok && number_ok && letter_ok && case_ok,
        case_kind,
    }
}

pub fn password_complexity_message(case_kind: PasswordComplexityCase) -> &'static str {
    match case_kind {
        PasswordComplexityCase::Cased => PASSWORD_COMPLEXITY_MESSAGE_CASED,
        PasswordComplexityCase::Mixed | PasswordComplexityCase::Uncased => {
            PASSWORD_COMPLEXITY_MESSAGE_UNCASED
        }
    }
}

pub fn validate_password_complexity(password: &str) -> Result<(), String> {
    let report = evaluate_password_complexity(password);
    if report.valid {
        Ok(())
    } else {
        Err(password_complexity_message(report.case_kind).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cased_password_with_number() {
        let report = evaluate_password_complexity("Abcdefg1");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Cased);
    }

    #[test]
    fn rejects_cased_password_missing_lowercase() {
        let report = evaluate_password_complexity("ABCDEFG1");
        assert!(!report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Cased);
    }

    #[test]
    fn accepts_uncased_password_with_number() {
        let report = evaluate_password_complexity("漢字漢字漢字12");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Uncased);
    }

    #[test]
    fn accepts_mixed_password_without_both_cases() {
        let report = evaluate_password_complexity("A漢字1234B");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Mixed);
    }
}
