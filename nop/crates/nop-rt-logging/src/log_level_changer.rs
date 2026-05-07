// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use env_logger::Logger;
use log::{Level, Log, Metadata, Record, SetLoggerError};

struct LevelModifierLogger {
    inner: Logger,
    rules: Vec<(String, Level, Level)>,
}

impl LevelModifierLogger {
    fn new(inner: Logger, rules: Vec<(String, Level, Level)>) -> Self {
        LevelModifierLogger { inner, rules }
    }

    fn get_new_level(&self, target: &str, original_level: Level) -> Level {
        for rule in &self.rules {
            if target.starts_with(&rule.0) && rule.1 == original_level {
                return rule.2;
            }
        }
        original_level
    }
}

impl Log for LevelModifierLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let new_level = self.get_new_level(metadata.target(), metadata.level());
        let new_metadata = Metadata::builder()
            .level(new_level)
            .target(metadata.target())
            .build();
        self.inner.enabled(&new_metadata)
    }

    fn log(&self, record: &Record) {
        let new_level = self.get_new_level(record.target(), record.level());
        let new_record = Record::builder()
            .level(new_level)
            .target(record.target())
            .args(*record.args())
            .module_path(record.module_path())
            .file(record.file())
            .line(record.line())
            .build();
        self.inner.log(&new_record);
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

pub fn init_logger(
    rules: Vec<(String, Level, Level)>,
    logger: Logger,
) -> Result<(), SetLoggerError> {
    let custom_logger = LevelModifierLogger::new(logger, rules);
    log::set_boxed_logger(Box::new(custom_logger))?;
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
}
