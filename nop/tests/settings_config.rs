// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_config::{Config, RuntimeSettings};
use nop_testing::test_fixtures::TestFixtureRoot;
use std::fs;

fn write_config(root: &TestFixtureRoot, settings: Option<&str>) {
    let settings_block = settings
        .map(|block| format!("\nsettings:\n{}\n", block))
        .unwrap_or_default();
    let config = format!(
        r#"server:
  host: "127.0.0.1"
  port: 8080
  workers: 1

admin:
  path: "/admin"

users:
  auth_method: "local"
  local:
    jwt:
      secret: "test-secret"

navigation:
  max_dropdown_items: 7

logging:
  level: "info"

security:
  max_violations: 2
  cooldown_seconds: 30
  use_forwarded_for: false
  hsts_enabled: false
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  hsts_preload: false

app:
  name: "Test"
  description: "Test"

upload:
  max_file_size_mb: 100
{}
"#,
        settings_block
    );
    fs::write(root.path().join("config.yaml"), config).expect("write config");
    fs::write(root.path().join("users.yaml"), "{}\n").expect("write users");
}

#[test]
fn loads_runtime_root_with_missing_settings() {
    let fixture = TestFixtureRoot::new_unique("settings-missing").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    write_config(&fixture, None);

    let config = Config::load_and_validate(fixture.path()).expect("config");
    assert_eq!(config.settings.name.as_deref(), Some("Test"));
    assert_eq!(config.settings.title, None);
    assert_eq!(config.settings.description.as_deref(), Some("Test"));
}

#[test]
fn loads_runtime_root_with_unset_settings() {
    let fixture = TestFixtureRoot::new_unique("settings-unset").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    write_config(&fixture, Some("  title: null"));

    let config = Config::load_and_validate(fixture.path()).expect("config");
    assert_eq!(config.settings.title, None);
}

#[test]
fn loads_runtime_root_with_configured_settings_and_seeds_runtime_snapshot() {
    let fixture = TestFixtureRoot::new_unique("settings-configured").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    write_config(&fixture, Some("  title: \"  Example Site  \""));

    let config = Config::load_and_validate(fixture.path()).expect("config");
    assert_eq!(config.settings.title, Some("Example Site".to_string()));

    let runtime_settings = RuntimeSettings::new(&config.settings);
    assert_eq!(
        runtime_settings.website_title(),
        Some("Example Site".to_string())
    );
}
