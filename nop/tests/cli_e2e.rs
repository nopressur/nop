// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop::config::{
    AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
    LoggingRotationConfig, NavigationConfig, OidcConfig, PasswordHashingConfig, RenderingConfig,
    SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
};
use nop::management::socket::ManagementSocket;
use nop::management::{AccessRule, ManagementBus, ManagementContext, build_default_registry};
use nop::runtime_paths::RuntimePaths;
use nop::util::test_fixtures::TestFixtureRoot;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct PasswordProviderFixture {
    front_end_salt: String,
    back_end_salt: String,
    stored_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PasswordRecordFixture {
    LegacyHash(String),
    Provider(PasswordProviderFixture),
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlUser {
    name: String,
    password: Option<PasswordRecordFixture>,
    roles: Vec<String>,
    #[serde(default)]
    password_version: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlTag {
    name: String,
    roles: Vec<String>,
    access_rule: Option<AccessRule>,
}

fn write_local_config(root: &Path) {
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            http_port: None,
            workers: 1,
        },
        admin: AdminConfig {
            path: "/admin".to_string(),
        },
        users: UsersConfig {
            auth_method: AuthMethod::Local,
            local: Some(LocalAuthConfig {
                jwt: JwtConfig {
                    secret: "test-secret".to_string(),
                    issuer: "nopressure".to_string(),
                    audience: "nopressure-users".to_string(),
                    expiration_hours: 12,
                    cookie_name: "nop_auth".to_string(),
                    disable_refresh: false,
                    refresh_threshold_percentage: 10,
                    refresh_threshold_hours: 24,
                },
                password: PasswordHashingConfig::default(),
            }),
            oidc: None,
        },
        navigation: NavigationConfig {
            max_dropdown_items: 7,
        },
        logging: LoggingConfig {
            level: "info".to_string(),
            rotation: LoggingRotationConfig::default(),
        },
        security: SecurityConfig {
            max_violations: 10,
            cooldown_seconds: 60,
            use_forwarded_for: false,
            login_sessions: nop::config::LoginSessionConfig::default(),
            hsts_enabled: false,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: false,
        },
        tls: None,
        app: AppConfig {
            name: "Test App".to_string(),
            description: "Test Description".to_string(),
        },
        upload: UploadConfig {
            max_file_size_mb: 100,
            allowed_extensions: vec!["md".to_string()],
        },
        streaming: StreamingConfig { enabled: false },
        shortcodes: ShortcodeConfig::default(),
        rendering: RenderingConfig::default(),
        dev_mode: None,
    };

    let content = serde_yaml::to_string(&config).expect("serialize config");
    std::fs::write(root.join("config.yaml"), content).expect("write config");
    std::fs::write(root.join("users.yaml"), "{}\n").expect("write users");
    std::fs::create_dir_all(root.join("state").join("sys")).expect("state sys dir");
    std::fs::write(
        root.join("state").join("sys").join("roles.yaml"),
        "- admin\n- editor\n",
    )
    .expect("write roles");
}

fn write_oidc_config(root: &Path) {
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            http_port: None,
            workers: 1,
        },
        admin: AdminConfig {
            path: "/admin".to_string(),
        },
        users: UsersConfig {
            auth_method: AuthMethod::Oidc,
            local: None,
            oidc: Some(OidcConfig {
                server_url: "https://id.example.com".to_string(),
                realm: "nop".to_string(),
                client_id: "nop-cli".to_string(),
                client_secret: None,
                redirect_uri: "http://localhost/callback".to_string(),
                scope: "openid email profile".to_string(),
                verify_ssl: true,
            }),
        },
        navigation: NavigationConfig {
            max_dropdown_items: 7,
        },
        logging: LoggingConfig {
            level: "info".to_string(),
            rotation: LoggingRotationConfig::default(),
        },
        security: SecurityConfig {
            max_violations: 10,
            cooldown_seconds: 60,
            use_forwarded_for: false,
            login_sessions: nop::config::LoginSessionConfig::default(),
            hsts_enabled: false,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: false,
        },
        tls: None,
        app: AppConfig {
            name: "Test App".to_string(),
            description: "Test Description".to_string(),
        },
        upload: UploadConfig {
            max_file_size_mb: 100,
            allowed_extensions: vec!["md".to_string()],
        },
        streaming: StreamingConfig { enabled: false },
        shortcodes: ShortcodeConfig::default(),
        rendering: RenderingConfig::default(),
        dev_mode: None,
    };

    let content = serde_yaml::to_string(&config).expect("serialize config");
    std::fs::write(root.join("config.yaml"), content).expect("write config");
}

fn write_users(root: &Path, users: HashMap<String, YamlUser>) {
    let content = serde_yaml::to_string(&users).expect("serialize users");
    std::fs::write(root.join("users.yaml"), content).expect("write users");
}

fn read_users(root: &Path) -> HashMap<String, YamlUser> {
    let content = std::fs::read_to_string(root.join("users.yaml")).expect("read users");
    serde_yaml::from_str(&content).unwrap_or_default()
}

fn read_tags(root: &Path) -> HashMap<String, YamlTag> {
    let path = root.join("state").join("sys").join("tags.yaml");
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(path).expect("read tags");
    serde_yaml::from_str(&content).unwrap_or_default()
}

fn read_roles(root: &Path) -> Vec<String> {
    let path = root.join("state").join("sys").join("roles.yaml");
    if !path.exists() {
        return Vec::new();
    }
    let content = std::fs::read_to_string(path).expect("read roles");
    serde_yaml::from_str(&content).unwrap_or_default()
}

fn run_cli(root: &Path, args: &[&str]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_nop");
    Command::new(binary)
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run nop cli")
}

fn run_cli_owned(root: &Path, args: &[String]) -> std::process::Output {
    let args_ref: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
    run_cli(root, &args_ref)
}

#[test]
fn cli_system_ping() {
    let fixture = TestFixtureRoot::new_unique("cli-ping").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(fixture.path(), &["system", "ping"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Version match"));
}

#[test]
fn cli_system_ping_uses_socket_when_available() {
    let temp = tempfile::Builder::new()
        .prefix("cli-sock")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let root = temp.path();
    write_local_config(root);

    let validated_config = Config::load_and_validate(root).expect("validate config");
    let runtime_paths = RuntimePaths::from_root(root, &validated_config).expect("runtime paths");
    let registry = build_default_registry().expect("registry");
    let context = ManagementContext::from_components(
        runtime_paths.root.clone(),
        Arc::new(validated_config),
        runtime_paths.clone(),
    )
    .expect("context");

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let _guard = runtime.enter();
    let bus = ManagementBus::start(registry, context);
    let _socket = runtime
        .block_on(async { ManagementSocket::start(&runtime_paths, bus.clone()).await })
        .expect("socket");

    std::fs::write(root.join("config.yaml"), "invalid: [").expect("break config");

    let output = run_cli(root, &["system", "ping"]);
    assert!(output.status.success());
}

#[test]
fn cli_tag_crud_roundtrip() {
    let fixture = TestFixtureRoot::new_unique("cli-tags").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "tag",
            "add",
            "news/alerts",
            "--name",
            "News Alerts",
            "--roles",
            "editor",
            "--access",
            "union",
        ],
    );
    assert!(output.status.success());

    let tags = read_tags(fixture.path());
    let stored = tags.get("news/alerts").expect("tag present");
    assert_eq!(stored.name, "News Alerts");
    assert_eq!(stored.roles, vec!["editor".to_string()]);
    assert_eq!(stored.access_rule, Some(AccessRule::Union));

    let output = run_cli(fixture.path(), &["tag", "list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("news/alerts"));

    let output = run_cli(fixture.path(), &["tag", "show", "news/alerts"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Access rule: union"));

    let output = run_cli(
        fixture.path(),
        &[
            "tag",
            "change",
            "news/alerts",
            "--name",
            "News Alerts Updated",
            "--clear-roles",
            "--access",
            "intersect",
        ],
    );
    assert!(output.status.success());

    let tags = read_tags(fixture.path());
    let stored = tags.get("news/alerts").expect("tag present");
    assert_eq!(stored.name, "News Alerts Updated");
    assert!(stored.roles.is_empty());
    assert_eq!(stored.access_rule, Some(AccessRule::Intersect));

    let output = run_cli(fixture.path(), &["tag", "delete", "news/alerts"]);
    assert!(output.status.success());
    let tags = read_tags(fixture.path());
    assert!(tags.get("news/alerts").is_none());
}

#[test]
fn cli_role_crud_roundtrip() {
    let fixture = TestFixtureRoot::new_unique("cli-roles").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(fixture.path(), &["role", "add", "contributor"]);
    assert!(output.status.success());

    let output = run_cli(fixture.path(), &["role", "list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("contributor"));

    let output = run_cli(fixture.path(), &["role", "show", "contributor"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Role: contributor"));

    let output = run_cli(
        fixture.path(),
        &["role", "change", "contributor", "--new-role", "author"],
    );
    assert!(output.status.success());

    let roles = read_roles(fixture.path());
    assert!(roles.contains(&"author".to_string()));
    assert!(!roles.contains(&"contributor".to_string()));

    let output = run_cli(fixture.path(), &["role", "delete", "author"]);
    assert!(output.status.success());

    let roles = read_roles(fixture.path());
    assert!(!roles.contains(&"author".to_string()));
    assert!(roles.contains(&"admin".to_string()));
}

#[test]
fn cli_user_lifecycle() {
    let fixture = TestFixtureRoot::new_unique("cli-user-lifecycle").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--roles",
            "admin",
            "--password",
            "secret",
        ],
    );
    assert!(output.status.success());
    let users = read_users(fixture.path());
    let user = users.get("user@example.com").expect("user added");
    assert_eq!(user.name, "User One");
    assert_eq!(user.roles, vec!["admin"]);
    let stored_hash = match user.password.as_ref().expect("password") {
        PasswordRecordFixture::Provider(block) => &block.stored_hash,
        PasswordRecordFixture::LegacyHash(_) => panic!("expected provider password block"),
    };
    assert_ne!(stored_hash, "secret");
    assert!(stored_hash.starts_with("$argon2id$"));
    let original_hash = stored_hash.to_string();

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "change",
            "user@example.com",
            "--name",
            "User Two",
            "--roles",
            "editor",
        ],
    );
    assert!(output.status.success());
    let users = read_users(fixture.path());
    let user = users.get("user@example.com").expect("user updated");
    assert_eq!(user.name, "User Two");
    assert_eq!(user.roles, vec!["editor"]);
    let stored_hash = match user.password.as_ref().expect("password") {
        PasswordRecordFixture::Provider(block) => &block.stored_hash,
        PasswordRecordFixture::LegacyHash(_) => panic!("expected provider password block"),
    };
    assert_eq!(stored_hash, &original_hash);

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "password",
            "user@example.com",
            "--password",
            "new-secret",
        ],
    );
    assert!(output.status.success());
    let users = read_users(fixture.path());
    let user = users.get("user@example.com").expect("user updated");
    let stored_hash = match user.password.as_ref().expect("password") {
        PasswordRecordFixture::Provider(block) => &block.stored_hash,
        PasswordRecordFixture::LegacyHash(_) => panic!("expected provider password block"),
    };
    assert_ne!(stored_hash, &original_hash);
    assert!(stored_hash.starts_with("$argon2id$"));

    let output = run_cli(fixture.path(), &["user", "delete", "user@example.com"]);
    assert!(output.status.success());
    let users = read_users(fixture.path());
    assert!(!users.contains_key("user@example.com"));
}

#[test]
fn cli_user_list_and_show() {
    let fixture = TestFixtureRoot::new_unique("cli-user-list-show").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--roles",
            "admin",
            "--password",
            "secret",
        ],
    );
    assert!(output.status.success());

    let output = run_cli(fixture.path(), &["user", "list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Email"));
    assert!(stdout.contains("Name"));
    assert!(stdout.contains("user@example.com"));
    assert!(stdout.contains("User One"));

    let output = run_cli(fixture.path(), &["user", "show", "user@example.com"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Email: user@example.com"));
    assert!(stdout.contains("Name: User One"));
    assert!(stdout.contains("Roles: admin"));
}

#[test]
fn cli_user_change_clear_roles() {
    let fixture = TestFixtureRoot::new_unique("cli-user-clear-roles").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--roles",
            "admin",
            "--password",
            "secret",
        ],
    );
    assert!(output.status.success());

    let output = run_cli(
        fixture.path(),
        &["user", "change", "user@example.com", "--clear-roles"],
    );
    assert!(output.status.success());

    let users = read_users(fixture.path());
    let user = users.get("user@example.com").expect("user updated");
    assert!(user.roles.is_empty());
}

#[test]
fn cli_user_add_rejects_existing_user() {
    let fixture = TestFixtureRoot::new_unique("cli-user-existing").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let mut users = HashMap::new();
    users.insert(
        "user@example.com".to_string(),
        YamlUser {
            name: "Existing".to_string(),
            password: Some(PasswordRecordFixture::LegacyHash("hash".to_string())),
            roles: vec!["admin".to_string()],
            password_version: Some(1),
        },
    );
    write_users(fixture.path(), users);

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--roles",
            "admin",
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.to_lowercase().contains("already exists"));
}

#[test]
fn cli_user_change_requires_flags() {
    let fixture = TestFixtureRoot::new_unique("cli-user-change-flags").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(fixture.path(), &["user", "change", "user@example.com"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires --name, --roles, or --clear-roles"));
}

#[test]
fn cli_user_size_limits() {
    let fixture = TestFixtureRoot::new_unique("cli-user-limits").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let long_username = "a".repeat(129);
    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            &long_username,
            "--name",
            "User One",
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Email must be at most 128"));

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user2@example.com",
            "--name",
            "a",
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Name must be between 2 and 256"));

    let long_name = "n".repeat(257);
    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user2@example.com",
            "--name",
            &long_name,
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Name must be between 2 and 256"));

    let mut args = vec![
        "user".to_string(),
        "add".to_string(),
        "user3@example.com".to_string(),
        "--name".to_string(),
        "User Three".to_string(),
        "--password".to_string(),
        "secret".to_string(),
    ];
    for idx in 0..65 {
        args.push("--roles".to_string());
        args.push(format!("role{}", idx));
    }
    let output = run_cli_owned(fixture.path(), &args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Roles must be at most 64"));

    let long_role = "r".repeat(65);
    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user4@example.com",
            "--name",
            "User Four",
            "--roles",
            &long_role,
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Role must be at most 64"));

    let long_password = "p".repeat(1025);
    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "password",
            "user@example.com",
            "--password",
            &long_password,
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Password must be at most 1024"));
}

#[test]
fn cli_user_rejects_oidc() {
    let fixture = TestFixtureRoot::new_unique("cli-user-oidc").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_oidc_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--password",
            "secret",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires local authentication"));
}

#[test]
fn cli_user_rejects_empty_password() {
    let fixture = TestFixtureRoot::new_unique("cli-user-empty-password").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user@example.com",
            "--name",
            "User One",
            "--password",
            "",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Password is required"));
}

#[test]
fn cli_user_allows_special_characters() {
    let fixture = TestFixtureRoot::new_unique("cli-user-special-chars").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let output = run_cli(fixture.path(), &["role", "add", "role_admin"]);
    assert!(output.status.success());

    let output = run_cli(
        fixture.path(),
        &[
            "user",
            "add",
            "user+test@example.com",
            "--name",
            "User One",
            "--roles",
            "role_admin",
            "--password",
            "secret",
        ],
    );
    assert!(output.status.success());

    let users = read_users(fixture.path());
    let user = users.get("user+test@example.com").expect("user exists");
    assert_eq!(user.roles, vec!["role_admin".to_string()]);
}

#[test]
fn cli_system_ping_concurrent() {
    let fixture = TestFixtureRoot::new_unique("cli-ping-concurrent").unwrap();
    fixture.init_runtime_layout().unwrap();
    write_local_config(fixture.path());

    let root = fixture.path().to_path_buf();
    let mut handles = Vec::new();
    for _ in 0..4 {
        let root = root.clone();
        handles.push(std::thread::spawn(move || {
            run_cli(&root, &["system", "ping"])
        }));
    }

    for handle in handles {
        let output = handle.join().expect("join");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Version"));
    }
}
