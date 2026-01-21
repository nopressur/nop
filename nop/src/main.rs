// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::rt::System;
use actix_web::{App, HttpServer, middleware::Logger, web};
use log::{Level, LevelFilter, info};
use std::io::Write;
use std::sync::Arc;

mod acme;
mod admin;
mod app_state;
mod bootstrap;
mod builtin;
mod config;
mod content;
mod headers;
mod iam;
mod login;
mod management;
mod public;
mod roles;
mod runtime_paths;
mod security;
mod templates;
mod tls;
mod util;
mod well_known;

use app_state::AppState;
use config::{AcmeChallenge, ServerProtocol, ServerRole, TlsMode, ValidatedConfig};
use futures_util::future::try_join_all;
use iam::UserServices;
use iam::middleware::JwtAuthMiddlewareFactory;
use public::page_meta_cache::PageMetaCache;
use public::shortcode::create_default_registry_with_config;
use runtime_paths::RuntimePaths;
use util::log_rotation::{
    DEFAULT_LOG_FILE_NAME, LogController, LogRotationSettings, LogRunMode, RotatingLogWriter,
};
use util::{CsrfTokenStore, CsrfValidationMiddlewareFactory, ReleaseTracker, WsTicketStore};

fn main() {
    let exit_code = run();
    std::process::exit(exit_code);
}

fn run() -> i32 {
    let parsed_args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("❌ Invalid command line arguments: {}", error);
            eprintln!("❌ Use -C <root> to set the runtime directory.");
            eprintln!("❌ Use -F to keep the server in the foreground.");
            return 1;
        }
    };

    if matches!(parsed_args.mode, RunMode::Help) {
        print!("{}", management::cli::help_text());
        return 0;
    }

    if let RunMode::Cli(tokens) = parsed_args.mode {
        return System::new()
            .block_on(async { management::cli::run_cli(&parsed_args.runtime_root, tokens).await });
    }

    let requested_daemon = matches!(parsed_args.mode, RunMode::Daemon);
    let pid_path = util::pid_file::pid_file_path(&parsed_args.runtime_root);
    let pid_status = match util::pid_file::cleanup_stale_pid_file(&pid_path) {
        Ok(status) => status,
        Err(error) => {
            eprintln!(
                "❌ Failed to inspect PID file {}: {}",
                pid_path.display(),
                error
            );
            return 1;
        }
    };

    if let util::pid_file::PidFileStatus::Running { pid } = pid_status {
        eprintln!("❌ Server is already running (pid {}).", pid);
        return 1;
    }

    let bootstrap = match bootstrap::bootstrap_runtime(&parsed_args.runtime_root) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("❌ Bootstrap error: {}", error);
            eprintln!("❌ Application cannot start with invalid configuration.");
            return 1;
        }
    };

    let mut daemon_requested = requested_daemon;
    if should_force_foreground(
        daemon_requested,
        bootstrap.created_config,
        bootstrap.created_users,
    ) {
        let mut created = Vec::new();
        if bootstrap.created_config {
            created.push("config.yaml");
        }
        if bootstrap.created_users {
            created.push("users.yaml");
        }
        eprintln!(
            "[bootstrap] created {}; staying in foreground for this run",
            created.join(" and ")
        );
        daemon_requested = false;
    }

    if daemon_requested && let Err(error) = util::daemonize_or_warn() {
        eprintln!("❌ Failed to daemonize: {}", error);
        return 1;
    }

    let mut pid_guard = None;
    if daemon_requested {
        match util::pid_file::create_pid_file(&pid_path) {
            Ok(guard) => pid_guard = Some(guard),
            Err(error) => {
                eprintln!("❌ Failed to create PID file: {}", error);
                return 1;
            }
        }
    }

    let result = System::new().block_on(run_server(bootstrap, daemon_requested));
    let exit_code = match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("❌ Server failed to start: {}", error);
            1
        }
    };

    drop(pid_guard);
    exit_code
}

async fn run_server(
    bootstrap: bootstrap::BootstrapResult,
    daemon_requested: bool,
) -> std::io::Result<()> {
    let validated_config = Arc::new(bootstrap.validated_config);
    let runtime_paths = bootstrap.runtime_paths;
    let log_run_mode = determine_log_run_mode(daemon_requested);
    let rotation_settings = LogRotationSettings {
        max_size_mb: validated_config.logging.rotation.max_size_mb,
        max_files: validated_config.logging.rotation.max_files,
    };

    // Parse log level from config
    let log_level = match validated_config.logging.level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let (log_controller, log_target) = if matches!(log_run_mode, LogRunMode::Daemon) {
        match RotatingLogWriter::new(
            runtime_paths.logs_dir.clone(),
            DEFAULT_LOG_FILE_NAME,
            rotation_settings,
        ) {
            Ok(writer) => (
                LogController::new(
                    log_run_mode,
                    runtime_paths.logs_dir.clone(),
                    DEFAULT_LOG_FILE_NAME,
                    rotation_settings,
                    Some(writer.clone()),
                ),
                env_logger::Target::Pipe(Box::new(writer)),
            ),
            Err(error) => {
                eprintln!("❌ Failed to initialize daemon log files: {}", error);
                return Err(error);
            }
        }
    } else {
        (
            LogController::new(
                log_run_mode,
                runtime_paths.logs_dir.clone(),
                DEFAULT_LOG_FILE_NAME,
                rotation_settings,
                None,
            ),
            env_logger::Target::Stdout,
        )
    };

    // Configure logging with a stable format
    let logger = env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .target(log_target)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {}: {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .build();

    util::init_logger(
        vec![("html5ever".to_string(), Level::Debug, Level::Trace)],
        logger,
    )
    .map_err(|error| {
        eprintln!("❌ Failed to initialize logger: {}", error);
        std::io::Error::other(error.to_string())
    })?;

    // Log startup information including canonical paths
    log_startup_info(&validated_config, &runtime_paths);
    if matches!(log_run_mode, LogRunMode::Daemon) {
        info!("Logs directory: {}", log_controller.log_dir().display());
        info!(
            "Log rotation: {} MB, {} files",
            rotation_settings.max_size_mb, rotation_settings.max_files
        );
    }

    let management_registry = match management::build_default_registry() {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("❌ Failed to initialize management registry: {}", error);
            return Err(std::io::Error::other(error.to_string()));
        }
    };
    // Initialize page roles cache
    let page_cache = Arc::new(PageMetaCache::new(
        runtime_paths.content_dir.clone(),
        runtime_paths.state_sys_dir.clone(),
        crate::content::reserved_paths::ReservedPaths::from_config(&validated_config),
    ));

    info!("✅ Page roles cache initialized successfully");

    // Initialize user services
    let mut user_services =
        match UserServices::new(&validated_config, runtime_paths.users_file.clone()) {
            Ok(services) => services,
            Err(error) => {
                eprintln!("❌ Failed to initialize user services: {}", error);
                eprintln!("❌ Application cannot start without user services.");
                return Err(std::io::Error::other(error.to_string()));
            }
        };

    info!("✅ User services initialized successfully");

    // Set the page cache on user services so it can access content roles
    user_services.set_page_cache(page_cache.clone());

    // Convert to Arc after setting the cache
    let user_services = Arc::new(user_services);

    let upload_registry = Arc::new(management::UploadRegistry::new());

    // Track the release identifier (Last Big Change) for cache busting headers.
    let release_tracker = Arc::new(ReleaseTracker::new());
    info!(
        "✅ Release tracker initialized with X-Release {}",
        release_tracker.current_hex()
    );

    let management_context =
        match management::ManagementContext::from_components_with_user_services_and_cache_and_logs(
            runtime_paths.root.clone(),
            validated_config.clone(),
            runtime_paths.clone(),
            Some(user_services.clone()),
            Some(page_cache.clone()),
            log_controller.clone(),
        ) {
            Ok(context) => context,
            Err(error) => {
                eprintln!("❌ Failed to initialize management context: {}", error);
                return Err(std::io::Error::other(error.to_string()));
            }
        };
    let management_context = management_context
        .with_upload_registry(upload_registry.clone())
        .with_release_tracker(release_tracker.clone());
    let management_bus = management::ManagementBus::start(management_registry, management_context);

    let _management_socket =
        match management::socket::ManagementSocket::start(&runtime_paths, management_bus.clone())
            .await
        {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("❌ Failed to initialize management socket: {}", error);
                return Err(std::io::Error::other(error.to_string()));
            }
        };

    let app_state = Arc::new(AppState::new(
        &validated_config.app.name,
        runtime_paths.clone(),
        management_bus,
        upload_registry,
    ));
    info!(
        "✅ App state initialized with app name: {}",
        validated_config.app.name
    );

    let well_known_registry = Arc::new(well_known::WellKnownRegistry::new());

    let acme_token_store = if validated_config
        .tls
        .as_ref()
        .map(|tls| {
            tls.mode == TlsMode::Acme
                && tls
                    .acme
                    .as_ref()
                    .map(|acme| acme.challenge == AcmeChallenge::Http01)
                    .unwrap_or(false)
        })
        .unwrap_or(false)
    {
        let store = acme::AcmeTokenStore::new();
        well_known::register_acme_http01_handler(&well_known_registry, store.clone());
        Some(store)
    } else {
        None
    };

    info!("✅ MIME types files initialized successfully");

    // Build the initial cache
    if let Err(e) = page_cache.rebuild_cache(true).await {
        eprintln!("❌ Failed to build initial page cache: {}", e);
        eprintln!("❌ Application cannot start without page cache.");
        return Err(std::io::Error::other(e.to_string()));
    }

    let admin_path = validated_config.admin.path.clone();
    let workers = validated_config.server.workers;

    let main_http_servers: Vec<_> = validated_config
        .servers_for_role(ServerRole::Main, Some(ServerProtocol::Http))
        .into_iter()
        .cloned()
        .collect();
    let main_https_servers: Vec<_> = validated_config
        .servers_for_role(ServerRole::Main, Some(ServerProtocol::Https))
        .into_iter()
        .cloned()
        .collect();
    let well_known_http_servers: Vec<_> = validated_config
        .servers_for_role(ServerRole::WellKnown, Some(ServerProtocol::Http))
        .into_iter()
        .cloned()
        .collect();

    // Create the shortcode registry once with config
    let shortcode_registry = Arc::new(create_default_registry_with_config(
        &validated_config,
        &release_tracker,
        app_state.templates.clone(),
    ));
    if let Err(e) = app_state
        .runtime_paths
        .ensure_shortcode_dirs(&shortcode_registry.registered_names())
    {
        eprintln!("❌ Failed to initialize shortcode state directories: {}", e);
        eprintln!("❌ Application cannot start without shortcode state directories.");
        return Err(std::io::Error::other(e.to_string()));
    }

    // Initialize CSRF token store with exempt endpoints
    let csrf_store = Arc::new(CsrfTokenStore::new(&validated_config));
    let ws_ticket_store = Arc::new(WsTicketStore::new());

    info!("✅ CSRF token store initialized successfully");
    info!("✅ WebSocket ticket store initialized successfully");

    let main_factory = {
        let admin_path = admin_path.clone();
        let config_for_app = validated_config.clone();
        let config_for_security = validated_config.clone();
        let config_for_admin = validated_config.clone();
        let config_for_login = validated_config.clone();
        let release_tracker_for_app = release_tracker.clone();
        let app_state_for_app = app_state.clone();
        let user_services = user_services.clone();
        let page_cache = page_cache.clone();
        let shortcode_registry = shortcode_registry.clone();
        let csrf_store = csrf_store.clone();
        let ws_ticket_store = ws_ticket_store.clone();

        move || {
            let admin_path_clone = admin_path.clone();
            let config_for_app = config_for_app.clone();
            let config_for_security = config_for_security.clone();
            let config_for_admin = config_for_admin.clone();
            let config_for_login = config_for_login.clone();
            let release_tracker_for_app = release_tracker_for_app.clone();
            let app_state_for_app = app_state_for_app.clone();

            App::new()
                .app_data(web::Data::from(config_for_app))
                .app_data(web::Data::from(app_state_for_app))
                .app_data(web::Data::from(user_services.clone()))
                .app_data(web::Data::from(page_cache.clone()))
                .app_data(web::Data::from(shortcode_registry.clone()))
                .app_data(web::Data::from(csrf_store.clone()))
                .app_data(web::Data::from(ws_ticket_store.clone()))
                .app_data(web::Data::from(release_tracker_for_app.clone()))
                .wrap(Logger::new(
                    r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#,
                ))
                .wrap(headers::Headers::new(
                    config_for_security,
                    page_cache.clone(),
                ))
                .wrap(CsrfValidationMiddlewareFactory)
                .wrap(JwtAuthMiddlewareFactory)
                .configure(move |cfg| admin::configure(cfg, &admin_path_clone, &config_for_admin))
                .configure(move |cfg| login::configure(cfg, &config_for_login))
                .configure(builtin::configure)
                .configure(public::configure)
        }
    };

    let well_known_factory = {
        let config_for_app = validated_config.clone();
        let config_for_security = validated_config.clone();
        let page_cache = page_cache.clone();
        let well_known_registry = well_known_registry.clone();

        move || {
            let config_for_app = config_for_app.clone();
            let config_for_security = config_for_security.clone();
            let well_known_registry = well_known_registry.clone();

            let app = App::new()
                .app_data(web::Data::from(config_for_app))
                .app_data(web::Data::from(well_known_registry))
                .wrap(Logger::new(
                    r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T"#,
                ))
                .wrap(headers::Headers::new(
                    config_for_security,
                    page_cache.clone(),
                ));

            app.configure(well_known::configure)
        }
    };

    let mut servers = Vec::new();

    if validated_config
        .tls
        .as_ref()
        .map(|tls| tls.mode == TlsMode::Acme)
        .unwrap_or(false)
    {
        if let Err(err) = acme::ensure_acme_certificate(
            &runtime_paths,
            &validated_config,
            acme_token_store.clone(),
            None,
        )
        .await
        {
            eprintln!("❌ Failed to obtain ACME certificate: {}", err);
            return Err(std::io::Error::other(err.to_string()));
        }

        acme::spawn_renewal_loop(
            runtime_paths.clone(),
            validated_config.clone(),
            acme_token_store,
        );
    }

    if !main_http_servers.is_empty() {
        let mut http_server = HttpServer::new(main_factory.clone()).workers(workers);
        for listener in &main_http_servers {
            http_server = http_server.bind(listener.address_tuple())?;
        }
        servers.push(http_server.run());
    }

    if !main_https_servers.is_empty() {
        let tls_config = tls::load_rustls_config(&app_state.runtime_paths, &validated_config)?;
        let mut https_server = HttpServer::new(main_factory.clone()).workers(workers);
        for listener in &main_https_servers {
            https_server =
                https_server.bind_rustls_0_23(listener.address_tuple(), tls_config.clone())?;
        }
        servers.push(https_server.run());
    }

    if !well_known_http_servers.is_empty() {
        let mut well_known_server = HttpServer::new(well_known_factory).workers(workers);
        for listener in &well_known_http_servers {
            well_known_server = well_known_server.bind(listener.address_tuple())?;
        }
        servers.push(well_known_server.run());
    }

    if servers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No servers configured to run",
        ));
    }

    try_join_all(servers).await.map(|_| ())
}

fn determine_log_run_mode(daemon_requested: bool) -> LogRunMode {
    if daemon_requested && cfg!(unix) {
        LogRunMode::Daemon
    } else {
        LogRunMode::Foreground
    }
}

fn should_force_foreground(
    daemon_requested: bool,
    created_config: bool,
    created_users: bool,
) -> bool {
    daemon_requested && (created_config || created_users)
}

fn log_startup_info(config: &ValidatedConfig, runtime_paths: &RuntimePaths) {
    info!("Starting {} - {}", config.app.name, config.app.description);
    info!("Workers: {}", config.server.workers);

    for server in &config.servers {
        let protocol = match server.protocol {
            config::ServerProtocol::Http => "http",
            config::ServerProtocol::Https => "https",
        };
        let role = match server.role {
            config::ServerRole::Main => "main",
            config::ServerRole::WellKnown => "well-known",
        };
        let name = server.name.as_deref().unwrap_or("listener");
        info!(
            "{} [{} {}] listening on {}:{}",
            name, role, protocol, server.host, server.port
        );
    }

    for server in config.servers_for_role(config::ServerRole::Main, None) {
        let protocol = match server.protocol {
            config::ServerProtocol::Http => "http",
            config::ServerProtocol::Https => "https",
        };
        info!(
            "Admin panel available at: {}://{}:{}{}",
            protocol, server.host, server.port, config.admin.path
        );
    }

    // Log canonical paths being used by the server
    info!(
        "Content directory (canonical): {}",
        runtime_paths.content_dir.display()
    );
    info!(
        "Themes directory (canonical): {}",
        runtime_paths.themes_dir.display()
    );
    info!(
        "State directory (canonical): {}",
        runtime_paths.state_dir.display()
    );
    info!(
        "State sys directory (canonical): {}",
        runtime_paths.state_sys_dir.display()
    );
    info!(
        "State sc directory (canonical): {}",
        runtime_paths.state_sc_dir.display()
    );
    info!("Config file: {}", runtime_paths.config_file.display());
    info!("Users file: {}", runtime_paths.users_file.display());
    info!("Runtime root: {}", runtime_paths.root.display());

    // Log working directory for context
    if let Ok(current_dir) = std::env::current_dir() {
        info!("Working directory: {}", current_dir.display());
    }
}

enum RunMode {
    Daemon,
    Foreground,
    Cli(Vec<String>),
    Help,
}

struct ParsedArgs {
    runtime_root: std::path::PathBuf,
    mode: RunMode,
}

fn parse_args() -> Result<ParsedArgs, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(args: I) -> Result<ParsedArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.iter().any(|arg| is_help_flag(arg)) {
        return Ok(ParsedArgs {
            runtime_root: std::path::PathBuf::from("."),
            mode: RunMode::Help,
        });
    }

    let mut args = args.into_iter();
    let mut runtime_root = std::path::PathBuf::from(".");
    let mut cli_tokens = Vec::new();
    let mut force_foreground = false;

    while let Some(arg) = args.next() {
        if arg == "--" {
            continue;
        } else if arg == "-C" {
            let value = args
                .next()
                .ok_or_else(|| "Missing value for -C".to_string())?;
            runtime_root = std::path::PathBuf::from(value);
        } else if arg == "-F" {
            force_foreground = true;
        } else {
            cli_tokens.push(arg);
        }
    }

    if cli_tokens.len() == 1 && cli_tokens[0].eq_ignore_ascii_case("help") {
        return Ok(ParsedArgs {
            runtime_root,
            mode: RunMode::Help,
        });
    }

    if !cli_tokens.is_empty() && force_foreground {
        return Err("-F can only be used when starting the server with no subcommands".to_string());
    }

    let runtime_root = make_runtime_root_absolute(runtime_root)?;

    let mode = if cli_tokens.is_empty() {
        if force_foreground {
            RunMode::Foreground
        } else {
            RunMode::Daemon
        }
    } else {
        RunMode::Cli(cli_tokens)
    };

    Ok(ParsedArgs { runtime_root, mode })
}

fn is_help_flag(arg: &str) -> bool {
    arg == "-h" || arg == "--help"
}

fn make_runtime_root_absolute(
    runtime_root: std::path::PathBuf,
) -> Result<std::path::PathBuf, String> {
    if runtime_root.is_absolute() {
        return Ok(runtime_root);
    }

    let current_dir = std::env::current_dir()
        .map_err(|error| format!("Failed to resolve current directory: {}", error))?;
    Ok(current_dir.join(runtime_root))
}

#[cfg(test)]
mod tests {
    use super::{
        LogRunMode, RunMode, determine_log_run_mode, parse_args_from, should_force_foreground,
    };

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_to_daemon() {
        let parsed = parse_args_from(Vec::new()).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Daemon));
        assert!(parsed.runtime_root.is_absolute());
    }

    #[test]
    fn parse_args_honors_foreground_flag() {
        let parsed = parse_args_from(args(&["-F"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Foreground));
    }

    #[test]
    fn parse_args_accepts_runtime_root_with_foreground() {
        let parsed = parse_args_from(args(&["-C", "runtime", "-F"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Foreground));
        assert!(parsed.runtime_root.ends_with("runtime"));
    }

    #[test]
    fn parse_args_accepts_runtime_root_with_foreground_reversed() {
        let parsed = parse_args_from(args(&["-F", "-C", "runtime"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Foreground));
        assert!(parsed.runtime_root.ends_with("runtime"));
    }

    #[test]
    fn parse_args_ignores_double_dash() {
        let parsed = parse_args_from(args(&["--", "-F", "-C", "runtime"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Foreground));
        assert!(parsed.runtime_root.ends_with("runtime"));
    }

    #[test]
    fn parse_args_rejects_foreground_with_subcommands() {
        match parse_args_from(args(&["-F", "system", "ping"])) {
            Err(error) => assert!(error.contains("-F")),
            Ok(_) => panic!("expected -F rejection"),
        }
    }

    #[test]
    fn parse_args_allows_subcommands() {
        let parsed = parse_args_from(args(&["system", "ping"])).expect("parse args");
        match parsed.mode {
            RunMode::Cli(tokens) => {
                assert_eq!(tokens, vec!["system".to_string(), "ping".to_string()]);
            }
            _ => panic!("expected cli mode"),
        }
    }

    #[test]
    fn parse_args_accepts_help_command() {
        let parsed = parse_args_from(args(&["help"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Help));
    }

    #[test]
    fn parse_args_accepts_help_flag() {
        let parsed = parse_args_from(args(&["--help", "system", "ping"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Help));
    }

    #[test]
    fn parse_args_accepts_help_with_runtime_root() {
        let parsed = parse_args_from(args(&["-C", "runtime", "help"])).expect("parse args");
        assert!(matches!(parsed.mode, RunMode::Help));
    }

    #[test]
    fn log_run_mode_defaults_to_foreground() {
        assert_eq!(determine_log_run_mode(false), LogRunMode::Foreground);
    }

    #[test]
    fn log_run_mode_daemon_flag_respects_platform() {
        let expected = if cfg!(unix) {
            LogRunMode::Daemon
        } else {
            LogRunMode::Foreground
        };
        assert_eq!(determine_log_run_mode(true), expected);
    }

    #[test]
    fn force_foreground_when_bootstrap_creates_config() {
        assert!(should_force_foreground(true, true, false));
    }

    #[test]
    fn force_foreground_when_bootstrap_creates_users() {
        assert!(should_force_foreground(true, false, true));
    }

    #[test]
    fn no_force_foreground_when_bootstrap_creates_nothing() {
        assert!(!should_force_foreground(true, false, false));
    }

    #[test]
    fn no_force_foreground_when_daemon_not_requested() {
        assert!(!should_force_foreground(false, true, true));
    }

    #[actix_web::test]
    async fn test_awc_tls_connectivity() {
        // Initialize the crypto provider for rustls - ignore errors if already set
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Test that awc can connect to HTTPS endpoints
        let client = awc::Client::default();
        let response = client.get("https://httpbin.org/get").send().await;

        match response {
            Ok(resp) => {
                assert!(
                    resp.status().is_success(),
                    "Should get successful response, got status: {}",
                    resp.status()
                );
            }
            Err(e) => {
                // This test requires network connectivity and may fail in CI environments
                // Just log the error and skip the test rather than failing
                eprintln!("TLS test skipped due to network error: {}", e);
                return;
            }
        }
    }
}
