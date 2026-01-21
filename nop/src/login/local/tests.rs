// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::password::fetch_front_end_salt;
use super::profile::profile_password_salt;
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::iam::types::User;
use crate::management::{
    DomainActionKey, ManagementBus, ManagementContext, ManagementRegistry, ManagementRequest,
    ManagementResponse, PasswordSaltResponse, ResponsePayload, USER_ACTION_PASSWORD_SALT,
    USER_ACTION_PASSWORD_SALT_OK, USERS_DOMAIN_ID, UploadRegistry, WorkflowCounter,
    next_connection_id,
};
use crate::util::test_config::TestConfigBuilder;
use crate::util::test_fixtures::TestFixtureRoot;
use actix_web::{HttpMessage, http::StatusCode, test::TestRequest, web};
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

struct ObservedEvents {
    sender: mpsc::Sender<(u32, u32)>,
    receiver: mpsc::Receiver<(u32, u32)>,
}

impl ObservedEvents {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self { sender, receiver }
    }

    fn sender(&self) -> mpsc::Sender<(u32, u32)> {
        self.sender.clone()
    }

    fn recv_one(&self) -> Option<(u32, u32)> {
        self.receiver.recv_timeout(Duration::from_secs(1)).ok()
    }

    fn drain(&self) -> Vec<(u32, u32)> {
        self.receiver.try_iter().collect()
    }
}

fn build_test_app_state(
    observed: mpsc::Sender<(u32, u32)>,
) -> (AppState, ValidatedConfig, TestFixtureRoot) {
    let fixture = TestFixtureRoot::new_unique("login-salt-ids").expect("fixture");
    let runtime_paths = fixture.runtime_paths().expect("runtime paths");
    let config = TestConfigBuilder::new().build();
    let upload_registry = Arc::new(UploadRegistry::new());
    let context = ManagementContext::from_components(
        runtime_paths.root.clone(),
        Arc::new(config.clone()),
        runtime_paths.clone(),
    )
    .expect("context")
    .with_upload_registry(upload_registry.clone());
    let mut registry = ManagementRegistry::new();
    let observed_for_handler = observed.clone();
    registry
        .register_handler(
            DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT),
            Arc::new(move |request: ManagementRequest, _context| {
                let observed_for_handler = observed_for_handler.clone();
                Box::pin(async move {
                    let _ = observed_for_handler.send((request.connection_id, request.workflow_id));
                    Ok(ManagementResponse {
                        domain_id: USERS_DOMAIN_ID,
                        action_id: USER_ACTION_PASSWORD_SALT_OK,
                        workflow_id: request.workflow_id,
                        payload: ResponsePayload::UserPasswordSalt(PasswordSaltResponse {
                            change_token: "token".to_string(),
                            current_front_end_salt: "salt".to_string(),
                            next_front_end_salt: "salt-next".to_string(),
                            expires_in_seconds: 30,
                        }),
                    })
                })
            }),
        )
        .expect("handler");
    let bus = ManagementBus::start(registry, context);
    let app_state = AppState::new("Test App", runtime_paths, bus, upload_registry);
    (app_state, config, fixture)
}

#[actix_web::test]
async fn fetch_front_end_salt_passes_connection_and_workflow_ids() {
    let observed = ObservedEvents::new();
    let (app_state, config, _fixture) = build_test_app_state(observed.sender());
    let connection_id = next_connection_id();
    let workflow_id = WorkflowCounter::new().next_id().expect("workflow id");

    let salt = fetch_front_end_salt(
        "user@example.com",
        connection_id,
        workflow_id,
        &app_state,
        &config,
    )
    .await;

    assert_eq!(salt, "salt");
    let event = observed.recv_one().expect("observed");
    assert_eq!(event, (connection_id, workflow_id));
    assert!(observed.drain().is_empty());
}

#[actix_web::test]
async fn profile_password_salt_uses_generated_ids() {
    let observed = ObservedEvents::new();
    let (app_state, config, _fixture) = build_test_app_state(observed.sender());
    let user = User {
        email: "user@example.com".to_string(),
        name: "User".to_string(),
        password: None,
        legacy_password_hash: None,
        roles: vec!["admin".to_string()],
        password_version: 1,
    };
    let addr: SocketAddr = "127.0.0.1:1234".parse().expect("addr");
    let req = TestRequest::default().peer_addr(addr).to_http_request();
    req.extensions_mut().insert(user);

    let response = profile_password_salt(
        req,
        web::Data::new(config.clone()),
        web::Data::new(app_state),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let event = observed.recv_one().expect("observed");
    assert_ne!(event.0, 0);
    assert_eq!(event.1, 1);
    assert!(observed.drain().is_empty());
}
