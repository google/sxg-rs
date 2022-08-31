// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{Account, OngoingOrder};
use crate::crypto::CertificateChain;
use crate::fetcher::Fetcher;
use crate::runtime::Runtime;
use crate::signature::Signer;
use crate::utils::console_log;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub const ACME_STORAGE_KEY: &str = "ACME";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcmeStorageData {
    pub certificates: Vec<String>,
    pub task: Option<Task>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Task {
    order: OngoingOrder,
    pub schedule: Schedule,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Schedule {
    pub updated_at: SystemTime,
    pub wait_time: Duration,
    next_step: TaskStep,
}

impl Schedule {
    fn double_wait(&mut self, now: SystemTime) {
        self.updated_at = now;
        self.wait_time = std::cmp::min(self.wait_time * 2, MAX_SLEEP);
    }
    fn reset(&mut self, now: SystemTime, next_step: TaskStep) {
        self.updated_at = now;
        self.wait_time = MIN_SLEEP;
        self.next_step = next_step;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum TaskStep {
    RequestChallengeValidation,
    CheckChallengeFinished,
    FinalizeSigningRequest,
    DownloadCertificate,
}

/// Reads and returns current `AcmeStorageData` from runtime storage.
/// Throws an error if unable to read.
/// Returns the default value, which contains no certificates or pending orders,
/// if the storage returns null or if the storage returns a string that can't
/// be parsed.
/// We don't throw parsing error, because the parsing errors are likely to happen
/// when a new version of `sxg-rs` changes the definition of `AcmeStorageData`.
pub async fn read_current_state(runtime: &Runtime) -> Result<AcmeStorageData> {
    match runtime.storage.read(ACME_STORAGE_KEY).await {
        Ok(Some(value)) => match serde_json::from_str(&value) {
            Ok(state) => Ok(state),
            Err(e) => {
                console_log(&format!("Failed to parse ACME state in storage. {:?}", e));
                Ok(Default::default())
            }
        },
        Ok(None) => {
            console_log("No ACME state in storage");
            Ok(Default::default())
        }
        Err(e) => Err(e.context("Failed to read ACME state in storage")),
    }
}

async fn write_state(runtime: &Runtime, state: &AcmeStorageData) -> Result<()> {
    let value = serde_json::to_string(state)?;
    runtime.storage.write(ACME_STORAGE_KEY, &value).await?;
    Ok(())
}

const MIN_SLEEP: Duration = Duration::from_secs(59);
const MAX_SLEEP: Duration = Duration::from_secs(600);

// Parses the certificate chain PEM, and returns the expiration time of the first certificate.
fn get_certificate_expiration_time(certificate_pem: &str) -> Result<SystemTime> {
    let certificate_chain = CertificateChain::from_pem_files(&[certificate_pem])?;
    let x509_cert = x509_parser::parse_x509_certificate(&certificate_chain.end_entity.der)?;
    let timestamp = x509_cert.1.tbs_certificate.validity.not_after.timestamp();
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
}

async fn update_state_impl(
    account: &Account,
    state: &mut AcmeStorageData,
    now: SystemTime,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<()> {
    if let Some(certificate_pem) = state.certificates.last() {
        let expiration = get_certificate_expiration_time(certificate_pem)?;
        const TEN_DAYS: Duration = Duration::from_secs(3600 * 24 * 10);
        if now + TEN_DAYS < expiration {
            // There is already a certificate, and it is far from expiration,
            // so we do nothing.
            return Ok(());
        }
    }
    if let Some(task) = &mut state.task {
        if now < task.schedule.updated_at + task.schedule.wait_time {
            // We do nothing before the scheduled wait time has passed.
            return Ok(());
        }
        match &task.schedule.next_step {
            TaskStep::RequestChallengeValidation => {
                super::request_challenge_validation(
                    account,
                    task.order.challenge_url.clone(),
                    fetcher,
                    acme_signer,
                )
                .await?;
                task.schedule.reset(now, TaskStep::CheckChallengeFinished);
            }
            TaskStep::CheckChallengeFinished => {
                let is_finished = super::check_challenge_finished(
                    account,
                    &task.order.authorization_url,
                    fetcher,
                    acme_signer,
                )
                .await?;
                if is_finished {
                    task.schedule.reset(now, TaskStep::FinalizeSigningRequest);
                } else {
                    task.schedule.double_wait(now);
                }
            }
            TaskStep::FinalizeSigningRequest => {
                super::finalize_signing_request(
                    account,
                    task.order.finalize_url.clone(),
                    fetcher,
                    acme_signer,
                )
                .await?;
                task.schedule.reset(now, TaskStep::DownloadCertificate);
            }
            TaskStep::DownloadCertificate => {
                let certificate_url = super::get_certificate_url(
                    account,
                    task.order.order_url.clone(),
                    fetcher,
                    acme_signer,
                )
                .await?;
                if let Some(certificate_url) = certificate_url {
                    task.order.certificate_url = Some(certificate_url);
                    let certificate_pem = super::download_certificate(
                        account,
                        task.order.certificate_url.clone().unwrap(),
                        fetcher,
                        acme_signer,
                    )
                    .await?;
                    state.certificates.push(certificate_pem);
                    state.task = None;
                } else {
                    task.schedule.double_wait(now);
                }
            }
        }
    } else {
        let order = super::place_new_order(account, fetcher, acme_signer).await?;
        state.task = Some(Task {
            order,
            schedule: Schedule {
                updated_at: now,
                wait_time: MIN_SLEEP,
                next_step: TaskStep::RequestChallengeValidation,
            },
        });
    }
    Ok(())
}

pub async fn update_state(runtime: &Runtime, account: &Account) -> Result<()> {
    let mut old_state = read_current_state(runtime).await?;
    let mut new_state = old_state.clone();
    let result = update_state_impl(
        account,
        &mut new_state,
        runtime.now,
        runtime.fetcher.as_ref(),
        runtime.acme_signer.as_ref(),
    )
    .await;
    match result {
        Ok(()) => {
            if old_state != new_state {
                write_state(runtime, &new_state).await?;
            }
            Ok(())
        }
        Err(e) => {
            // In case any error occured, we use the old state,
            // and double the wait time for next update.
            if let Some(task) = &mut old_state.task {
                task.schedule.double_wait(runtime.now);
                write_state(runtime, &old_state).await?;
            }
            Err(e)
        }
    }
}

pub async fn get_challenge_token_and_answer(runtime: &Runtime) -> Result<Option<(String, String)>> {
    let state = read_current_state(runtime).await?;
    if let Some(task) = state.task {
        Ok(Some((
            task.order.challenge_token,
            task.order.challenge_answer,
        )))
    } else {
        Ok(None)
    }
}

pub fn create_from_challenge(
    challenge_token: impl ToString,
    challenge_answer: impl ToString,
) -> AcmeStorageData {
    AcmeStorageData {
        certificates: vec![],
        task: Some(Task {
            order: OngoingOrder {
                challenge_token: challenge_token.to_string(),
                challenge_answer: challenge_answer.to_string(),
                authorization_url: String::new(),
                certificate_url: None,
                challenge_url: String::new(),
                finalize_url: String::new(),
                order_url: String::new(),
            },
            schedule: Schedule {
                updated_at: SystemTime::UNIX_EPOCH,
                wait_time: Duration::ZERO,
                next_step: TaskStep::RequestChallengeValidation,
            },
        }),
    }
}

pub fn create_from_certificate(certificate_pem: impl ToString) -> AcmeStorageData {
    AcmeStorageData {
        certificates: vec![certificate_pem.to_string()],
        task: None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        example_approved_authorization_response, example_approved_order_response,
        example_authorization_request, example_certificate_request, example_certificate_response,
        example_challenge_request, example_finalize_request, example_new_order_request,
        example_new_order_response, example_order_request, example_pending_authorization_response,
        example_pending_challenge_response, example_pending_finalize_response,
        example_pending_order_response, handle_server_directory,
    };
    use super::*;
    use crate::storage::{InMemoryStorage, Storage};
    use std::time::UNIX_EPOCH;
    const ACCOUNT: &str = r#"{
        "serverDirectoryUrl": "https://acme.server/",
        "accountUrl": "https://acme.server/acct/123456",
        "domain": "example.com",
        "certRequestDer": "Y3NyIGNvbnRlbnQ",
        "publicKeyThumbprint": "key_thumbprint"
    }"#;
    #[tokio::test]
    async fn new_storage_returns_default_state() {
        let storage = InMemoryStorage::new();
        let runtime = Runtime {
            storage: Box::new(storage),
            ..Default::default()
        };
        let state = read_current_state(&runtime).await.unwrap();
        assert!(state.certificates.is_empty());
        assert!(state.task.is_none());
    }
    #[tokio::test]
    async fn storage_with_invalid_schema_returns_default_state() {
        let storage = InMemoryStorage::new();
        storage.write(ACME_STORAGE_KEY, "asdf").await.unwrap();
        let runtime = Runtime {
            storage: Box::new(storage),
            ..Default::default()
        };
        let state = read_current_state(&runtime).await.unwrap();
        assert!(state.certificates.is_empty());
        assert!(state.task.is_none());
    }
    // When staring with an empty storage, the state machine crates an new order,
    // and stops at `RequestChallengeValidation` for the next step.
    #[tokio::test]
    async fn place_new_order_and_challenge_answer() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_new_order_request("1").await,
                    example_new_order_response("2"),
                )
                .await
                .unwrap();
            server
                .handle_next_request(
                    example_authorization_request("2").await,
                    example_pending_authorization_response("3"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH,
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                get_challenge_token_and_answer(&runtime)
                    .await
                    .unwrap()
                    .unwrap(),
                (
                    "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o".to_string(),
                    "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint".to_string()
                ),
            );
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH,
                    wait_time: Duration::from_secs(59),
                    next_step: TaskStep::RequestChallengeValidation,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `RequestChallengeValidation`, while not having waited long enough,
    // the state machine does nothing.
    #[tokio::test]
    async fn wait_challenge_answer_to_propagate() {
        let (fetcher, _server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {};
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":60,"nanos":0},
                        "next_step": "RequestChallengeValidation"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(49),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH,
                    wait_time: Duration::from_secs(60),
                    next_step: TaskStep::RequestChallengeValidation,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `RequestChallengeValidation`, and have waited long enough,
    // the state machine notifies the server that the client is ready for challenge,
    // and stops at `CheckChallengeFinished`.
    #[tokio::test]
    async fn notify_server_to_validate_challenge() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_challenge_request("1").await,
                    example_pending_challenge_response("2"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":59,"nanos":0},
                        "next_step": "RequestChallengeValidation"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH + Duration::from_secs(61),
                    wait_time: Duration::from_secs(59),
                    next_step: TaskStep::CheckChallengeFinished,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `RequestChallengeValidation`, and have waited long enough,
    // the state machine checks the server with the validation status. If the server is
    // still processing, the state machine remains in `RequestChallengeValidation`, but
    // increases the wait time.
    #[tokio::test]
    async fn wait_server_to_validate_challenge() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_authorization_request("1").await,
                    example_pending_authorization_response("2"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":60,"nanos":0},
                        "next_step": "CheckChallengeFinished"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH + Duration::from_secs(61),
                    wait_time: Duration::from_secs(120),
                    next_step: TaskStep::CheckChallengeFinished,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `RequestChallengeValidation`, and have waited long enough,
    // the state machine checks the server with the validation status. If the server has
    // finished validation, the state machine stops at `FinalizeSigningRequest` as next step.
    #[tokio::test]
    async fn acknowledge_server_finish_validation() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_authorization_request("1").await,
                    example_approved_authorization_response("2"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":59,"nanos":0},
                        "next_step": "CheckChallengeFinished"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH + Duration::from_secs(61),
                    wait_time: Duration::from_secs(59),
                    next_step: TaskStep::FinalizeSigningRequest,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `FinalizeSigningRequest`, and have waited long enough,
    // the state machine submits CSR file to the server, and stops at
    // `DownloadCertificate` as next step.
    #[tokio::test]
    async fn submit_certificate_signing_request() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_finalize_request("1").await,
                    example_pending_finalize_response("2"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":59,"nanos":0},
                        "next_step": "FinalizeSigningRequest"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH + Duration::from_secs(61),
                    wait_time: Duration::from_secs(59),
                    next_step: TaskStep::DownloadCertificate,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `DownloadCertificate`, and have waited long enough,
    // the state machine checks the server with certificate signing status.
    // If the server is still processing, the state machine remains in
    // `DownloadCertificate`, but increases the wait time.
    #[tokio::test]
    async fn wait_for_server_signing_certificate() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_order_request("1").await,
                    example_pending_order_response("2"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":60,"nanos":0},
                        "next_step": "DownloadCertificate"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            assert_eq!(
                read_current_state(&runtime)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .schedule,
                Schedule {
                    updated_at: UNIX_EPOCH + Duration::from_secs(61),
                    wait_time: Duration::from_secs(120),
                    next_step: TaskStep::DownloadCertificate,
                }
            );
        };
        tokio::join!(client_thread, server_thread);
    }
    // When staring with `DownloadCertificate`, and have waited long enough,
    // the state machine checks the server with certificate signing status.
    // If the server is has issued the certificate, the state machine stops
    // at the new certificate.
    #[tokio::test]
    async fn download_certificate_from_server() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let server_thread = async {
            handle_server_directory(&mut server, "1").await;
            server
                .handle_next_request(
                    example_order_request("1").await,
                    example_approved_order_response("2"),
                )
                .await
                .unwrap();
            handle_server_directory(&mut server, "3").await;
            server
                .handle_next_request(
                    example_certificate_request("3").await,
                    example_certificate_response("4"),
                )
                .await
                .unwrap();
        };
        let client_thread = async {
            let storage = Box::new(InMemoryStorage::new());
            const VALUE: &str = r#"{
                "certificates": [],
                "task": {
                    "order": {"authorization_url":"https://acme.server/authz-v3/1866692048","challenge_url":"https://acme.server/chall-v3/1866692048/oFAcwQ","challenge_token":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o","challenge_answer":"0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.key_thumbprint","order_url":"https://acme.server/order/46540038","finalize_url":"https://acme.server/finalize/46540038/1977802858","certificate_url":null},
                    "schedule": {
                        "updated_at": {"secs_since_epoch":0,"nanos_since_epoch":0},
                        "wait_time": {"secs":59,"nanos":0},
                        "next_step": "DownloadCertificate"
                    }
                }
            }"#;
            storage.write(ACME_STORAGE_KEY, VALUE).await.unwrap();
            let runtime = Runtime {
                storage,
                now: UNIX_EPOCH + Duration::from_secs(61),
                fetcher: Box::new(fetcher),
                ..Default::default()
            };
            let account: Account = serde_json::from_str(ACCOUNT).unwrap();
            update_state(&runtime, &account).await.unwrap();
            let new_state = read_current_state(&runtime).await.unwrap();
            assert!(new_state.task.is_none());
            assert!(!new_state.certificates.is_empty());
        };
        tokio::join!(client_thread, server_thread);
    }
}
