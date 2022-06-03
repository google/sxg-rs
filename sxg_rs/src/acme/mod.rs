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

//! This module includes tools to communicate with an ACME server.
//! It takes three steps to request a certificate.
//! 1. Call this module's `create_request_and_get_challenge_answer`. An HTTP
//!    challenge is created with the answer.
//! 1. Use some other methods to set up an HTTP service to serve the HTTP
//!    challenge answer.
//! 1. Call this module's `continue_challenge_validation_and_get_certificate`.

pub mod client;
pub mod directory;
pub mod eab;
pub mod jws;
pub mod state_machine;

use crate::crypto::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::signature::Signer;
use anyhow::{anyhow, Error, Result};
use client::{parse_response_body, AuthMethod, Client};
use directory::{
    Authorization, Challenge, Directory, FinalizeRequest, Identifier, IdentifierType,
    NewAccountRequestPayload, NewAccountResponsePayload, NewOrderRequestPayload, Order, Status,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub server_directory_url: String,
    pub account_url: String,
    pub domain: String,
    #[serde(with = "crate::serde_helpers::base64")]
    pub cert_request_der: Vec<u8>,
    pub public_key_thumbprint: String,
}

/// The runtime context of an ongoing ACME certificate request, which is
/// waiting for HTTP challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OngoingOrder {
    authorization_url: String,
    challenge_url: String,
    challenge_token: String,
    challenge_answer: String,
    order_url: String,
    finalize_url: String,
    certificate_url: Option<String>,
}

pub struct AccountSetupParams<'a> {
    pub directory_url: String,
    /// This must be the same as what required by ACME server.
    pub agreed_terms_of_service: &'a str,
    pub external_account_binding: Option<jws::JsonWebSignature>,
    pub email: &'a str,
    pub domain: String,
    pub public_key: EcPublicKey,
    pub cert_request_der: Vec<u8>,
}

/// Connects to ACME server to request a certificate, stops after generating
/// HTTP challenge answer, and returns the running context of this application.
pub async fn create_account(
    params: AccountSetupParams<'_>,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<Account> {
    let public_key_thumbprint = base64::encode_config(
        params.public_key.get_jwk_thumbprint()?,
        base64::URL_SAFE_NO_PAD,
    );
    let (directory, nonce) = Directory::from_url(&params.directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        client::AuthMethod::JsonWebKey(params.public_key),
        nonce,
    );
    if params.agreed_terms_of_service != client.directory.meta.terms_of_service {
        return Err(anyhow!(
            "Please read and include the terms of service {}",
            &client.directory.meta.terms_of_service
        ));
    }
    if client.directory.meta.external_account_required == Some(true)
        && params.external_account_binding.is_none()
    {
        return Err(anyhow!(
            "External Acount Binding information is required by server but not provided by client"
        ));
    }
    let account_url: String = {
        let request_payload = NewAccountRequestPayload {
            contact: vec![format!("mailto:{}", params.email)],
            external_account_binding: params.external_account_binding,
            terms_of_service_agreed: true,
        };
        let response = client
            .post_with_payload(
                client.directory.new_account.clone(),
                request_payload,
                fetcher,
                acme_signer,
            )
            .await?;
        let rsp_paylod: NewAccountResponsePayload = parse_response_body(&response)?;
        if rsp_paylod.status != Status::Valid {
            return Err(Error::msg("The account status is not valid"));
        }
        client::find_header(&response, "Location")?
    };
    Ok(Account {
        server_directory_url: params.directory_url,
        cert_request_der: params.cert_request_der,
        public_key_thumbprint,
        domain: params.domain,
        account_url,
    })
}

pub async fn place_new_order(
    account: &Account,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<OngoingOrder> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    let (order, order_url) = {
        let request_payload = NewOrderRequestPayload {
            identifiers: vec![Identifier {
                r#type: IdentifierType::Dns,
                value: account.domain.clone(),
            }],
            not_before: None,
            not_after: None,
        };
        let response = client
            .post_with_payload(
                client.directory.new_order.clone(),
                request_payload,
                fetcher,
                acme_signer,
            )
            .await?;
        let order: Order = parse_response_body(&response)?;
        let order_url = client::find_header(&response, "location")
            .map_err(|e| e.context("Failed to get order URL"))?;
        (order, order_url)
    };
    let authorization_url: String = order
        .authorizations
        .get(0)
        .ok_or_else(|| Error::msg("The order response does not contain authorizations"))?
        .to_owned();
    let challenge =
        get_http_challenge(&mut client, &authorization_url, fetcher, acme_signer).await?;

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
    let challenge_answer = format!("{}.{}", challenge.token, account.public_key_thumbprint);
    Ok(OngoingOrder {
        authorization_url,
        challenge_url: challenge.url,
        challenge_token: challenge.token,
        challenge_answer,
        order_url,
        finalize_url: order.finalize,
        certificate_url: None,
    })
}

/// Notifies the server that the client is ready for HTTP challenge.
pub async fn request_challenge_validation(
    account: &Account,
    challenge_url: String,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<()> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    // The client indicates to the server that it is ready for the challenge
    // validation by sending an empty JSON body ("{}") carried in a POST
    // request to the challenge URL (not the authorization URL).
    client
        .post_with_payload(challenge_url, serde_json::Map::new(), fetcher, acme_signer)
        .await?;
    Ok(())
}

/// Checks the HTTP challenge status. Returns `true` if the challenge is successfully finished;
/// returns `false` is the server is still processing.
pub async fn check_challenge_finished(
    account: &Account,
    authorization_url: &str,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<bool> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    let challenge =
        get_http_challenge(&mut client, authorization_url, fetcher, acme_signer).await?;
    // The status of a challenge object is defined in
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
    match challenge.status {
        Status::Valid => Ok(true),
        Status::Pending | Status::Processing => Ok(false),
        Status::Invalid => Err(anyhow!(
            "The challenge is rejected by server with the error {}",
            challenge.error.unwrap_or(serde_json::Value::Null)
        )),
        _ => Err(anyhow!(
            "This code is unreachable, \
                but the challenge now has the status {:?}.",
            challenge.status
        )),
    }
}

/// Finalizes the order by submitting the CSR to the server.
async fn finalize_signing_request(
    account: &Account,
    finalize_url: String,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<()> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    client
        .post_with_payload(
            finalize_url.clone(),
            FinalizeRequest {
                csr: &base64::encode_config(&account.cert_request_der, base64::URL_SAFE_NO_PAD),
            },
            fetcher,
            acme_signer,
        )
        .await?;
    Ok(())
}

/// Checks the order status, and returns the certificate URL if it is issued;
/// returns `None` if the server is still processing.
async fn get_certificate_url(
    account: &Account,
    order_url: String,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<Option<String>> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    let response = client
        .post_as_get(order_url.clone(), fetcher, acme_signer)
        .await?;
    let order: Order = parse_response_body(&response)?;
    match order.status {
        Status::Pending | Status::Processing => Ok(None),
        Status::Valid => {
            let certificate_url = order.certificate.ok_or_else(|| {
                anyhow!("The order status is Valid, but there is no certificate URL")
            })?;
            Ok(Some(certificate_url))
        }
        _ => Err(anyhow!(
            "This code is unreachable, \
                    but the order now has the status {:?}.",
            order.status
        )),
    }
}

/// Downloads the certificate from URL, and returns it in PEM format.
async fn download_certificate(
    account: &Account,
    certificate_url: String,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<String> {
    let (directory, nonce) = Directory::from_url(&account.server_directory_url, fetcher).await?;
    let mut client = Client::new(
        &directory,
        AuthMethod::KeyId(account.account_url.clone()),
        nonce,
    );
    let certificate = client
        .post_as_get(certificate_url, fetcher, acme_signer)
        .await?;
    let certificate = String::from_utf8(certificate.body).unwrap();
    Ok(certificate)
}

/// Fetches `authorization_url` and returns the first `HTTP-01` challenge.
async fn get_http_challenge(
    client: &mut Client<'_>,
    authorization_url: &str,
    fetcher: &dyn Fetcher,
    acme_signer: &dyn Signer,
) -> Result<Challenge> {
    let response = client
        .post_as_get(authorization_url.to_string(), fetcher, acme_signer)
        .await?;
    let authorization: Authorization = parse_response_body(&response)?;
    let challenge: &Challenge = authorization
        .challenges
        .iter()
        .find(|challenge| challenge.r#type == "http-01")
        .ok_or_else(|| Error::msg("The authorization does not have http-01 type challenge"))?;
    Ok((*challenge).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::mock_fetcher::MockServer;
    use crate::http::{HttpRequest, HttpResponse, Method};
    use crate::runtime::Runtime;
    use crate::signature::mock_signer::MockSigner;
    use jws::JsonWebSignature;

    pub async fn handle_server_directory(server: &mut MockServer, nonce: &str) {
        let req = HttpRequest {
            body: vec![],
            method: Method::Get,
            headers: vec![],
            url: "https://acme.server/".to_string(),
        };
        let res = HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                "keyChange": "https://acme.server/key-change",
                "newAccount": "https://acme.server/new-acct",
                "newNonce": "https://acme.server/new-nonce",
                "newOrder": "https://acme.server/new-order",
                "revokeCert": "https://acme.server/revoke-cert",
                "meta": {
                    "termsOfService": "https://acme.server/terms_of_service.pdf"
                }
            }"#
            .to_string()
            .into_bytes(),
        };
        server.handle_next_request(req, res).await.unwrap();
    }

    pub async fn example_new_order_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
            body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/new-order","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                r#"{"identifiers":[{"type":"dns","value":"example.com"}],"notBefore":null,"notAfter":null}"#,
                &signer,
            ).await.unwrap()).unwrap(),
            method: Method::Post,
            headers: vec![(
                "content-type".to_string(),
                "application/jose+json".to_string(),
            )],
            url: "https://acme.server/new-order".to_string(),
        }
    }

    pub fn example_new_order_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![
                ("Replay-Nonce".to_string(), nonce.to_string()),
                (
                    "Location".to_string(),
                    "https://acme.server/order/46540038".to_string(),
                ),
            ],
            body: r#"{
                "status": "pending",
                "expires": "2022-03-15T19:38:31Z",
                "identifiers": [
                    {
                        "type": "dns",
                        "value": "example.com"
                    }
                ],
                "authorizations": [
                    "https://acme.server/authz-v3/1866692048"
                ],
                "finalize": "https://acme.server/finalize/46540038/1977802858"
            }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub async fn example_authorization_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
            body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/authz-v3/1866692048","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                "",
                &signer,
            ).await.unwrap()).unwrap(),
            method: Method::Post,
            headers: vec![(
                "content-type".to_string(),
                "application/jose+json".to_string(),
            )],
            url: "https://acme.server/authz-v3/1866692048".to_string(),
        }
    }

    pub fn example_pending_authorization_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                "identifier": {
                    "type": "dns",
                    "value": "example.com"
                },
                "status": "pending",
                "expires": "2022-03-15T19:38:31Z",
                "challenges": [
                    {
                        "type": "http-01",
                        "status": "pending",
                        "url": "https://acme.server/chall-v3/1866692048/oFAcwQ",
                        "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o"
                    },
                    {
                        "type": "dns-01",
                        "status": "pending",
                        "url": "https://acme.server/chall-v3/1866692048/G_sfog",
                        "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o"
                    },
                    {
                        "type": "tls-alpn-01",
                        "status": "pending",
                        "url": "https://acme.server/chall-v3/1866692048/O-NVtg",
                        "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o"
                    }
                ]
            }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub fn example_approved_authorization_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                "identifier": {
                    "type": "dns",
                    "value": "example.com"
                },
                "status": "valid",
                "expires": "2022-03-15T19:38:33Z",
                "challenges": [
                    {
                        "type": "http-01",
                        "status": "valid",
                        "url": "https://acme.server/chall-v3/1866692048/oFAcwQ",
                        "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o",
                        "validated": "2022-03-08T19:38:32Z"
                    }
                ]
            }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub async fn example_challenge_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/chall-v3/1866692048/oFAcwQ","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                    "{}",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/chall-v3/1866692048/oFAcwQ".to_string(),
            }
    }

    pub fn example_pending_challenge_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.server/chall-v3/1866692048/oFAcwQ",
                    "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o"
                }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub async fn example_finalize_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/finalize/46540038/1977802858","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                    r#"{"csr":"Y3NyIGNvbnRlbnQ"}"#,
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/finalize/46540038/1977802858".to_string(),
            }
    }

    pub fn example_pending_finalize_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                    "status": "processing",
                    "expires": "2022-03-15T19:38:31Z",
                    "identifiers": [
                        {
                            "type": "dns",
                            "value": "example.com"
                        }
                    ],
                    "authorizations": [
                        "https://acme.server/authz-v3/1866692048"
                    ],
                    "finalize": "https://acme.server/finalize/46540038/1977802858",
                }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub async fn example_order_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/order/46540038","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                    "",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/order/46540038".to_string(),
            }
    }

    pub fn example_pending_order_response(nonce: &str) -> HttpResponse {
        example_new_order_response(nonce)
    }

    pub fn example_approved_order_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: r#"{
                    "status": "valid",
                    "expires": "2022-03-15T19:38:31Z",
                    "identifiers": [
                        {
                            "type": "dns",
                            "value": "example.com"
                        }
                    ],
                    "authorizations": [
                        "https://acme.server/authz-v3/1866692048"
                    ],
                    "finalize": "https://acme.server/finalize/46540038/1977802858",
                    "certificate": "https://acme.server/cert/fa7af446e23117a13137f4cf64f24c3cdb5b"
                }"#
            .to_string()
            .into_bytes(),
        }
    }

    pub async fn example_certificate_request(nonce: &str) -> HttpRequest {
        let signer = MockSigner;
        HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    &format!(r#"{{"alg":"ES256","nonce":"{}","url":"https://acme.server/cert/fa7af446e23117a13137f4cf64f24c3cdb5b","jwk":null,"kid":"https://acme.server/acct/123456"}}"#, nonce),
                    "",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/cert/fa7af446e23117a13137f4cf64f24c3cdb5b".to_string(),
            }
    }

    pub fn example_certificate_response(nonce: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".to_string(), nonce.to_string())],
            body: "content of certificate".to_string().into_bytes(),
        }
    }

    // Tests basic workflow of requesting certificate using ACME protocol.
    #[tokio::test]
    async fn workflow() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let runtime = Runtime {
            fetcher: Box::new(fetcher),
            ..Default::default()
        };
        let public_key = EcPublicKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: vec![1],
            y: vec![2],
        };
        // The client is handled by the code in `sxg_rs::acme`.
        let client_thread = async {
            let acme_account = create_account(
                AccountSetupParams {
                    directory_url: "https://acme.server/".to_string(),
                    agreed_terms_of_service: "https://acme.server/terms_of_service.pdf",
                    external_account_binding: None,
                    email: "admin@example.com",
                    domain: "example.com".to_string(),
                    public_key,
                    cert_request_der: "csr content".to_string().into_bytes(),
                },
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap();
            let ongoing_certificate_request = place_new_order(
                &acme_account,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap();
            assert_eq!(&ongoing_certificate_request.challenge_answer, "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.CmzeuaSxxfG8gIKRU_AgBzPa16nTt0H64JD7q1sZUUY");
            request_challenge_validation(
                &acme_account,
                ongoing_certificate_request.challenge_url,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap();
            assert!(check_challenge_finished(
                &acme_account,
                &ongoing_certificate_request.authorization_url,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap(),);
            finalize_signing_request(
                &acme_account,
                ongoing_certificate_request.finalize_url,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap();
            let certificate_url = get_certificate_url(
                &acme_account,
                ongoing_certificate_request.order_url,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap()
            .unwrap();
            let certificate_pem = download_certificate(
                &acme_account,
                certificate_url,
                runtime.fetcher.as_ref(),
                runtime.acme_signer.as_ref(),
            )
            .await
            .unwrap();
            assert_eq!(certificate_pem, "content of certificate");
        };
        // The server side is mocked by directly putting all HTTP requests and responses.
        // For each pair (`req`, `res`) variables in the following code block, we expect the client
        // thread to fetch `req`, and we will return `res` to client side.
        let server_thread = async {
            let signer = crate::signature::mock_signer::MockSigner;

            handle_server_directory(&mut server, "1").await;

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/new-acct","jwk":{"crv":"P-256","kty":"EC","x":"AQ","y":"Ag"},"kid":null}"#,
                    r#"{"contact":["mailto:admin@example.com"],"externalAccountBinding":null,"termsOfServiceAgreed":true}"#,
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/new-acct".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Location".to_string(),
                        "https://acme.server/acct/123456".to_string(),
                    ),
                    ("Replay-Nonce".to_string(), "2".to_string()),
                ],
                body: r#"{
                    "key": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "AQ",
                        "y": "Ag"
                    },
                    "contact": [
                        "mailto:admin@example.com"
                    ],
                    "initialIp": "2620:0:1000:0:0:0:0:0",
                    "createdAt": "2022-03-08T19:01:23.845700962Z",
                    "status": "valid"
                }"#
                .to_string()
                .into_bytes(),
            };
            server.handle_next_request(req, res).await.unwrap();

            handle_server_directory(&mut server, "3").await;

            server
                .handle_next_request(
                    example_new_order_request("3").await,
                    example_new_order_response("4"),
                )
                .await
                .unwrap();

            server
                .handle_next_request(
                    example_authorization_request("4").await,
                    example_pending_authorization_response("5"),
                )
                .await
                .unwrap();

            handle_server_directory(&mut server, "6").await;

            server
                .handle_next_request(
                    example_challenge_request("6").await,
                    example_pending_challenge_response("7"),
                )
                .await
                .unwrap();

            handle_server_directory(&mut server, "8").await;

            server
                .handle_next_request(
                    example_authorization_request("8").await,
                    example_approved_authorization_response("9"),
                )
                .await
                .unwrap();

            handle_server_directory(&mut server, "10").await;

            server
                .handle_next_request(
                    example_finalize_request("10").await,
                    example_pending_finalize_response("11"),
                )
                .await
                .unwrap();

            handle_server_directory(&mut server, "12").await;

            server
                .handle_next_request(
                    example_order_request("12").await,
                    example_approved_order_response("13"),
                )
                .await
                .unwrap();

            handle_server_directory(&mut server, "14").await;

            server
                .handle_next_request(
                    example_certificate_request("14").await,
                    example_certificate_response("15"),
                )
                .await
                .unwrap();
        };
        tokio::join!(client_thread, server_thread);
    }
}
