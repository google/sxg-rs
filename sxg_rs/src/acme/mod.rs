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
pub mod jws;

use crate::crypto::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::signature::Signer;
use anyhow::{Error, Result};
use client::AuthMethod;
use client::Client;
use directory::{
    Authorization, Challenge, FinalizeRequest, Identifier, IdentifierType,
    NewAccountRequestPayload, NewAccountResponsePayload, NewOrderRequestPayload, Order, Status,
};

/// The runtime context of an ongoing ACME certificate request, which is
/// waiting for HTTP challenge.
pub struct OngoingCertificateRequest<F: Fetcher, S: Signer> {
    account_url: String,
    authorization_url: String,
    cert_request_der: Vec<u8>,
    challenge: Challenge,
    pub challenge_answer: String,
    client: Client<F, S>,
    order: Order,
}

/// Connects to ACME server to request a certificate, stops after generating
/// HTTP challenge answer, and returns the running context of this application.
pub async fn create_request_and_get_challenge_answer<F: Fetcher, S: Signer>(
    directory_url: &str,
    email: &str,
    domain: impl ToString,
    public_key: EcPublicKey,
    cert_request_der: Vec<u8>,
    fetcher: F,
    signer: S,
) -> Result<OngoingCertificateRequest<F, S>> {
    let mut client = Client::new(directory_url, public_key, fetcher, signer).await?;
    let account_url: String = {
        let request_payload = NewAccountRequestPayload {
            contact: vec![format!("mailto:{}", email)],
            terms_of_service_agreed: true, // DO NOT SUBMIT
        };
        let response = client
            .post_with_payload(
                AuthMethod::JsonWebKey,
                client.directory.new_account.clone(),
                request_payload,
            )
            .await?;
        let rsp_paylod: NewAccountResponsePayload = serde_json::from_slice(&response.body)
            .map_err(|e| Error::new(e).context("Failed to parse new account response"))?;
        if rsp_paylod.status != Status::Valid {
            return Err(Error::msg("The account status is not valid"));
        }
        client::find_header(&response, "Location")?
    };
    let order: Order = {
        let request_payload = NewOrderRequestPayload {
            identifiers: vec![Identifier {
                r#type: IdentifierType::Dns,
                value: domain.to_string(),
            }],
            not_before: None,
            not_after: None,
        };
        let response = client
            .post_with_payload(
                AuthMethod::KeyId(&account_url),
                client.directory.new_order.clone(),
                request_payload,
            )
            .await?;
        serde_json::from_slice(&response.body)
            .map_err(|e| Error::new(e).context("Failed to parse new order response"))?
    };
    let authorization_url: String = order
        .authorizations
        .get(0)
        .ok_or_else(|| Error::msg("The order response does not contain authorizations"))?
        .to_owned();
    let challenge = get_http_challenge(&mut client, &account_url, &authorization_url).await?;

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
    let challenge_answer = format!(
        "{}.{}",
        challenge.token,
        base64::encode_config(
            client.public_key.get_jwk_thumbprint()?,
            base64::URL_SAFE_NO_PAD
        )
    );
    Ok(OngoingCertificateRequest {
        account_url,
        authorization_url,
        cert_request_der,
        challenge,
        challenge_answer,
        client,
        order,
    })
}

/// Notifies the server to validate HTTP challenge, polls the request status
/// until it is ready, and returns the certificate in PEM format.
pub async fn continue_challenge_validation_and_get_certificate<F: Fetcher, S: Signer>(
    ongoing_certificate_request: OngoingCertificateRequest<F, S>,
) -> Result<String> {
    let OngoingCertificateRequest {
        account_url,
        authorization_url,
        cert_request_der,
        challenge,
        challenge_answer: _,
        mut client,
        order,
    } = ongoing_certificate_request;
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    // The client indicates to the server that it is ready for the challenge
    // validation by sending an empty JSON body ("{}") carried in a POST
    // request to the challenge URL (not the authorization URL).
    client
        .post_with_payload(
            AuthMethod::KeyId(&account_url),
            challenge.url,
            serde_json::Map::new(),
        )
        .await?;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let challenge = get_http_challenge(&mut client, &account_url, &authorization_url).await?;
        if challenge.status == Status::Valid {
            break;
        }
    }
    let order: Order = {
        let response = client
            .post_with_payload(
                AuthMethod::KeyId(&account_url),
                order.finalize,
                FinalizeRequest {
                    csr: &base64::encode_config(cert_request_der, base64::URL_SAFE_NO_PAD),
                },
            )
            .await?;
        serde_json::from_slice(&response.body)
            .map_err(|e| Error::new(e).context("Failed to parse order finalize response"))?
    };
    let certificate_url = order.certificate.unwrap();
    let certificate = client
        .post_as_get(AuthMethod::KeyId(&account_url), certificate_url)
        .await?;
    let certificate = String::from_utf8(certificate.body).unwrap();
    Ok(certificate)
}

/// Fetches `authorization_url` and returns the first `HTTP-01` challenge.
async fn get_http_challenge<F: Fetcher, S: Signer>(
    client: &mut Client<F, S>,
    account_url: &str,
    authorization_url: &str,
) -> Result<Challenge> {
    let response = client
        .post_as_get(
            AuthMethod::KeyId(account_url),
            authorization_url.to_string(),
        )
        .await?;
    println!("{}", String::from_utf8(response.body.clone()).unwrap());
    let authorization: Authorization = serde_json::from_slice(&response.body)
        .map_err(|e| Error::new(e).context("Failed to parse authorization response"))?;
    let challenge: &Challenge = authorization
        .challenges
        .iter()
        .find_map(|challenge| {
            if challenge.r#type == "http-01" {
                Some(challenge)
            } else {
                None
            }
        })
        .ok_or_else(|| Error::msg("The authorization does not have http-01 type challenge"))?;
    Ok((*challenge).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse, Method};
    use jws::JsonWebSignature;
    #[tokio::test]
    async fn workflow() {
        let (fetcher, mut server) = crate::fetcher::mock_fetcher::create();
        let public_key = EcPublicKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: vec![1],
            y: vec![2],
        };
        println!("{}", serde_json::to_string_pretty(&public_key).unwrap());
        let client_thread = async {
            let signer = crate::signature::mock_signer::MockSigner;
            let ongoing_certificate_request = create_request_and_get_challenge_answer(
                "https://acme.server/",
                "admin@example.com",
                "example.com",
                public_key,
                "csr content".to_string().into_bytes(),
                fetcher,
                signer,
            )
            .await
            .unwrap();
            assert_eq!(&ongoing_certificate_request.challenge_answer, "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o.CmzeuaSxxfG8gIKRU_AgBzPa16nTt0H64JD7q1sZUUY");
            let certificate_pem =
                continue_challenge_validation_and_get_certificate(ongoing_certificate_request)
                    .await
                    .unwrap();
            assert_eq!(certificate_pem, "content of certificate");
        };
        let server_thread = async {
            let signer = crate::signature::mock_signer::MockSigner;

            let req = HttpRequest {
                body: vec![],
                method: Method::Get,
                headers: vec![],
                url: "https://acme.server/".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![],
                body: r#"
                      {
                        "keyChange": "https://acme.server/key-change",
                        "newAccount": "https://acme.server/new-acct",
                        "newNonce": "https://acme.server/new-nonce",
                        "newOrder": "https://acme.server/new-order",
                        "revokeCert": "https://acme.server/revoke-cert"
                      }
                    "#
                .to_string()
                .into_bytes(),
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: vec![],
                method: Method::Get,
                headers: vec![],
                url: "https://acme.server/new-nonce".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
                body: vec![],
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/new-acct","jwk":{"crv":"P-256","kty":"EC","x":"AQ","y":"Ag"},"kid":null}"#,
                    r#"{"contact":["mailto:admin@example.com"],"termsOfServiceAgreed":true}"#,
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
                    ("Replay-Nonce".to_string(), "1".to_string()),
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

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/new-order","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    r#"{"identifiers":[{"type":"dns","value":"example.com"}],"notBefore":null,"notAfter":null}"#,
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/new-order".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
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
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/authz-v3/1866692048","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    "",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/authz-v3/1866692048".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
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
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/chall-v3/1866692048/oFAcwQ","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    "{}",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/chall-v3/1866692048/oFAcwQ".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
                body: r#"{
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.server/chall-v3/1866692048/oFAcwQ",
                    "token": "0HORFRxrqEtAB-vUh9iSnFBHE66qWX4bbU1SBWxOr5o"
                }"#
                .to_string()
                .into_bytes(),
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/authz-v3/1866692048","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    "",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/authz-v3/1866692048".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
                body: r#"{
                    "identifier": {
                        "type": "dns",
                        "value": "example.com"
                    },
                    "status": "valid",
                    "expires": "2022-04-07T19:38:33Z",
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
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/finalize/46540038/1977802858","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    r#"{"csr":"Y3NyIGNvbnRlbnQ"}"#,
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/finalize/46540038/1977802858".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
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
            };
            server.handle_next_request(req, res).await.unwrap();

            let req = HttpRequest {
                body: serde_json::to_vec(&JsonWebSignature::new_from_serialized(
                    r#"{"alg":"ES256","nonce":"1","url":"https://acme.server/cert/fa7af446e23117a13137f4cf64f24c3cdb5b","jwk":null,"kid":"https://acme.server/acct/123456"}"#,
                    "",
                    &signer,
                ).await.unwrap()).unwrap(),
                method: Method::Post,
                headers: vec![(
                    "content-type".to_string(),
                    "application/jose+json".to_string(),
                )],
                url: "https://acme.server/cert/fa7af446e23117a13137f4cf64f24c3cdb5b".to_string(),
            };
            let res = HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".to_string(), "1".to_string())],
                body: "content of certificate".to_string().into_bytes(),
            };
            server.handle_next_request(req, res).await.unwrap();
        };
        tokio::join!(client_thread, server_thread);
    }
}