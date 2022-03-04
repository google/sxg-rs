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

pub struct OngoingCertificateRequest<F: Fetcher, S: Signer> {
    account_url: String,
    authorization_url: String,
    cert_request_der: Vec<u8>,
    challenge: Challenge,
    pub challenge_answer: String,
    client: Client<F, S>,
    order: Order,
}

pub async fn apply_certificate_and_get_challenge_answer<F: Fetcher, S: Signer>(
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
        .iter()
        .next()
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

async fn get_http_challenge<F: Fetcher, S: Signer>(
    client: &mut Client<F, S>,
    account_url: &str,
    authorization_url: &str,
) -> Result<Challenge> {
    let response = client
        .post_as_get(
            AuthMethod::KeyId(&account_url),
            authorization_url.to_string(),
        )
        .await?;
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
