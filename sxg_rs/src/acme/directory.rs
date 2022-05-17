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

//! This module includes the URL, request and response of the ACME operations.

use crate::fetcher::Fetcher;
use crate::http::HttpRequest;
use anyhow::{Error, Result};
use chrono::offset::FixedOffset;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// The URLs for each operation on a ACME server.
// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    // Although `key_change` is a required field, we are not using it.
    // We are marking it an optional field here, so we don't throw errors if
    // the ACME server does not provide it.
    pub key_change: Option<String>,
    pub meta: MetaData,
}

impl Directory {
    /// Constructs an ACME directory by fetching the given ACME directory URL.
    /// The second item in return value is the `replay-nonce` header from server.
    pub async fn from_url(url: &str, fetcher: &dyn Fetcher) -> Result<(Self, Option<String>)> {
        let request = HttpRequest {
            body: vec![],
            headers: vec![],
            method: crate::http::Method::Get,
            url: url.to_string(),
        };
        let response = fetcher.fetch(request).await?;
        let nonce = super::client::find_header(&response, "replay-nonce").ok();
        let directory = serde_json::from_slice(&response.body)
            .map_err(|e| Error::new(e).context("Failed to parse ACME directory"))?;
        Ok((directory, nonce))
    }
}

/// The meta data in ACME directory object
// https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.6
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    pub terms_of_service: String,
    pub external_account_required: Option<bool>,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequestPayload {
    pub contact: Vec<String>,
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4
    pub external_account_binding: Option<super::jws::JsonWebSignature>,
    pub terms_of_service_agreed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountResponsePayload {
    pub status: Status,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentifierType {
    Dns,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
    pub r#type: IdentifierType,
    pub value: String,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderRequestPayload {
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<DateTime<FixedOffset>>,
    pub not_after: Option<DateTime<FixedOffset>>,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: Status,
    pub expires: Option<DateTime<FixedOffset>>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<DateTime<FixedOffset>>,
    pub not_after: Option<DateTime<FixedOffset>>,
    pub error: Option<serde_json::Value>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub status: Status,
    pub expires: DateTime<FixedOffset>,
    pub challenges: Vec<Challenge>,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub r#type: String,
    pub token: String,
    pub url: String,
    pub status: Status,
    // https://datatracker.ietf.org/doc/html/rfc8555#:~:text=it%20SHOULD%20also%0A%20%20%20include%20the%20%22error%22%20field
    // The `error` field is added when the challenge object is in an invalid status.
    // We only use this field to print to console, hence we define it as a
    // generic JSON type without internal details.
    pub error: Option<serde_json::Value>,
}

// https://datatracker.ietf.org/doc/html/rfc8555#:~:text=it%20should%20send%20a%20POST%20request%20to%20the%20order%20resource%27s%20finalize%20URL
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeRequest<'a> {
    pub csr: &'a str,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}
