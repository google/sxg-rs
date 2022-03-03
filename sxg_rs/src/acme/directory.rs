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

use crate::fetcher::Fetcher;
use anyhow::{Error, Result};
use chrono::offset::FixedOffset;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// The URLs for each operation on a ACME server.
// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: String,
}

impl Directory {
    /// Constructs an ACME directory by fetching the given ACME directory URL.
    pub async fn new<F: Fetcher>(url: &str, fetcher: &F) -> Result<Self> {
        let bytes = fetcher
            .get(url)
            .await
            .map_err(|e| e.context("Failed to fetch from directory URL"))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::new(e).context("Failed to parse ACME directory"))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequestPayload {
    pub contact: Vec<String>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub status: Status,
    pub expires: DateTime<FixedOffset>,
    pub challenges: Vec<Challenge>,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub r#type: String,
    pub token: String,
    pub url: String,
    pub status: Status,
}

// https://datatracker.ietf.org/doc/html/rfc8555#:~:text=it%20should%20send%20a%20POST%20request%20to%20the%20order%20resource%27s%20finalize%20URL
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeRequest<'a> {
    pub csr: &'a str,
}

// https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}
