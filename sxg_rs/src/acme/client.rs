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

//! An ACME client handles authentication with the ACME server.

use super::directory::Directory;
use crate::crypto::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::signature::Signer;
use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};

pub struct Client<F: Fetcher, S: Signer> {
    pub directory: Directory,
    pub auth_method: AuthMethod,
    nonce: Option<String>,
    fetcher: F,
    signer: S,
}

pub enum AuthMethod {
    JsonWebKey(EcPublicKey),
    KeyId(String),
}

impl<F: Fetcher, S: Signer> Client<F, S> {
    pub async fn new(
        directory: Directory,
        auth_method: AuthMethod,
        fetcher: F,
        signer: S,
    ) -> Result<Self> {
        Ok(Client {
            directory,
            auth_method,
            nonce: None,
            fetcher,
            signer,
        })
    }
    /// Fetches a server resource at given URL using
    /// [POST-as-GET](https://datatracker.ietf.org/doc/html/rfc8555#section-6.3)
    /// method. `POST-as-GET` is a `POST` request with no request payload. This
    /// function is useful because an ACME server always returns error code
    /// `405` for `GET` requests, which don't contain request body for
    /// authentication.
    pub async fn post_as_get(&mut self, url: String) -> Result<HttpResponse> {
        let payload: Option<()> = None;
        self.post_impl(url, payload).await
    }
    /// Fetches a server resource at given URL using `POST` method with a
    /// request payload.
    pub async fn post_with_payload<P: Serialize>(
        &mut self,
        url: String,
        payload: P,
    ) -> Result<HttpResponse> {
        self.post_impl(url, Some(payload)).await
    }
    /// Encapsulates the payload in JWS for authentication, connects to the ACME
    /// server, saves `nonce` for next request, and returns the server response.
    async fn post_impl<P: Serialize>(
        &mut self,
        url: String,
        payload: Option<P>,
    ) -> Result<HttpResponse> {
        let nonce = self.take_nonce().await?;
        let (jwk, key_id) = match &self.auth_method {
            AuthMethod::JsonWebKey(public_key) => (Some(public_key), None),
            AuthMethod::KeyId(key_id) => (None, Some(key_id.as_str())),
        };
        let request_body =
            super::jws::create_acme_request_body(jwk, key_id, nonce, &url, payload, &self.signer)
                .await?;
        let request = HttpRequest {
            url: url.clone(),
            method: Method::Post,
            headers: vec![(
                "content-type".to_string(),
                "application/jose+json".to_string(),
            )],
            body: request_body,
        };
        let response = self.fetcher.fetch(request).await?;
        if let Ok(nonce) = find_header(&response, "Replay-Nonce") {
            let _ = self.nonce.insert(nonce);
        }
        Ok(response)
    }
    /// If `self.nonce` exists, deletes and returns it;
    /// if there is no `nonce`, fetches a new one and returns it.
    async fn take_nonce(&mut self) -> Result<String> {
        match self.nonce.take() {
            Some(nonce) => Ok(nonce),
            None => self.fetch_new_nonce().await,
        }
    }
    /// Fetches a new `nonce` from the server.
    async fn fetch_new_nonce(&self) -> Result<String> {
        let request = HttpRequest {
            method: Method::Get,
            headers: vec![],
            url: self.directory.new_nonce.clone(),
            body: vec![],
        };
        let response = self.fetcher.fetch(request).await?;
        find_header(&response, "Replay-Nonce")
    }
}

pub fn find_header(response: &HttpResponse, header_name: &str) -> Result<String> {
    response
        .headers
        .iter()
        .find_map(|(name, value)| {
            if name.eq_ignore_ascii_case(header_name) {
                Some(value.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("The response header does not contain {}", header_name))
}

/// Parses response body as JSON of type `T`.
pub fn parse_response_body<'a, T: Deserialize<'a>>(response: &'a HttpResponse) -> Result<T> {
    serde_json::from_slice(&response.body).map_err(|e| {
        let msg = if let Ok(s) = String::from_utf8(response.body.clone()) {
            format!("Body contains text: {}", s)
        } else {
            format!("Body contains bytes: {:?}", response.body)
        };
        Error::new(e)
            .context(format!(
                "Failed to parse response body into type {}",
                std::any::type_name::<T>()
            ))
            .context(msg)
    })
}
