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

use super::directory::Directory;
use crate::crypto::EcPublicKey;
use crate::fetcher::Fetcher;
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::signature::Signer;
use anyhow::{anyhow, Result};
use serde::Serialize;

pub struct Client<F: Fetcher, S: Signer> {
    pub public_key: EcPublicKey,
    pub directory: Directory,
    nonce: Option<String>,
    fetcher: F,
    signer: S,
}

#[derive(PartialEq, Eq)]
pub enum AuthMethod<'a> {
    JsonWebKey,
    KeyId(&'a str),
}

impl<F: Fetcher, S: Signer> Client<F, S> {
    pub async fn new(
        directory_url: &str,
        public_key: EcPublicKey,
        fetcher: F,
        signer: S,
    ) -> Result<Self> {
        let directory = Directory::new(directory_url, &fetcher).await?;
        Ok(Client {
            public_key,
            directory,
            nonce: None,
            fetcher,
            signer,
        })
    }
    pub async fn post_as_get(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
    ) -> Result<HttpResponse> {
        let payload: Option<()> = None;
        self.post_impl(auth_method, url, payload).await
    }
    pub async fn post_with_payload<P: Serialize>(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
        payload: P,
    ) -> Result<HttpResponse> {
        self.post_impl(auth_method, url, Some(payload)).await
    }
    async fn post_impl<P: Serialize>(
        &mut self,
        auth_method: AuthMethod<'_>,
        url: String,
        payload: Option<P>,
    ) -> Result<HttpResponse> {
        let nonce = self.take_nonce().await?;
        let (jwk, key_id) = match auth_method {
            AuthMethod::JsonWebKey => (Some(&self.public_key), None),
            AuthMethod::KeyId(key_id) => (None, Some(key_id)),
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
    async fn take_nonce(&mut self) -> Result<String> {
        match self.nonce.take() {
            Some(nonce) => Ok(nonce),
            None => self.fetch_new_nonce().await,
        }
    }
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
