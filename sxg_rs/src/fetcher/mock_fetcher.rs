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

//! A ['Fetcher`] returning pre-defined responses, to be used in unit testing.

use super::Fetcher;
use crate::http::{HttpRequest, HttpResponse};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::{mpsc, Mutex},
    time::timeout,
};

pub struct MockFetcher {
    request_sender: mpsc::Sender<HttpRequest>,
    response_receiver: Arc<Mutex<mpsc::Receiver<HttpResponse>>>,
    time_limit: Duration,
}

pub struct MockServer {
    request_receiver: mpsc::Receiver<HttpRequest>,
    response_sender: mpsc::Sender<HttpResponse>,
    time_limit: Duration,
}

pub fn create() -> (MockFetcher, MockServer) {
    let (request_sender, request_receiver) = mpsc::channel(1);
    let (response_sender, response_receiver) = mpsc::channel(1);
    let mock_fetcher = MockFetcher {
        request_sender,
        response_receiver: Arc::new(Mutex::new(response_receiver)),
        time_limit: Duration::from_secs(1),
    };
    let mock_server = MockServer {
        request_receiver,
        response_sender,
        time_limit: Duration::from_secs(1),
    };
    (mock_fetcher, mock_server)
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Fetcher for MockFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request_url = request.url.clone();
        self.request_sender.send(request).await?;
        timeout(self.time_limit, self.response_receiver.lock().await.recv())
            .await
            .map_err(|_e| {
                anyhow!(
                    "Failed to get response for URL \"{}\" within time limit, \
                    did you set up \"handle_next_request\" on the MockServer side?",
                    request_url,
                )
            })?
            .ok_or_else(|| anyhow!("No more message"))
    }
}

impl MockServer {
    pub async fn handle_next_request(
        &mut self,
        expected_request: HttpRequest,
        response: HttpResponse,
    ) -> Result<()> {
        let actual_request = timeout(self.time_limit, self.request_receiver.recv())
            .await
            .map_err(|_e| {
                anyhow!(
                    "Failed to get request for URL \"{}\" within time limit, \
                did you call \"fetch\" on the MockFetcher side?",
                    &expected_request.url,
                )
            })?;
        if actual_request.as_ref() != Some(&expected_request) {
            return Err(anyhow!(
                "Actual {:?}\n Expected {:?}",
                actual_request,
                expected_request
            ));
        }
        self.response_sender.send(response).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::get;
    use super::*;
    // The server side calls `handle_next_request` for each `fetch` at client
    // side.
    #[tokio::test]
    async fn it_works() {
        let (fetcher, mut server) = create();
        let server_thread = async {
            let expected_request = HttpRequest {
                body: vec![],
                method: crate::http::Method::Get,
                headers: vec![],
                url: "https://foo.com/1".to_string(),
            };
            let response = HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![1, 2, 3],
            };
            server
                .handle_next_request(expected_request, response)
                .await
                .unwrap();

            let expected_request = HttpRequest {
                body: vec![],
                method: crate::http::Method::Get,
                headers: vec![],
                url: "https://foo.com/2".to_string(),
            };
            let response = HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![7, 8, 9],
            };
            server
                .handle_next_request(expected_request, response)
                .await
                .unwrap();
        };
        let client_thread = async {
            assert_eq!(
                get(&fetcher, "https://foo.com/1").await.unwrap(),
                vec![1, 2, 3]
            );
            assert_eq!(
                get(&fetcher, "https://foo.com/2").await.unwrap(),
                vec![7, 8, 9]
            );
        };
        tokio::join!(server_thread, client_thread);
    }
    // In the case client side actual request does not match against server
    // side expected request, both server and client will get an error.
    #[tokio::test]
    async fn req_mismatch() {
        let (fetcher, mut server) = create();
        let server_thread = async {
            let expected_request = HttpRequest {
                body: vec![],
                method: crate::http::Method::Get,
                headers: vec![],
                url: "https://foo.com".to_string(),
            };
            let response = HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![1, 2, 3],
            };
            assert!(server
                .handle_next_request(expected_request, response)
                .await
                .is_err());
        };
        let client_thread = async { assert!(get(&fetcher, "https://bar.com").await.is_err()) };
        tokio::join!(server_thread, client_thread);
    }
}
