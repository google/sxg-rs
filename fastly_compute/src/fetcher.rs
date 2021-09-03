// Copyright 2021 Google LLC
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

use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use fastly::{Request as FastlyRequest, Response as FastlyResponse};
use std::io::Read;
use sxg_rs::{
    fetcher::Fetcher,
    http::{HttpRequest, HttpResponse, Method},
};

/// A [`Fetcher`] implemented by
/// [Fastly backend](https://developer.fastly.com/reference/api/services/backend/).
pub struct FastlyFetcher {
    backend_name: &'static str,
}

impl FastlyFetcher {
    /// Constructs a new `FastlyFetcher` from the backend name.
    /// This function does not create the backend in Fastly;
    /// the Fastly backend need to be created via Fastly API
    /// before calling this function.
    pub fn new(backend_name: &'static str) -> Self {
        FastlyFetcher {
            backend_name: backend_name,
        }
    }
}

#[async_trait(?Send)]
impl Fetcher for FastlyFetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse> {
        let request = from_http_request(request);
        let response: FastlyResponse = request
            .send(self.backend_name)
            .map_err(|e| Error::new(e).context("Failed to fetch from backend."))?;
        into_http_response(response)
    }
}

fn from_http_request(http_request: HttpRequest) -> FastlyRequest {
    let method = match http_request.method {
        Method::Get => "GET",
        Method::Post => "POST",
    };
    let mut fastly_request = FastlyRequest::new(method, http_request.url);
    for (name, value) in http_request.headers {
        fastly_request.append_header(name, value)
    }
    fastly_request.set_body(http_request.body);
    fastly_request
}

pub fn from_http_response(input: HttpResponse) -> FastlyResponse {
    let mut output = FastlyResponse::new();
    output.set_status(input.status);
    for (name, value) in input.headers {
        output.append_header(name, value)
    }
    output.set_body(input.body);
    output
}

fn into_http_response(response: FastlyResponse) -> Result<HttpResponse> {
    let mut header_fields = vec![];
    for name in response.get_header_names() {
        for value in response.get_header_all(name) {
            let value = value.to_str().map_err(|_| {
                Error::msg(format!(r#"Header "{}" contains non-ASCII value."#, name))
            })?;
            header_fields.push((name.as_str().to_string(), value.to_string()));
        }
    }
    let status = response.get_status().as_u16();
    let mut body_bytes = vec![];
    const MAX_BYTES: usize = 8_000_000;
    response
        .into_body()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut body_bytes)?;
    if body_bytes.len() > MAX_BYTES {
        return Err(anyhow!("Body is larger than {} bytes.", MAX_BYTES))
    }
    Ok(HttpResponse {
        body: body_bytes,
        headers: header_fields,
        status,
    })
}
