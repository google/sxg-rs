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

//! Serializable HTTP interfaces.
//! # Conversion
//! For interoperability with other Rust libraries, all structs can be coverted to and from the
//! corresponding types in [`http`] crate.

use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use std::convert::{Infallible, TryFrom, TryInto};

#[derive(Debug, Eq, PartialEq, Serialize, Clone)]
pub struct HttpRequest {
    pub body: Vec<u8>,
    pub headers: HeaderFields,
    pub method: Method,
    pub url: String,
}

impl TryFrom<::http::request::Request<Vec<u8>>> for HttpRequest {
    type Error = Error;
    fn try_from(input: ::http::request::Request<Vec<u8>>) -> Result<Self> {
        let (parts, body) = input.into_parts();
        Ok(HttpRequest {
            body,
            headers: try_from_header_map(parts.headers)?,
            method: parts.method.try_into()?,
            url: parts.uri.to_string(),
        })
    }
}

impl TryInto<::http::request::Request<Vec<u8>>> for HttpRequest {
    type Error = Error;
    fn try_into(self) -> Result<::http::request::Request<Vec<u8>>> {
        let mut output = ::http::request::Request::new(self.body);
        *output.headers_mut() = try_into_header_map(self.headers)?;
        *output.method_mut() = self.method.try_into()?;
        *output.uri_mut() = self.url.try_into()?;
        Ok(output)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub headers: HeaderFields,
    pub status: u16,
}

impl TryFrom<::http::response::Response<Vec<u8>>> for HttpResponse {
    type Error = Error;
    fn try_from(input: ::http::response::Response<Vec<u8>>) -> Result<Self> {
        let (parts, body) = input.into_parts();
        Ok(HttpResponse {
            body,
            headers: try_from_header_map(parts.headers)?,
            status: parts.status.as_u16(),
        })
    }
}

impl TryInto<::http::response::Response<Vec<u8>>> for HttpResponse {
    type Error = Error;
    fn try_into(self) -> Result<::http::response::Response<Vec<u8>>> {
        let mut output = ::http::response::Response::new(self.body);
        *output.headers_mut() = try_into_header_map(self.headers)?;
        *output.status_mut() = self.status.try_into()?;
        Ok(output)
    }
}

pub type HeaderFields = Vec<(String, String)>;

// The more readable way is to write
// ```
// impl TryFrom<::http::header::HeaderMap> for HeaderFields { ... }
// ```
// But compiler will throw error E0117 if do that.
// Because `HeaderFields` is a type alias, and we are not the author of `Vec<(String, String)>`.
fn try_from_header_map(input: ::http::header::HeaderMap) -> Result<HeaderFields> {
    let mut output = vec![];
    for (name, value) in input.iter() {
        let value = value.to_str().map_err(|e| {
            Error::new(e).context(format!("Header {} contains non-ASCII value", name))
        })?;
        output.push((name.to_string(), value.to_string()));
    }
    Ok(output)
}

// The more readable way is to write
// ```
// impl TryInto<::http::header::HeaderMap> for HeaderFields { ... }
// ```
// But compiler will throw error E0117 if do that.
// Because `HeaderFields` is a type alias, and we are not the author of `Vec<(String, String)>`.
fn try_into_header_map(input: HeaderFields) -> Result<::http::header::HeaderMap> {
    input
        .iter()
        .map(|(name, value)| -> Result<_> {
            let name =
                ::http::header::HeaderName::from_bytes(name.as_bytes()).map_err(Error::new)?;
            let value = ::http::header::HeaderValue::from_str(value).map_err(Error::new)?;
            Ok((name, value))
        })
        .collect()
}

#[derive(Debug, Eq, PartialEq, Serialize, Clone)]
pub enum Method {
    Get,
    Post,
}

impl TryFrom<::http::Method> for Method {
    type Error = Error;
    fn try_from(method: ::http::Method) -> Result<Self> {
        match method {
            ::http::Method::GET => Ok(Method::Get),
            ::http::Method::POST => Ok(Method::Post),
            x => Err(anyhow!("Method {} is not supported", x)),
        }
    }
}

impl TryInto<::http::Method> for Method {
    type Error = Infallible;
    fn try_into(self) -> Result<::http::Method, Self::Error> {
        match self {
            Method::Get => Ok(::http::Method::GET),
            Method::Post => Ok(::http::Method::POST),
        }
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &base64::encode(&self.body))
            .finish()
    }
}
