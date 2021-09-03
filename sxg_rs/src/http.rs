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

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct HttpRequest {
    pub body: Vec<u8>,
    pub headers: HeaderFields,
    pub method: Method,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub headers: HeaderFields,
    pub status: u16,
}

pub type HeaderFields = Vec<(String, String)>;

#[derive(Serialize)]
pub enum Method {
    Get,
    Post,
}
