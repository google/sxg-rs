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

use std::collections::HashSet;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    #[serde(skip_deserializing)]
    pub cert_url: String,
    pub forward_request_headers: HashSet<String>,
    pub html_host: String,
    pub reject_stateful_headers: bool,
    pub respond_debug_info: bool,
    #[serde(skip_deserializing)]
    pub validity_url: String,
    pub worker_host: String,
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    let input = include_str!("../config.yaml");
    let mut config: Config = serde_yaml::from_str(&input).unwrap();
    config.cert_url = format!("https://{}/cert", config.worker_host);
    config.validity_url = format!("https://{}/.sxg_validity", config.html_host);
    config
});

pub struct Asset {
    pub cert_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
}

pub static ASSET: Lazy<Asset> = Lazy::new(|| {
    Asset {
        cert_der: get_der(include_str!("../certs/cert.pem"), "CERTIFICATE"),
        issuer_der: get_der(include_str!("../certs/issuer.pem"), "CERTIFICATE"),
    }
});

fn get_der(pem_text: &str, expected_tag: &str) -> Vec<u8> {
    for pem in ::pem::parse_many(pem_text) {
        if pem.tag == expected_tag {
            return pem.contents;
        }
    }
    panic!("The PEM file does not contains the expected block");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        &*ASSET;
        &*CONFIG;
    }
}
