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
use serde::{Deserialize, Serialize};

// This struct is source-of-truth of the sxg config. The user need to create
// a file (like `config.yaml`) to provide this config input.
#[derive(Deserialize, Serialize)]
pub struct ConfigInput {
    pub cert_url_basename: String,
    pub forward_request_headers: HashSet<String>,
    pub html_host: String,
    // This field is only needed by Fastly, because Cloudflare uses secret
    // env variables to store private key.
    // TODO: check if Fastly edge dictionary is ok to store private key.
    #[serde(default)]
    pub private_key_base64: String,
    pub reject_stateful_headers: bool,
    pub reserved_path: String,
    pub respond_debug_info: bool,
    pub validity_url_basename: String,
    pub worker_host: String,
}

// This contains not only source-of-truth ConfigInput, but also a few more
// attributes which are computed from ConfigInput.
pub struct Config {
    input: ConfigInput,
    pub cert_der: Vec<u8>,
    pub cert_url: String,
    pub issuer_der: Vec<u8>,
    pub validity_url: String,
}

impl std::ops::Deref for Config {
    type Target = ConfigInput;
    #[must_use]
    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl Config {
    pub fn new(input_yaml: &str, cert_pem: &str, issuer_pem: &str) -> Self {
        let input: ConfigInput = serde_yaml::from_str(input_yaml).unwrap();
        let cert_der = get_der(cert_pem, "CERTIFICATE");
        let issuer_der = get_der(issuer_pem, "CERTIFICATE");
        let cert_url = create_url(&input.worker_host, &input.reserved_path, &input.cert_url_basename);
        let validity_url = create_url(&input.html_host, &input.reserved_path, &input.validity_url_basename);
        Config {
            cert_der,
            cert_url,
            input,
            issuer_der,
            validity_url,
        }
    }
}

fn get_der(pem_text: &str, expected_tag: &str) -> Vec<u8> {
    for pem in ::pem::parse_many(pem_text) {
        if pem.tag == expected_tag {
            return pem.contents;
        }
    }
    panic!("The PEM file does not contains the expected block");
}

fn create_url(host: &str, reserved_path: &str, basename: &str) -> String {
    let reserved_path = reserved_path.trim_matches('/');
    let basename = basename.trim_start_matches('/');
    format!("https://{}/{}/{}", host, reserved_path, basename)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create_url() {
        assert_eq!(create_url("foo.com", ".sxg", "cert"), "https://foo.com/.sxg/cert");
        assert_eq!(create_url("foo.com", "/.sxg", "cert"), "https://foo.com/.sxg/cert");
        assert_eq!(create_url("foo.com", ".sxg/", "cert"), "https://foo.com/.sxg/cert");
        assert_eq!(create_url("foo.com", "/.sxg/", "cert"), "https://foo.com/.sxg/cert");
        assert_eq!(create_url("foo.com", "/.sxg/", "/cert"), "https://foo.com/.sxg/cert");
    }
}
