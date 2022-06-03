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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// This struct is source-of-truth of the sxg config. The user need to create
// a file (like `config.yaml`) to provide this config input.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub cert_url_dirname: String,
    pub forward_request_headers: BTreeSet<String>,
    pub html_host: String,
    // This field is only needed by Fastly, because Cloudflare uses secret
    // env variables to store private key.
    // TODO: check if Fastly edge dictionary is ok to store private key.
    pub private_key_base64: Option<String>,
    pub reserved_path: String,
    pub strip_request_headers: BTreeSet<String>,
    pub strip_response_headers: BTreeSet<String>,
    pub validity_url_dirname: String,
}

impl Config {
    pub fn normalize(&mut self) {
        self.cert_url_dirname = to_url_prefix(&self.cert_url_dirname);
        lowercase_all(&mut self.forward_request_headers);
        self.reserved_path = to_url_prefix(&self.reserved_path);
        lowercase_all(&mut self.strip_request_headers);
        lowercase_all(&mut self.strip_response_headers);
        self.validity_url_dirname = to_url_prefix(&self.validity_url_dirname);
    }
    /// Creates config from text
    pub fn new(input_yaml: &str) -> Result<Self> {
        let mut input: Self = serde_yaml::from_str(input_yaml)?;
        input.normalize();
        Ok(input)
    }
}

fn lowercase_all(names: &mut BTreeSet<String>) {
    let old_names = std::mem::take(names);
    *names = old_names
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
}

fn to_url_prefix(dirname: &str) -> String {
    format!("/{}/", dirname.trim_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn processes_input() {
        let yaml = r#"
cert_url_dirname: ".well-known/sxg-certs/"
forward_request_headers:
  - "cf-IPCOUNTRY"
  - "USER-agent"
html_host: my_domain.com
reserved_path: ".sxg"
respond_debug_info: false
strip_request_headers: ["Forwarded"]
strip_response_headers: ["Set-Cookie", "STRICT-TRANSPORT-SECURITY"]
validity_url_dirname: "//.well-known/sxg-validity"
        "#;
        let config = Config::new(yaml).unwrap();
        assert_eq!(config.cert_url_dirname, "/.well-known/sxg-certs/");
        assert_eq!(
            config.forward_request_headers,
            ["cf-ipcountry", "user-agent"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
        assert_eq!(config.html_host, "my_domain.com".to_string());
        assert_eq!(
            config.strip_request_headers,
            ["forwarded"].iter().map(|s| s.to_string()).collect()
        );
        assert_eq!(
            config.strip_response_headers,
            ["set-cookie", "strict-transport-security"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
        assert_eq!(config.reserved_path, "/.sxg/");
        assert_eq!(config.validity_url_dirname, "/.well-known/sxg-validity/");
    }
}
