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

use crate::linux_commands::{execute, execute_and_parse_stdout};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::process::Command;
use sxg_rs::signature::{Format as SignatureFormat, Signer};

#[derive(Debug)]
pub enum OpensslSigner<'a> {
    Hmac(&'a [u8]),
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl<'a> Signer for OpensslSigner<'a> {
    async fn sign(&self, message: &[u8], format: SignatureFormat) -> Result<Vec<u8>> {
        let tmp_file = execute_and_parse_stdout(&mut Command::new("mktemp"))?;
        let tmp_file = tmp_file.trim();
        std::fs::write(tmp_file, message)?;
        match self {
            OpensslSigner::Hmac(private_key) => {
                let hexkey = private_key
                    .iter()
                    .map(|x| format!("{:02x}", x))
                    .collect::<Vec<_>>()
                    .join("");
                let sig = execute(
                    Command::new("openssl")
                        .arg("dgst")
                        .arg("-sha256")
                        .arg("-mac")
                        .arg("HMAC")
                        .arg("-binary")
                        .arg("-macopt")
                        .arg(format!("hexkey:{}", hexkey))
                        .arg(tmp_file),
                )
                .map_err(|e| e.context("Failed to use openssl to create HMAC"))?;
                match format {
                    SignatureFormat::Raw => Ok(sig),
                    SignatureFormat::EccAsn1 => {
                        Err(anyhow!("HMAC signature can't be formatted as EccAsn1."))
                    }
                }
            }
        }
    }
}
