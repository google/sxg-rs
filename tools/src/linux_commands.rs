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

use anyhow::{Error, Result};
use std::process::Command;

/// Executes a command, and returns the stdout as bytes.
fn execute(command: &mut Command) -> Result<Vec<u8>> {
    let output = command
        .output()
        .map_err(|e| Error::new(e).context("Failed to execute command"))?;
    Ok(output.stdout)
}

/// Executes a command, and parses the stdout as a string.
fn execute_and_parse_stdout(command: &mut Command) -> Result<String> {
    let stdout = execute(command)?;
    String::from_utf8(stdout)
        .map_err(|e| Error::new(e).context("The stdout contains non-utf8 bytes."))
}

pub fn create_private_key_pem() -> Result<String> {
    execute_and_parse_stdout(Command::new("openssl").args(&[
        "ecparam",
        "-outform",
        "pem",
        "-name",
        "prime256v1",
        "-genkey",
    ]))
}

pub fn get_public_key_pem(certificate_file: &str) -> Result<String> {
    execute_and_parse_stdout(Command::new("openssl").args(&[
        "x509",
        "-pubkey",
        "-noout",
        "-in",
        certificate_file,
    ]))
}

pub fn create_certificate_request_pem(domain: &str, private_key_file: &str) -> Result<String> {
    execute_and_parse_stdout(Command::new("openssl").args(&[
        "req",
        "-new",
        "-sha256",
        "-key",
        private_key_file,
        "-subj",
        &format!("/CN={}/O=Test/C=US", domain),
    ]))
}

pub fn create_certificate(
    private_key_file: &str,
    certificiate_request_file: &str,
    ext_file: &str,
) -> Result<String> {
    execute_and_parse_stdout(Command::new("openssl").args(&[
        "x509",
        "-req",
        "-days",
        "90",
        "-in",
        certificiate_request_file,
        "-signkey",
        private_key_file,
        "-extfile",
        ext_file,
    ]))
}
