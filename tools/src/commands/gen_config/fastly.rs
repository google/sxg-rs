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

use super::{read_certificate_pem_file, Artifact, SxgCertConfig};
use crate::linux_commands::execute_and_parse_stdout;
use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;
use sxg_rs::config::Config as SxgConfig;

#[derive(Debug, Deserialize, Serialize)]
pub struct FastlySpecificInput {
    pub service_name: String,
    pub sxg_private_key_base64: String,
}

/// The format of `fastly.toml`, which is written by `sxg_rs::gen_config`
/// and is read by the command `fastly compute publish`.
/// https://developer.fastly.com/reference/compute/fastly-toml/
#[derive(Serialize)]
struct FastlyManifest {
    name: String,
    authors: Vec<String>,
    service_id: String,
    language: &'static str,
    manifest_version: u8,
}

const OUTPUT_FILE: &str = "fastly_compute/fastly.toml";

/// The name of Fastly dictionary to be used as worker's runtime storage.
const DICTIONARY_NAME: &str = "config";

/// If `text` matches regular expression `re`, returns caputuring groups.
/// `groups[0]` is the whole thing, and actual caputuring groups begins at `groups[1]`.
fn capture_regex_groups<'a, 'b>(text: &'a str, re: &'b str) -> Result<Vec<Option<&'a str>>> {
    let re = Regex::new(re)?;
    let captures = re
        .captures(text)
        .ok_or_else(|| anyhow!(r#"Text "{}" does not match regex "{}""#, text, re))?;
    let groups: Vec<_> = captures
        .iter()
        .into_iter()
        .map(|x| Some(x?.as_str()))
        .collect();
    Ok(groups)
}

/// Create a Fastly service by
/// [CLI](https://developer.fastly.com/reference/cli/service/create/).
fn create_service(name: &str) -> Result<String> {
    let stdout = execute_and_parse_stdout(
        Command::new("fastly")
            .arg("service")
            .arg("create")
            .arg("--type")
            .arg("wasm")
            .arg("--name")
            .arg(name),
    )?;
    let captures = capture_regex_groups(&stdout, r"Created service (\w+)\n")?;
    let service_id = captures[1].unwrap().to_string();
    println!("Successfully created Fastly service {}", service_id);
    Ok(service_id)
}

/// Create a Fastly dictionary by
/// [CLI](https://developer.fastly.com/reference/cli/dictionary/create/).
fn create_dictionary(service_id: &str, dictionary_name: &str, write_only: bool) -> Result<()> {
    execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary")
            .arg("create")
            .arg("--service-id")
            .arg(service_id)
            .arg("--version")
            .arg("latest")
            .arg("--name")
            .arg(dictionary_name)
            .arg("--write-only")
            .arg(format!("{}", write_only)),
    )?;
    Ok(())
}

/// Find a Fastly dictionary by
/// [CLI](https://developer.fastly.com/reference/cli/dictionary/list/).
fn find_dictionary_id(service_id: &str, dictionary_name: &str) -> Result<String> {
    let stdout = execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary")
            .arg("list")
            .arg("--service-id")
            .arg(service_id)
            .arg("--version")
            .arg("latest"),
    )?;
    let captures =
        capture_regex_groups(&stdout, &format!(r"ID: (\w+)\nName: {}", dictionary_name))?;
    Ok(captures[1].unwrap().to_string())
}

/// Add a key-value pair to Fastly dicitonary by
/// [CLI](https://developer.fastly.com/reference/cli/dictionary-item/create/).
pub fn create_dictionary_item(
    service_id: &str,
    dictionary_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary-item")
            .arg("create")
            .arg("--service-id")
            .arg(service_id)
            .arg("--dictionary-id")
            .arg(dictionary_id)
            .arg("--key")
            .arg(key)
            .arg("--value")
            .arg(value),
    )?;
    Ok(())
}

pub fn update_dictionary_item(
    service_id: &str,
    dictionary_id: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    execute_and_parse_stdout(
        Command::new("fastly")
            .arg("dictionary-item")
            .arg("update")
            .arg("--service-id")
            .arg(service_id)
            .arg("--dictionary-id")
            .arg(dictionary_id)
            .arg("--key")
            .arg(key)
            .arg("--value")
            .arg(value),
    )?;
    Ok(())
}

pub fn main(
    use_ci_mode: bool,
    sxg_input: &SxgConfig,
    cert_input: &SxgCertConfig,
    fastly_input: &FastlySpecificInput,
    artifact: &mut Artifact,
) -> Result<()> {
    let mut sxg_input = sxg_input.clone();
    sxg_input.private_key_base64 = Some(fastly_input.sxg_private_key_base64.clone());
    let service_id = if use_ci_mode {
        println!("Skipping serivce creation, because --use-ci-mode is set.");
        "foo".to_string()
    } else {
        let service_id = create_service(&fastly_input.service_name)?;
        artifact.fastly_service_id = Some(service_id.clone());
        create_dictionary(&service_id, DICTIONARY_NAME, false)?;
        let dictionary_id = find_dictionary_id(&service_id, DICTIONARY_NAME)?;
        artifact.fastly_dictionary_id = Some(dictionary_id.clone());
        create_dictionary_item(
            &service_id,
            &dictionary_id,
            "sxg-config-input",
            &serde_json::to_string(&sxg_input)?,
        )?;
        match &cert_input {
            SxgCertConfig::PreIssued {
                cert_file,
                issuer_file,
            } => {
                create_dictionary_item(
                    &service_id,
                    &dictionary_id,
                    "cert-pem",
                    &read_certificate_pem_file(cert_file)?,
                )?;
                create_dictionary_item(
                    &service_id,
                    &dictionary_id,
                    "issuer-pem",
                    &read_certificate_pem_file(issuer_file)?,
                )?;
            }
            SxgCertConfig::CreateAcmeAccount(_) => {}
        };
        service_id
    };
    let fastly_manifest = FastlyManifest {
        name: fastly_input.service_name.clone(),
        service_id,
        authors: vec![],
        language: "rust",
        manifest_version: 1,
    };

    std::fs::write(
        OUTPUT_FILE,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please note that anything you modify won't be preserved\n\
            # at the next time you run \"cargo run -p tools -- -gen-config\".\n\
            {}",
            toml::to_string_pretty(&fastly_manifest)?
        ),
    )?;
    println!("Successfully wrote config to {}", OUTPUT_FILE);
    Ok(())
}
