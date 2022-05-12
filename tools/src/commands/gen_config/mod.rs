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
use clap::Parser;
use serde::{Deserialize, Serialize};
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Debug, Parser)]
pub struct Opts {
    /// A YAML file containing all config values.
    /// You can use the template
    /// 'tools/src/commands/gen_config/input.example.yaml'.
    #[clap(long, value_name = "FILE_NAME")]
    input: String,
    /// A YAML file containing the generated values.
    #[clap(long, value_name = "FILE_NAME")]
    artifact: String,
    /// No longer log in to worker service providers.
    #[clap(long)]
    use_ci_mode: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    domain_name: String,
    sxg_worker: sxg_rs::config::Config,
    certificates: SxgCertConfig,
    cloudflare: CloudlareSpecificInput,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SxgCertConfig {
    PreIssued {
        cert_file: String,
        issuer_file: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CloudlareSpecificInput {
    account_id: String,
    zone_id: String,
    worker_name: String,
    deploy_on_workers_dev_only: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Artifact {
    cloudflare_kv_namespace_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVars {
    html_host: String,
    sxg_config: String,
    cert_pem: Option<String>,
    issuer_pem: Option<String>,
}

// TODO: Use `wrangler::settings::toml::Manifest`
// after [this issue](https://github.com/cloudflare/wrangler/issues/2037)
// is resolved.
#[derive(Deserialize, Serialize)]
struct WranglerManifest {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    workers_dev: Option<bool>,
    kv_namespaces: Vec<ConfigKvNamespace>,
    vars: WranglerVars,
}

// Set working directory to the root folder of the "sxg-rs" repository.
fn goto_repository_root() -> Result<(), std::io::Error> {
    let exe_path = std::env::current_exe()?;
    assert!(exe_path.ends_with("target/debug/tools"));
    let repo_root = exe_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_current_dir(repo_root)?;
    Ok(())
}

// Get the Cloudflare user.
// If there is no active user, the terminal will display a login link.
// This function will wait for the login process before returning.
fn get_global_user() -> GlobalUser {
    println!("Checking Cloudflare login state");
    let mut user = GlobalUser::new();
    if user.is_err() {
        wrangler::login::run(None).unwrap();
        user = GlobalUser::new();
    }
    let user = user.unwrap();
    println!("Successfully login to Cloudflare");
    user
}

// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    if let Some(namespace) = namespaces.into_iter().find(|n| n.title == "sxg-OCSP") {
        return namespace.id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, "OCSP")
        .unwrap()
        .result;
    namespace.id
}

fn read_certificate_pem_file(path: &str) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| Error::msg(format!(r#"Failed to read file "{}""#, path)))?;
    // Translate Windows-style line endings to Unix-style so the '\r' is
    // not rendered in the toml. This is purely cosmetic; '\r' is deserialized
    // faithfully from toml and pem::parse_many is able to parse either style.
    let text = text.replace("\r\n", "\n");
    let certs = pem::parse_many(&text).map_err(Error::new)?;
    if certs.len() == 1 && certs[0].tag == "CERTIFICATE" {
        Ok(text)
    } else {
        Err(Error::msg(format!(
            r#"File "{}" is not a valid certificate PEM"#,
            path
        )))
    }
}

const WRANGLER_TOML: &str = "cloudflare_worker/wrangler.toml";

fn read_artifact(file_name: &str) -> Result<Artifact> {
    let file_content = std::fs::read_to_string(file_name)?;
    let artifact = serde_yaml::from_str(&file_content)?;
    Ok(artifact)
}

pub fn main(opts: Opts) -> Result<()> {
    if std::env::var("CI").is_ok() && !opts.use_ci_mode {
        println!("The environment variable $CI is set, but --use-ci-mode is not set.");
    }
    goto_repository_root()?;
    let mut input: Config = serde_yaml::from_str(&std::fs::read_to_string(&opts.input)?)?;
    let mut artifact: Artifact = read_artifact(&opts.artifact).unwrap_or_default();
    input.sxg_worker.html_host = input
        .sxg_worker
        .html_host
        .clone() // TODO: Remove this clone while keep Rust compiler happy.
        .or_else(|| Some(input.domain_name.clone()));
    if artifact.cloudflare_kv_namespace_id.is_none() {
        if opts.use_ci_mode {
            println!("Skipping KV namespace creation, because --use-ci-mode is set.")
        } else {
            let user = get_global_user();
            artifact.cloudflare_kv_namespace_id =
                Some(get_ocsp_kv_id(&user, &input.cloudflare.account_id))
        }
    }
    let mut wrangler_vars = WranglerVars {
        html_host: input.domain_name.clone(),
        sxg_config: serde_yaml::to_string(&input.sxg_worker)?,
        cert_pem: None,
        issuer_pem: None,
    };
    match &input.certificates {
        SxgCertConfig::PreIssued {
            cert_file,
            issuer_file,
        } => {
            wrangler_vars.cert_pem = Some(read_certificate_pem_file(cert_file)?);
            wrangler_vars.issuer_pem = Some(read_certificate_pem_file(issuer_file)?);
        }
    };
    let wrangler_toml_output = WranglerManifest {
        name: input.cloudflare.worker_name.clone(),
        target_type: "rust".to_string(),
        account_id: input.cloudflare.account_id.clone(),
        zone_id: input.cloudflare.zone_id.clone(),
        routes: vec![
            format!("{}/*", input.domain_name),
            format!("{}/.well-known/sxg-certs/*", input.domain_name),
            format!("{}/.well-known/sxg-validity/*", input.domain_name),
        ],
        kv_namespaces: vec![ConfigKvNamespace {
            binding: String::from("OCSP"),
            id: artifact
                .cloudflare_kv_namespace_id
                .clone()
                .or_else(|| Some("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string())),
            preview_id: None,
        }],
        workers_dev: Some(input.cloudflare.deploy_on_workers_dev_only),
        vars: wrangler_vars,
    };

    std::fs::write(
        &opts.artifact,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please do not modify.\n\
            {}",
            serde_yaml::to_string(&artifact)?
        ),
    )?;

    std::fs::write(
        WRANGLER_TOML,
        format!(
            "# This file is generated by command \"cargo run -p tools -- gen-config\".\n\
            # Please note that anything you modify won't be preserved\n\
            # at the next time you run \"cargo run -p tools -- -gen-config\".\n\
            {}",
            toml::to_string_pretty(&wrangler_toml_output)?
        ),
    )?;
    println!("Successfully wrote config to {}", WRANGLER_TOML);
    Ok(())
}
