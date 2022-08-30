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

use super::{read_certificate_pem_file, SxgCertConfig};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sxg_rs::config::Config as SxgConfig;
use tools::Artifact;
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Debug, Deserialize, Serialize)]
pub struct CloudlareSpecificInput {
    pub account_id: String,
    pub zone_id: String,
    pub routes: Vec<String>,
    pub worker_name: String,
    pub deploy_on_workers_dev_only: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVars {
    html_host: String,
    sxg_config: String,
    cert_pem: Option<String>,
    issuer_pem: Option<String>,
    acme_account: Option<String>,
}

// TODO: Use `wrangler::settings::toml::Triggers`
// after [this PR](https://github.com/cloudflare/wrangler/pull/2259)
// is deployed to the latest `wrangler` version.
#[derive(Deserialize, Serialize)]
pub struct Triggers {
    pub crons: Vec<String>,
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
    triggers: Option<Triggers>,
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
    println!("Successful login to Cloudflare");
    user
}

const STORAGE_NAME: &str = "OCSP";
// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    if let Some(namespace) = namespaces.into_iter().find(|n| n.title == STORAGE_NAME) {
        return namespace.id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, STORAGE_NAME)
        .unwrap()
        .result;
    namespace.id
}

fn create_wrangler_secret_instruction(name: &str, value: &str) -> String {
    let base64_value = base64::encode(value);
    format!(
        "echo {} | openssl enc -base64 -d | wrangler secret put {}",
        base64_value, name
    )
}

const WRANGLER_TOML: &str = "cloudflare_worker/wrangler.toml";

pub fn main(
    use_ci_mode: bool,
    sxg_input: &SxgConfig,
    cert_input: &SxgCertConfig,
    cloudflare_input: &CloudlareSpecificInput,
    artifact: &mut Artifact,
) -> Result<()> {
    if artifact.cloudflare_kv_namespace_id.is_none() {
        if use_ci_mode {
            println!("Skipping KV namespace creation, because --use-ci-mode is set.")
        } else {
            let user = get_global_user();
            artifact.cloudflare_kv_namespace_id =
                Some(get_ocsp_kv_id(&user, &cloudflare_input.account_id))
        }
    }
    let mut wrangler_vars = WranglerVars {
        html_host: sxg_input.html_host.clone(),
        sxg_config: serde_yaml::to_string(&sxg_input)?,
        ..Default::default()
    };
    match &cert_input {
        SxgCertConfig::PreIssued {
            cert_file,
            issuer_file,
        } => {
            wrangler_vars.cert_pem = Some(read_certificate_pem_file(cert_file)?);
            wrangler_vars.issuer_pem = Some(read_certificate_pem_file(issuer_file)?);
        }
        SxgCertConfig::CreateAcmeAccount(_) => {
            artifact.acme_private_key_instructions.insert(
                "cloudflare".to_string(),
                create_wrangler_secret_instruction(
                    "ACME_PRIVATE_KEY_JWK",
                    &serde_json::to_string(&artifact.acme_private_key)?,
                ),
            );
            wrangler_vars.acme_account = Some(serde_json::to_string(&artifact.acme_account)?);
        }
    };
    let mut routes = cloudflare_input.routes.clone();
    routes.extend(vec![
        format!("{}/.well-known/sxg-certs/*", sxg_input.html_host),
        format!("{}/.well-known/sxg-validity/*", sxg_input.html_host),
        format!("{}/.well-known/acme-challenge/*", sxg_input.html_host),
    ]);
    let wrangler_toml_output = WranglerManifest {
        name: cloudflare_input.worker_name.clone(),
        target_type: "rust".to_string(),
        account_id: cloudflare_input.account_id.clone(),
        zone_id: cloudflare_input.zone_id.clone(),
        routes,
        kv_namespaces: vec![ConfigKvNamespace {
            binding: STORAGE_NAME.to_string(),
            id: artifact
                .cloudflare_kv_namespace_id
                .clone()
                .or_else(|| Some("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string())),
            preview_id: None,
        }],
        workers_dev: Some(cloudflare_input.deploy_on_workers_dev_only),
        vars: wrangler_vars,
        triggers: Some(Triggers {
            crons: vec![
                // The syntax is at https://developers.cloudflare.com/workers/platform/cron-triggers
                // This triggers at every minute.
                "* * * * *".to_string(),
            ],
        }),
    };

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
