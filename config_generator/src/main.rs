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

use dialoguer::Input;
use serde::{Deserialize, Serialize};
use sxg_rs::config::ConfigInput as SxgConfig;
use wrangler::settings::global_user::GlobalUser;
use wrangler::settings::toml::ConfigKvNamespace;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVars {
    sxg_config: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    issuer_pem: String,
}

// TODO: Use `wrangler::settings::toml::Manifest`
// after [this issue](https://github.com/cloudflare/wrangler/issues/2037)
// is resolved.
#[derive(Deserialize, Serialize)]
struct WranglerConfig {
    name: String,
    #[serde(rename = "type")]
    target_type: String,
    account_id: String,
    zone_id: String,
    routes: Vec<String>,
    kv_namespaces: Vec<ConfigKvNamespace>,
    vars: WranglerVars,
}

// Set working directory to the root folder of the "sxg-rs" repository.
fn goto_repository_root() -> Result<(), std::io::Error> {
    let exe_path = std::env::current_exe()?;
    assert!(exe_path.ends_with("target/debug/config-generator"));
    let repo_root = exe_path.parent().unwrap().parent().unwrap().parent().unwrap();
    std::env::set_current_dir(repo_root)?;
    Ok(())
}

// Get the Cloudflare user.
// If there is no active user, the terminal will display a login link.
// This function will wait for the login process before returning.
fn get_global_uesr() -> GlobalUser {
    println!("Checking Cloudflare login state");
    let mut user = GlobalUser::new();
    if user.is_err() {
        wrangler::login::run().unwrap();
        user = GlobalUser::new();
    }
    let user = user.unwrap();
    println!("Successfully login to Cloudflare");
    user
}

// Get the ID of the KV namespace for OCSP.
// If there is no such KV namespace, one will be created.
fn get_ocsp_kv_id(user: &GlobalUser, account_id: &str) -> String {
    let client = wrangler::http::cf_v4_client(&user).unwrap();
    let target: wrangler::settings::toml::Target = Default::default();
    let namespaces = wrangler::kv::namespace::list(&client, &target).unwrap();
    let exsiting_id = namespaces.into_iter().find_map(|namespace| {
        if namespace.title == "sxg-OCSP" {
            Some(namespace.id)
        } else {
            None
        }
    });
    if let Some(id) = exsiting_id {
        return id;
    }
    let namespace = wrangler::kv::namespace::create(&client, account_id, "OCSP")
        .unwrap()
        .result;
    namespace.id
}

fn read_certificate_pem_file(path: &str) -> Result<String, String> {
    let text =
        std::fs::read_to_string(path).map_err(|_| format!(r#"Failed to read file "{}""#, path))?;
    let certs = pem::parse_many(&text);
    if certs.len() == 1 && certs[0].tag == "CERTIFICATE" {
        Ok(text)
    } else {
        Err(format!(r#"File "{}" is not a valid certificate PEM"#, path))
    }
}

const CONFIG_FILE: &'static str = "cloudflare_worker/wrangler.toml";
const CONFIG_EXAMPLE_FILE: &'static str = "cloudflare_worker/wrangler.example.toml";

// Read and parse `wrangler.toml`.
// `wrangler.example.toml` will be read if `wrangler.toml` does not exist.
// This function panics if `wrangler.toml` contains syntax error,
// even when a valid `wrangler.example.toml` exists.
fn read_exsiting_config() -> (WranglerConfig, SxgConfig) {
    let wrangler_config = std::fs::read_to_string(CONFIG_FILE)
        .or_else(|_| std::fs::read_to_string(CONFIG_EXAMPLE_FILE))
        .unwrap();
    let wrangler_config: WranglerConfig = toml::from_str(&wrangler_config).unwrap();
    let sxg_config: SxgConfig = serde_yaml::from_str(&wrangler_config.vars.sxg_config).unwrap();
    (wrangler_config, sxg_config)
}

fn main() -> Result<(), std::io::Error> {
    goto_repository_root()?;
    let (mut wrangler_config, mut sxg_config) = read_exsiting_config();
    loop {
        let cert = read_certificate_pem_file("credentials/cert.pem");
        let issuer = read_certificate_pem_file("credentials/issuer.pem");
        if cert.is_ok() && issuer.is_ok() {
            println!("Succesffuly read certificates");
            wrangler_config.vars.cert_pem = cert.unwrap();
            wrangler_config.vars.issuer_pem = issuer.unwrap();
            break;
        }
        if let Err(msg) = cert {
            println!("{}", msg);
        }
        if let Err(msg) = issuer {
            println!("{}", msg);
        }
        println!(
            "To generate certificates, please refer to\n\
            \thttps://github.com/google/sxg-rs/blob/main/credentials/README.md"
        );
        Input::<String>::new()
            .with_prompt("Press ENTER key after you generate the certificates")
            .allow_empty(true)
            .interact_text()
            .unwrap();
    }
    let user = get_global_uesr();
    wrangler_config.account_id = Input::new()
        .with_prompt("What's your Cloudflare account ID?")
        .with_initial_text(wrangler_config.account_id)
        .interact_text()
        .unwrap();
    wrangler_config.zone_id = Input::new()
        .with_prompt("What's your Cloudflare zone ID?")
        .with_initial_text(wrangler_config.zone_id)
        .interact_text()
        .unwrap();
    sxg_config.html_host = Input::new()
        .with_prompt("What's your domain registered in Cloudflare?")
        .with_initial_text(sxg_config.html_host)
        .validate_with(|s: &String| -> Result<(), url::ParseError> {
            url::Host::parse(s)?;
            Ok(())
        })
        .interact_text()
        .unwrap();
    sxg_config.worker_host = Input::new()
        .with_prompt("What's the domain of your Cloudflare worker?")
        .with_initial_text(sxg_config.worker_host)
        .validate_with(|s: &String| -> Result<(), url::ParseError> {
            url::Host::parse(s)?;
            Ok(())
        })
        .interact_text()
        .unwrap();
    // TODO: Allow user to customize routes
    wrangler_config.routes = vec![format!("{}/*", sxg_config.html_host)];
    let ocsp_kv_id = get_ocsp_kv_id(&user, &wrangler_config.account_id);
    wrangler_config.kv_namespaces = vec![ConfigKvNamespace {
        binding: String::from("OCSP"),
        id: Some(ocsp_kv_id),
        preview_id: None,
    }];
    wrangler_config.vars.sxg_config = serde_yaml::to_string(&sxg_config).unwrap();
    std::fs::write(
        CONFIG_FILE,
        toml::to_string_pretty(&wrangler_config).unwrap(),
    )?;
    println!("Succesfully write config to {}", CONFIG_FILE);
    Ok(())
}
