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

use anyhow::Result;
use clap::{ArgEnum, Parser};
use warp::Filter;

use crate::linux_commands::{create_certificate_request_pem, create_private_key_pem};

#[derive(ArgEnum, Clone, Debug, Parser)]
enum AcmeServer {
    LetsencryptStaging,
}

#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(long)]
    port: u16,
    #[clap(arg_enum, long)]
    server: AcmeServer,
    #[clap(long)]
    email: String,
    #[clap(long)]
    domain: String,
}

fn start_warp_server(port: u16, answer: String) -> tokio::sync::oneshot::Sender<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let routes =
        warp::path!(".well-known" / "acme-challenge" / String).map(move |_name| answer.to_string());
    let (_addr, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([127, 0, 0, 1], port), async {
            rx.await.ok();
        });
    tokio::spawn(server);
    tx
}

pub async fn main(opts: Opts) -> Result<()> {
    let server_directory_url = match opts.server {
        AcmeServer::LetsencryptStaging => sxg_rs::acme::directory::LETSENCRYPT_STAGING,
    };
    let acme_private_key = {
        let private_key_file = "acme_account_private_key.pem";
        let private_key_pem = create_private_key_pem(private_key_file)?;
        sxg_rs::crypto::EcPrivateKey::from_sec1_pem(&private_key_pem)?
    };
    let sxg_cert_request_der = {
        let private_key_file = "privkey.pem";
        let cert_request_file = "cert.csr";
        create_private_key_pem(private_key_file)?;
        let cert_request_pem =
            create_certificate_request_pem(&opts.domain, private_key_file, cert_request_file)?;
        sxg_rs::crypto::get_der_from_pem(&cert_request_pem, "CERTIFICATE REQUEST")?
    };
    let signer = acme_private_key.create_signer()?;
    let fetcher = sxg_rs::fetcher::hyper_fetcher::HyperFetcher::new();
    let ongoing_certificate_request = sxg_rs::acme::apply_certificate_and_get_challenge_answer(
        server_directory_url,
        &opts.email,
        &opts.domain,
        acme_private_key.public_key,
        sxg_cert_request_der,
        fetcher,
        signer,
    )
    .await?;
    let tx = start_warp_server(
        opts.port,
        ongoing_certificate_request.challenge_answer.clone(),
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let certificate_pem = sxg_rs::acme::continue_challenge_validation_and_get_certificate(
        ongoing_certificate_request,
    )
    .await?;
    let _ = tx.send(());
    println!("{}", certificate_pem);
    Ok(())
}
