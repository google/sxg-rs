<!--
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

## Setup

1. Get an SXG-compatible certificate
   using [these steps](../credentials/README.md#get-an-sxg_compatible-certificate).

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. Install [@cloudflare/wrangler](https://github.com/cloudflare/wrangler).

1. Clone this repo and cd into the current folder.
   ```bash
   git clone https://github.com/google/sxg-rs.git
   cd sxg-rs/cloudflare_worker/
   ```
   All following steps in this `README.md` should be done in this folder.

1. Create a `wrangler.toml` from the template `wrangler.example.toml`.
   1. Set `zone_id` and `account_id` from the values [pictured
      here](https://forum.aapanel.com/d/3914-how-to-get-zone-id-of-cloudflare).
   1. Change the domain in `routes` from `my_domain.com` to your domain.
      ([Details
      here.](https://developers.cloudflare.com/workers/get-started/guide#optional-configure-for-deploying-to-a-registered-domain))
   1. Use the command `wrangler kv:namespace create OCSP` to create the id of
      [KV namespace](https://developers.cloudflare.com/workers/runtime-apis/kv),
      and put it into the `id` field in `kv_namespaces`. (If already created,
      use the command `wrangler kv:namespace list` to get the id.)
1. Create a `config.yaml` from the template `config.example.yaml`.
   1. Put your domain as `html_host`.
   1. In `worker_host`, replace `my_worker_subdomain` with the value from the
      Manage Workers page [available from
      here](https://dash.cloudflare.com/workers/overview). ([Details
      here.](https://developers.cloudflare.com/workers/get-started/guide#1-sign-up-for-a-workers-account))

1. Run `cargo test` to check errors in `config.yml`.
1. Put your private key as a
   [secret](https://developers.cloudflare.com/workers/cli-wrangler/commands#secret)
   to cloudflare worker.
   1. Parse your private key to JWK format.
      ```bash
      go run ../credentials/parse_private_key.go <../credentials/privkey.pem
      ```
   1. Run `wrangler secret put PRIVATE_KEY_JWK`. (Use the string
      `PRIVATE_KEY_JWK` as is, and don't replace it with the
      actual private key.)
   1. The terminal will interactively ask for the value of the secret.
      Put the private key in JWK format here.

1. Run `./publish.sh` to build and deploy the worker online.

1. The Google SXG Cache tries to [update SXGs
   often](https://developers.google.com/search/docs/advanced/experience/signed-exchange#:~:text=Regardless%20of%20the,the%20SXG%20response.),
   but may reuse them for up to 7 days. To ensure they expire sooner, use
   [Cloudflare Page
   Rules](https://support.cloudflare.com/hc/en-us/articles/218411427-Understanding-and-Configuring-Cloudflare-Page-Rules-Page-Rules-Tutorial-)
   to set a custom Browser Cache TTL. This creates an unsigned outer
   `Cache-Control` header on top of the SXG.

1. Read on for [next steps](../README.md).

## Maintenance

The certificates need to be renewed every 90 days.

1. Follow the steps in the [DigiCert
   doc](https://docs.digicert.com/manage-certificates/renew-ssltls-certificate/) to renew the certificate.
1. Overwrite the new-issued `cert.pem` and `issuer.pem` into the folder
   `REPO_ROOT/credentials/`.
1. Run `./publish.sh` to restart the worker.

## Uninstall

The worker and KV namespace can be deleted from the [workers
dashboard](https://dash.cloudflare.com/workers/overview).
