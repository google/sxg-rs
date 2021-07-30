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
   using [these steps](../../credentials/README.md#get-an-sxg_compatible-certificate).

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. Install [@cloudflare/wrangler](https://github.com/cloudflare/wrangler).
1. Create a `wrangler.toml` from the template `wrangler.example.toml`.
   1. Put your Cloudflare account ID.
   1. Put your `zone_id` and `routes` as described
      [here](https://developers.cloudflare.com/workers/get-started/guide#optional-configure-for-deploying-to-a-registered-domain).
   1. Use the command `wrangler kv:namespace create OCSP` to create the id of
      [KV namespace](https://developers.cloudflare.com/workers/runtime-apis/kv),
      and put it into `kv_namespaces`.
1. Create a `config.yaml` from the template `config.example.yaml`.
   1. Put your domain as `html_host`.
   1. Put your
      [cloudflare worker subdomain](https://developers.cloudflare.com/workers/get-started/guide#1-sign-up-for-a-workers-account)
      into `worker_host`.

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

1. Run `publish.sh` to build and deploy the worker online.

## Maintenance

The certificates need to be renewed every 90 days.

1. Follow the steps in digicert
   [doc](https://docs.digicert.com/manage-certificates/renew-ssltls-certificate/) to renew the certificate.
1. Overwrite the new-issued `cert.pem` and `issuer.pem` into the folder
   `REPO_ROOT/credentials/`.
1. Run `wrangler publish` to restart the worker.
