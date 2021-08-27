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

1. Install [Rust](https://www.rust-lang.org/tools/install) using
   [rustup](https://rustup.rs/)

1. Install [Fastly CLI](https://github.com/fastly/cli).

1. Clone this repo and cd into the current folder.
   ```bash
   git clone https://github.com/google/sxg-rs.git
   cd sxg-rs/fastly_compute/
   ```
   All following steps in this `README.md` should be done in this folder.

1. Create a `config.yaml` from the template `config.example.yaml`.

   1. For private key
      1. Parse your private key to base64 format.
         ```bash
         go run ../credentials/parse_private_key.go <../credentials/privkey.pem
         ```
      1. Put the base64 string to `config.yaml` as `private_key_base64`.

1. Create a `fastly.toml` from the template `fastly.example.toml`.

1. Create a WASM service in [Fastly](https://manage.fastly.com/).

   1. Copy service ID to `fastly.toml`.

   <!--TODO: Use CLI to add domains and backends-->
   1. Add a domain to the service.
      This domain will be the final entrypoint of the SXG service.

   1. Add your original server, which serves your HTML website,
      as a backend to the service.
      Put it to `config.yaml` as `html_host` (see `config.example.yaml`).
      Edit the backend and change its name from `Host 1` to `Origin HTML server`.

   1. Add `ocsp.digicert.com` as a backend to the service.
      Edit the backend and change its name from `Host 1` to `OCSP server`,
      and change the port from `TLS 443` to `Non-TLS 80`.

1. Run `cargo test` to check errors in `config.yml`.

1. Run `fastly compute publish`.

1. To check whether the worker generates a valid SXG,
   use Chrome browser to open `https://${WORKER_HOST}/.sxg/test.html`.

1. Read on for [next steps](../README.md).

## Maintenance

The certificates need to be renewed every 90 days.

1. Follow the steps in digicert
   [doc](https://docs.digicert.com/manage-certificates/renew-ssltls-certificate/) to renew the certificate.
1. Overwrite the new-issued `cert.pem` and `issuer.pem` into the folder
   `REPO_ROOT/credentials/`.
1. Run `fastly compute publish` to restart the worker.
