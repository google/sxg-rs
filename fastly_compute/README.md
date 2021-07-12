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

1. Install [Rust](https://www.rust-lang.org/tools/install).

1. Install [Fastly CLI](https://github.com/fastly/cli).

1. Create a `config.yaml` from the template `config.example.yaml`.

1. Create a `fastly.toml` from the template `fastly.example.toml`.

1. Create a WASM service in [Fastly](https://manage.fastly.com/).

   1. Copy service ID to `fastly.toml`.

   <!--TODO: Use CLI to add domains and backends-->
   1. Add a domain to the service.
      This domain will be the final entrypoint of the SXG service.
      Put it to `config.yaml` as `worker_host`.

   1. Add your original server, which serves your HTML website,
      as a backend to the service.
      Put it to `config.yaml` as `html_host`.
      Edit the backend and change its name from `Host 1` to `Origin HTML server`.

   1. Add `ocsp.digicert.com` as a backend to the service.
      Edit the backend and change its name from `Host 1` to `OCSP server`,
      and change the port from `TLS 443` to `Non-TLS 80`.

1. Run `fastly compute publish`.
