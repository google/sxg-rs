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

# sxg-rs/playground

A playground to locally preview Signed Exchanges without needing a certificate.

## Build

1. Compile sxg-rs to WebAssembly

   ```bash
   cd ../cloudflare_worker && wrangler build && cd ../playground
   ```

1. Compile playground

   ```bash
   npm install
   npm run build
   ```

## Run

```bash
node dist/index.js --single-url https://example.com/ --emulate-network Fast\ 3G --repeat-time 3
```
The output will be like below.
```
Measuring non-SXG LCP of https://example.com/
LCP 1 / 3: 720
LCP 2 / 3: 674
LCP 3 / 3: 636
Measuring SXG LCP of https://example.com/
LCP 1 / 3: 78
LCP 2 / 3: 95
LCP 3 / 3: 69
SXG changes LCP from 677 ± 24 to 80 ± 8
```
