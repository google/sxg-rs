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

This folder contains SXG certificates. All these files are ignored by git.

## Needed files

Please add these files to your local directory.

### `cert.pem`

This is the primary certificate downloaded from digicert.
This file looks like
```
-----BEGIN CERTIFICATE-----
(Dozens of lines: your_domain_name.crt)
-----END CERTIFICATE-----
```

### `issuer.pem`

This is the intemediate certificate downloaded from digicert.
This file looks like
```
-----BEGIN CERTIFICATE-----
(Dozens of lines: DigiCertCA.crt)
-----END CERTIFICATE-----
```

## Parser for private key

[parse_private_key.go](./parse_private_key.go) reads `privkey.pem`
in the current folder, and prints the parsed value.
```bash
go run parse_private_key.go
```
The input file `privkey.pem` looks like
```
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
(A few lines)
-----END EC PRIVATE KEY-----
```
