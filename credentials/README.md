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

## Get an SXG-compatible certificate

To generate SXG, you will need a
certificate chain `cert.pem + issuer.pem` and private key `privkey.pem`.
You can not use a normal HTTPS certificate,
because SXG requires the certificate to have a
[CanSignHttpExchanges extension](https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#cross-origin-cert-req).
You have two options to get an SXG-compatible certificate.

### Option 1: Get from CA (Certificate Authority)

1. Follow the
   [doc](https://docs.digicert.com/manage-certificates/certificate-profile-options/get-your-signed-http-exchange-certificate/)
   in Digicert.

1. From the files issued by DigiCert,
   rename `DigiCertCA.crt` as `issuer.pem`,
   and rename `your_domain.crt` as `cert.pem`.

### Option 2: Generate a self-signed certificate

1. Generate prime256v1 ecdsa private key.

   ```bash
   openssl ecparam -out privkey.pem -name prime256v1 -genkey
   ```

1. Create a certificate signing request for the private key.

   ```bash
   openssl req -new -sha256 -key privkey.pem -out cert.csr \
    -subj '/CN=example.org/O=Test/C=US'
   ```

1. Self-sign the certificate with "CanSignHttpExchanges" extension.

   ```bash
   openssl x509 -req -days 90 -in cert.csr -signkey privkey.pem -out cert.pem \
     -extfile <(echo -e "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:example.org")
   ```

1. Create a dummy issuer file.

   ```bash
   cp cert.pem issuer.pem
   ```

1. (Optional) to let chrome ignore certificate errors of the self-signed
   certificate.

   1. Genenerate `SHA-256` of the certificate.

      ```bash
      openssl x509 -pubkey -noout -in cert.pem |\
          openssl pkey -pubin -outform der |\
          openssl dgst -sha256 -binary |\
          base64 >cert_sha256.txt
      ```
   1. Launch Chrome
      ```bash
      google-chrome --guest \
        --ignore-certificate-errors-spki-list=`cat cert_sha256.txt`
      ```

## Utility script

### Parser for private key

[parse_private_key.go](./parse_private_key.go) reads PEM from stdin,
and prints the parsed value.

```bash
go run parse_private_key.go <privkey.pem
```
