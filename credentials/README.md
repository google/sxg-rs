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

1. Generate prime256v1 ecdsa private key.

   ```bash
   openssl ecparam -out privkey.pem -name prime256v1 -genkey
   ```

1. Create a certificate signing request (CSR) for the private key.

   ```bash
   openssl req -new -sha256 -key privkey.pem -out cert.csr \
    -subj '/CN=example.org/O=Test/C=US'
   ```

At this point, you have two options:

### Option 1: Automatic Certificate Management Environment (ACME)

`sxg-rs` can create SXG certificates by connecting to [Certificate
Authorities](https://github.com/google/webpackager/wiki/Certificate-Authorities)
which provide ACME service.

1. Using Google as the Certificate Authority
   1. Read and agree to the [terms of service](https://pki.goog/GTS-SA.pdf).
   1. Follow the
      [instructions](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial),
      and get your
      [key ID and HMAC](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial#request-key-hmac).

      Some steps in Google Cloud's instruction need to be skipped.
      * Skip the *Install a client* step,
        because you have installed `sxg-rs` as your client.
      * Skip all steps after the step *Request an EAB key ID and HMAC*,
        because `sxg-rs` will do them.

   1. Copy `input.example.yaml` to `input.yaml`. For the [certificates
      section](../input.example.yaml#L28-L43), comment `pre_issued` section and
      uncomment `create_acme_account` section.
      ```diff
       # the last few lines in input.yaml
       certificates:
      -  !pre_issued:
      -     cert_file: credentials/cert.pem
      -     issuer_file: credentials/issuer.pem
      -  # !create_acme_account:
      -  #   server_url: https://dv-sxg.acme-v02.api.pki.goog/directory
      -  #   contact_email: YOUR_EMAIL
      -  #   agreed_terms_of_service: https://pki.goog/GTS-SA.pdf
      -  #   sxg_cert_request_file: credentials/cert.csr
      -  #   eab:
      -  #      key_id: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXQ
      -  #      base64_mac_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      +  # !pre_issued:
      +  #    cert_file: credentials/cert.pem
      +  #    issuer_file: credentials/issuer.pem
      +  !create_acme_account:
      +    server_url: https://dv-sxg.acme-v02.api.pki.goog/directory
      +    contact_email: YOUR_EMAIL
      +    agreed_terms_of_service: https://pki.goog/GTS-SA.pdf
      +    sxg_cert_request_file: credentials/cert.csr
      +    eab:
      +       key_id: YOUR_KEY_ID
      +       base64_mac_key: YOUR_HMAC
      ```

### Option 2: Obtain from Certificate Authority

You can obtain SXG certificates from [Certificate
Authority](https://github.com/google/webpackager/wiki/Certificate-Authorities),
by manually placing orders on their website.

1. Using DigiCert as the Certificate Authority
   1. Follow the [DigiCert
      doc](https://docs.digicert.com/manage-certificates/certificate-profile-options/get-your-signed-http-exchange-certificate/).
      Note:
      1. Accounts should be created via the [SXG account signup
         form](https://www.digicert.com/account/ietf/http-signed-exchange-account.php#create-account).
         For existing accounts, you will need to reach out to DigiCert support to
         enable the CanSignHttpExchanges option.
      1. If setting the CAA DNS record using Cloudflare, add a trailing period
         after `com`, so the value for CA domain name is: `digicert.com.;
         cansignhttpexchanges=yes`.

   1. From the files issued by DigiCert, rename `DigiCertCA.crt` as `issuer.pem`,
      and rename `your_domain.crt` as `cert.pem`. Place them in this `credentials/`
      directory.

   1. After 90 days, the certificates need to be renewed
      by following the steps in the [DigiCert
      doc](https://docs.digicert.com/manage-certificates/renew-ssltls-certificate/).

### Option 3: Development certificate

When developing or testing, you can create your own SXG certificate. However, it will
not work in production; Google's cache will not use an SXG signed by development
certificate.

1. Self-sign the certificate with "CanSignHttpExchanges" extension.

   ```bash
   openssl x509 -req -days 90 -in cert.csr -signkey privkey.pem -out cert.pem \
     -extfile <(echo -e "1.3.6.1.4.1.11129.2.1.22 = ASN1:NULL\nsubjectAltName=DNS:example.org")
   ```

1. Create a placeholder issuer file.

   ```bash
   cp cert.pem issuer.pem
   ```

1. (Optional) To test the worker after it is installed, tell Chrome to ignore
   certificate errors of the self-signed certificate.

   1. Genenerate `SHA-256` of the certificate.

      ```bash
      openssl x509 -pubkey -noout -in cert.pem |\
          openssl pkey -pubin -outform der |\
          openssl dgst -sha256 -binary |\
          base64 >cert_sha256.txt
      ```
   1. Launch Chrome with these flags:
      ```bash
      google-chrome --guest --user-data-dir=/tmp/udd \
        --ignore-certificate-errors-spki-list=`cat cert_sha256.txt`
      ```
