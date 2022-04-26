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

1. Create a certificate signing request for the private key.

   ```bash
   openssl req -new -sha256 -key privkey.pem -out cert.csr \
    -subj '/CN=example.org/O=Test/C=US'
   ```

At this point, you have two options:

### Option 1: Development certificate

When developing or testing, you can create your own SXG certificate. It will
not work in production.

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
      google-chrome --guest \
        --ignore-certificate-errors-spki-list=`cat cert_sha256.txt`
      ```

### Option 2: Production certificate

For use in production, a SXG certificate must be obtained from a [Certificate
Authority](https://github.com/google/webpackager/wiki/Certificate-Authorities).
A production certificate enables the Google SXG Cache to prefetch your site's
SXGs.

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

1. Using Google as the Certificate Authority
   1. Follow the [Google doc](https://cloud.devsite.corp.google.com/public-certificate-authority/docs)
   1. Use the following [ACME Directory](https://dv-sxg.acme-v02.api.pki.goog/directory)
      for SXG certs.
   1. Use the HMAC and KID (Key ID) you retrieved in the steps above in your configuration file
      for use in retrieving the SXG certs.

#### Renew certificate

Production certificates need to be renewed every 90 days.

1. Follow the steps in the [DigiCert
   doc](https://docs.digicert.com/manage-certificates/renew-ssltls-certificate/)
   to renew the certificate.
1. From the files issued by DigiCert, rename `DigiCertCA.crt` as `issuer.pem`,
   and rename `your_domain.crt` as `cert.pem`. Place them in this `credentials/`
   directory.
