// Copyright 2021 Google LLC
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

// OCSP request is defined in
// https://tools.ietf.org/html/rfc6960#section-4.1
//
// OCSP over http is defined in
// https://tools.ietf.org/html/rfc2560#appendix-A.1

use crate::crypto::HashAlgorithm;
use crate::fetcher::Fetcher;
use crate::http::{HttpRequest, Method};
use anyhow::{anyhow, Error, Result};
use der_parser::{
    ber::{BerObject, BerObjectContent},
    oid,
    oid::Oid,
};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
};

fn create_ocsp_request(cert: &X509Certificate, issuer: &X509Certificate) -> Vec<u8> {
    let hash_algorithm = HashAlgorithm::Sha1;
    let issuer_name = issuer.tbs_certificate.subject.as_raw();
    let issuer_key = issuer.tbs_certificate.subject_pki.subject_public_key.data;
    let issuer_key_hash = hash_algorithm.digest(issuer_key);
    let issuer_name_hash = hash_algorithm.digest(issuer_name);
    let serial_number = cert.tbs_certificate.raw_serial();
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // CertID          ::=     SEQUENCE {
    //     hashAlgorithm       AlgorithmIdentifier,
    //     issuerNameHash      OCTET STRING, -- Hash of issuer's DN
    //     issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
    //     serialNumber        CertificateSerialNumber }
    let cert_id = BerObject::from_seq(vec![
        hash_algorithm.to_ber(),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_name_hash)),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_key_hash)),
        BerObject::from_obj(BerObjectContent::Integer(serial_number)),
    ]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // Request         ::=     SEQUENCE {
    //     reqCert                     CertID,
    //     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
    let request = BerObject::from_seq(vec![cert_id]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // TBSRequest      ::=     SEQUENCE {
    //     version             [0]     EXPLICIT Version DEFAULT v1,
    //     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    //     requestList                 SEQUENCE OF Request,
    //     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
    let tbs_request = BerObject::from_seq(vec![BerObject::from_seq(vec![request])]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // OCSPRequest     ::=     SEQUENCE {
    //     tbsRequest                  TBSRequest,
    //     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
    let ocsp_request = BerObject::from_seq(vec![tbs_request]);
    ocsp_request.to_vec().unwrap()
}

// https://datatracker.ietf.org/doc/html/rfc4325#section-2
// https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.2.1
const AIA: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);
// https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.48.1
const AIA_OCSP: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);

pub async fn fetch_from_ca<'a, F: Fetcher>(
    cert_der: &'a [u8],
    issuer_der: &'a [u8],
    fetcher: F,
) -> Result<Vec<u8>> {
    let cert = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::from(e).context("Failed to parse cert DER"))?
        .1;
    let issuer = x509_parser::parse_x509_certificate(issuer_der)
        .map_err(|e| Error::from(e).context("Failed to parse issuer DER"))?
        .1;
    let aia = cert.extensions().iter().find(|ext| ext.oid == AIA);
    let aia = if let Some(aia) = aia {
        aia
    } else {
        // If the certificate doesn't include an AIA section, it is probably a
        // self-signed certificate. Return a stub OCSP response.
        return Ok(b"ocsp".to_vec());
    };
    let aia = if let ParsedExtension::AuthorityInfoAccess(aia) = aia.parsed_extension() {
        aia
    } else {
        return Err(anyhow!("Failed to parse AIA extension"));
    };
    let url = aia
        .accessdescs
        .iter()
        .find_map(|access_desc| {
            if access_desc.access_method == AIA_OCSP {
                match access_desc.access_location {
                    GeneralName::URI(url) => Some(url),
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("AIA OCSP responder with type of URI is not found."))?;
    let req = HttpRequest {
        body: create_ocsp_request(&cert, &issuer),
        headers: vec![(
            String::from("content-type"),
            String::from("application/ocsp-request"),
        )],
        method: Method::Post,
        url: url.into(),
    };
    let rsp = fetcher
        .fetch(req)
        .await
        .map_err(|e| e.context("Failed to fetch OCSP"))?;
    Ok(rsp.body)
}
