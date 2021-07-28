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

use der_parser::{
    ber::{
        BerObject,
        BerObjectContent,
    },
    oid::Oid,
};

use crate::utils::get_sha;

pub fn create_ocsp_request(cert_der: &[u8], issuer_der: &[u8]) -> Vec<u8> {
    let cert = x509_parser::parse_x509_certificate(&cert_der).unwrap().1;
    let issuer = x509_parser::parse_x509_certificate(&issuer_der).unwrap().1;
    let issuer_name = issuer.tbs_certificate.subject.as_raw();
    let issuer_key = issuer.tbs_certificate.subject_pki.subject_public_key.data;
    let issuer_key_hash = get_sha(issuer_key);
    let issuer_name_hash = get_sha(issuer_name);
    let serial_number = cert.tbs_certificate.raw_serial();
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // CertID          ::=     SEQUENCE {
    //     hashAlgorithm       AlgorithmIdentifier,
    //     issuerNameHash      OCTET STRING, -- Hash of issuer's DN
    //     issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
    //     serialNumber        CertificateSerialNumber }
    let cert_id = BerObject::from_seq(vec![
        signature_algorithm(),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_name_hash)),
        BerObject::from_obj(BerObjectContent::OctetString(&issuer_key_hash)),
        BerObject::from_obj(BerObjectContent::Integer(&serial_number)),
    ]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // Request         ::=     SEQUENCE {
    //     reqCert                     CertID,
    //     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
    let request = BerObject::from_seq(vec![
        cert_id,
    ]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // TBSRequest      ::=     SEQUENCE {
    //     version             [0]     EXPLICIT Version DEFAULT v1,
    //     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    //     requestList                 SEQUENCE OF Request,
    //     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
    let tbs_request = BerObject::from_seq(vec![
        BerObject::from_seq(vec![request]),
    ]);
    // https://tools.ietf.org/html/rfc6960#section-4.1.1
    // OCSPRequest     ::=     SEQUENCE {
    //     tbsRequest                  TBSRequest,
    //     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
    let ocsp_request = BerObject::from_seq(vec![
       tbs_request,
    ]);
    ocsp_request.to_vec().unwrap()
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1.2
// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }
fn signature_algorithm() -> BerObject<'static> {
    BerObject::from_seq(vec![
        // https://datatracker.ietf.org/doc/html/rfc5758.html#section-2
        // id-sha256  OBJECT IDENTIFIER  ::=  { joint-iso-itu-t(2)
        //      country(16) us(840) organization(1) gov(101) csor(3)
        //      nistalgorithm(4) hashalgs(2) 1 }
        BerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap())),
        BerObject::from_obj(BerObjectContent::Null),
    ])
}