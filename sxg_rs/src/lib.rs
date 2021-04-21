mod cbor;
mod mice;
mod signature;
mod signed_headers;
mod structured_header;
mod sxg;
mod utils;

pub fn create_cert_cbor(certificate: &str, issuer: &str, ocsp: &[u8]) -> Vec<u8> {
    let certificate = ::pem::parse(certificate).unwrap();
    let issuer = ::pem::parse(issuer).unwrap();
    use cbor::DataItem;
    let cert_cbor = DataItem::Array(vec![
        DataItem::TextString("📜⛓"),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(&certificate.contents)),
            (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp)),
        ]),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(&issuer.contents)),
        ]),
    ]);
    cert_cbor.serialize()
}

pub struct CreateSignedExchangeParams<'a> {
    pub cert_url: &'a str,
    pub cert_pem: &'a str,
    pub fallback_url: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a str,
    pub payload_headers: Vec<(String, String)>,
    pub private_key_base64: &'a str,
    pub status_code: u16,
    pub validity_url: &'a str,
}

pub fn create_signed_exchange(params: CreateSignedExchangeParams) -> Vec<u8> {
    let CreateSignedExchangeParams {
        cert_url,
        cert_pem,
        fallback_url,
        now,
        payload_body,
        payload_headers,
        private_key_base64,
        status_code,
        validity_url,
    } = params;
    let certificate = ::pem::parse(cert_pem).unwrap();
    let (mice_digest, payload_body) = crate::mice::calculate(&payload_body.as_bytes());
    let mut headers = signed_headers::SignedHeaders::new();
    for (k, v) in payload_headers.iter() {
        headers.insert(k, v);
    }
    let status_code = status_code.to_string();
    headers.insert(":status", &status_code);
    headers.insert("content-type", "text/html;charset=UTF-8");
    headers.insert("content-encoding", "mi-sha256-03");
    let digest = format!("mi-sha256-03={}", ::base64::encode(&mice_digest));
    headers.insert("digest", &digest);
    let headers = headers.serialize();
    let private_key = ::base64::decode(private_key_base64).unwrap();
    let signature = signature::Signature::new(signature::SignatureParams {
        cert_url,
        cert_sha256: utils::get_sha(&certificate.contents),
        date: now,
        expires: now + std::time::Duration::from_secs(60 * 60 * 24 * 6),
        headers: &headers,
        id: "sig",
        private_key,
        request_url: fallback_url,
        validity_url,
    });
    sxg::build(fallback_url, &signature.serialize(), &headers, &payload_body)
}

