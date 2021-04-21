mod cbor;
mod mice;
mod signature;
mod signed_headers;
mod structured_header;
mod sxg;
mod utils;

pub fn create_cert_cbor(cert_der: &[u8], issuer_der: &[u8], ocsp_der: &[u8]) -> Vec<u8> {
    use cbor::DataItem;
    let cert_cbor = DataItem::Array(vec![
        DataItem::TextString("📜⛓"),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(cert_der)),
            (DataItem::TextString("ocsp"), DataItem::ByteString(ocsp_der)),
        ]),
        DataItem::Map(vec![
            (DataItem::TextString("cert"), DataItem::ByteString(issuer_der)),
        ]),
    ]);
    cert_cbor.serialize()
}

pub struct CreateSignedExchangeParams<'a> {
    pub cert_der: &'a [u8],
    pub cert_url: &'a str,
    pub fallback_url: &'a str,
    pub now: std::time::SystemTime,
    pub payload_body: &'a str,
    pub payload_headers: Vec<(String, String)>,
    pub privkey_der: &'a [u8],
    pub status_code: u16,
    pub validity_url: &'a str,
}

pub fn create_signed_exchange(params: CreateSignedExchangeParams) -> Vec<u8> {
    let CreateSignedExchangeParams {
        cert_der,
        cert_url,
        fallback_url,
        now,
        payload_body,
        payload_headers,
        privkey_der,
        status_code,
        validity_url,
    } = params;
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
    let signature = signature::Signature::new(signature::SignatureParams {
        cert_url,
        cert_sha256: utils::get_sha(cert_der),
        date: now,
        expires: now + std::time::Duration::from_secs(60 * 60 * 24 * 6),
        headers: &headers,
        id: "sig",
        private_key: privkey_der,
        request_url: fallback_url,
        validity_url,
    });
    sxg::build(fallback_url, &signature.serialize(), &headers, &payload_body)
}

