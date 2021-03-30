mod cbor;
mod mice;
mod signature;
mod signed_headers;
mod structured_header;
mod sxg;
mod utils;

pub fn create_cert_cbor(certificate: &str) -> Vec<u8> {
    let certificate = ::pem::parse(certificate).unwrap();
    use cbor::DataItem;
    let fake_ocsp = vec![1, 2, 3];
    let cert_cbor = DataItem::Array(vec![
        DataItem::TextString("📜⛓".to_string()),
        DataItem::Map(vec![
            (DataItem::TextString("cert".to_string()), DataItem::ByteString(certificate.contents)),
            (DataItem::TextString("ocsp".to_string()), DataItem::ByteString(fake_ocsp)),
        ]),
    ]);
    cert_cbor.serialize()
}

pub fn create_signed_exchange(url: &str, html: &str, certificate: &str, private_key: &str, seconds_since_epoch: u32) -> Vec<u8> {
    let url = ::url::Url::parse(url).unwrap();
    let certificate = ::pem::parse(certificate).unwrap();
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds_since_epoch as u64);
    let (mice_digest, payload_body) = crate::mice::calculate(&html.as_bytes());
    let validity_url = {
        let mut validity_url = url.clone();
        validity_url.set_path("/validity");
        validity_url.into_string()
    };
    let cert_url = {
        let mut cert_url = url.clone();
        cert_url.set_path("/cert");
        cert_url.into_string()
    };
    let mut headers = signed_headers::SignedHeaders::new();
    headers.insert(":status", "200");
    headers.insert("content-type", "text/html;charset=UTF-8");
    headers.insert("content-encoding", "mi-sha256-03");
    headers.insert("digest", &format!("mi-sha256-03={}", ::base64::encode(&mice_digest)));
    let headers = headers.serialize();
    let private_key = ::base64::decode(private_key).unwrap();
    let signature = signature::Signature::new(signature::SignatureParams {
        cert_url,
        cert_sha256: utils::get_sha(&certificate.contents),
        date: now,
        expires: now + std::time::Duration::from_secs(60 * 60 * 24 * 6),
        headers: headers.clone(),
        id: "sig".to_string(),
        private_key,
        request_url: url.to_string(),
        validity_url,
    });
    sxg::build(url.as_str(), &signature.serialize(), &headers, &payload_body)
}

