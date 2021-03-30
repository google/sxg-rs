// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#application-signed-exchange
pub fn build(fallback_url: &str, signature: &[u8], signed_headers: &[u8], payload_body: &[u8]) -> Vec<u8> {
    [
        "sxg1-b3\0".as_bytes(),
        &(fallback_url.len() as u16).to_be_bytes(),
        fallback_url.as_bytes(),
        (signature.len() as u32).to_be_bytes().get(1..4).unwrap(),
        (signed_headers.len() as u32).to_be_bytes().get(1..4).unwrap(),
        signature,
        signed_headers,
        payload_body,
    ].concat()
}

