// https://tools.ietf.org/html/draft-thomson-http-mice-03

pub fn calculate(input: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let record_size = input.len() as u64;
    let mut message = Vec::new();
    message.extend_from_slice(&record_size.to_be_bytes());
    message.extend_from_slice(input);
    let integrity = crate::utils::get_sha(&[input, &[0u8]].concat());
    (integrity, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.1
        let input = "When I grow up, I want to be a watermelon".as_bytes();
        let mut output = Vec::<u8>::new();
        output.extend_from_slice(&0x29u64.to_be_bytes());
        output.extend_from_slice(&input);
        assert_eq!(calculate(input), (::base64::decode("dcRDgR2GM35DluAV13PzgnG6+pvQwPywfFvAu1UeFrs=").unwrap(), output));
    }
}
