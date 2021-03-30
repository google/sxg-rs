pub fn get_sha(bytes: &[u8]) -> Vec<u8> {
    use ::sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

