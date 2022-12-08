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

// https://tools.ietf.org/html/draft-thomson-http-mice-03

use crate::crypto::HashAlgorithm;
use ::sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub fn calculate(input: &[u8], record_size: usize) -> (Vec<u8>, Vec<u8>) {
    if input.is_empty() {
        return (HashAlgorithm::Sha256.digest(&[0]), vec![]);
    }
    let record_size = std::cmp::min(record_size, input.len());
    let records: Vec<_> = if record_size > 0 {
        input.chunks(record_size).collect()
    } else {
        vec![input]
    };
    let mut proofs: VecDeque<Vec<u8>> = VecDeque::new();
    for record in records.iter().rev() {
        let mut hasher = Sha256::new();
        hasher.update(record);
        if let Some(f) = proofs.front() {
            hasher.update(f);
            hasher.update([1u8]);
        } else {
            hasher.update([0u8]);
        }
        proofs.push_front(hasher.finalize().to_vec());
    }
    let mut message = Vec::new();
    message.extend_from_slice(&(record_size as u64).to_be_bytes());
    for i in 0..records.len() {
        if i > 0 {
            message.extend_from_slice(&proofs[i]);
        }
        message.extend_from_slice(records[i]);
    }
    let integrity = proofs.pop_front().unwrap();
    (integrity, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.1
        let input = "When I grow up, I want to be a watermelon".as_bytes();
        assert_eq!(
            calculate(input, 1000000),
            (
                ::base64::decode("dcRDgR2GM35DluAV13PzgnG6+pvQwPywfFvAu1UeFrs=").unwrap(),
                [&0x29_u64.to_be_bytes(), input].concat(),
            ),
        );
        // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.2
        assert_eq!(
            calculate(input, 16),
            (
                ::base64::decode("IVa9shfs0nyKEhHqtB3WVNANJ2Njm5KjQLjRtnbkYJ4=").unwrap(),
                [
                    &0x10_u64.to_be_bytes(),
                    &input[0..16],
                    &::base64::decode("OElbplJlPK+Rv6JNK6p5/515IaoPoZo+2elWL7OQ60A=").unwrap(),
                    &input[16..32],
                    &::base64::decode("iPMpmgExHPrbEX3/RvwP4d16fWlK4l++p75PUu/KyN0=").unwrap(),
                    &input[32..],
                ]
                .concat(),
            ),
        );
    }
    #[test]
    fn empty_payload() {
        assert_eq!(
            calculate(b"", 16384),
            (
                ::base64::decode("bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=").unwrap(),
                vec![],
            ),
        );
    }
}
