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
