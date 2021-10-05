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

use super::media_type::{media_type, MediaType, Parameter};
use nom::{combinator::map, IResult};

#[derive(Debug, Eq, PartialEq)]
pub struct Accept<'a> {
    pub media_range: MediaType<'a>,
    // The q value has at most 3 digits, hence 1000*q must be an integer.
    // https://tools.ietf.org/html/rfc7231#section-5.3.1
    pub q_millis: u16,
    pub extensions: Vec<Parameter<'a>>,
}

// https://tools.ietf.org/html/rfc7231#section-5.3.2
// The `accept` header has a similar syntax to `media-type`, except a special
// `q` parameter. Parameters before the first `q=...` are media type parameters
// and the parameters after are accept extension parameters.
pub fn accept(input: &str) -> IResult<&str, Accept<'_>> {
    map(media_type, |media_range| {
        let mut accept = Accept {
            media_range,
            q_millis: 1000,
            extensions: vec![],
        };
        let params = &mut accept.media_range.parameters;
        for (i, param) in params.iter().enumerate() {
            if param.name.eq_ignore_ascii_case("q") {
                if let Some(q) = parse_q_millis(&param.value) {
                    accept.q_millis = q;
                    accept.extensions = params.split_off(i + 1);
                    params.pop();
                    break;
                }
            }
        }
        accept
    })(input)
}

fn parse_q_millis(s: &str) -> Option<u16> {
    let x = s.parse::<f64>().ok()?;
    if (0.0..=1.0).contains(&x) {
        Some((x * 1000.0) as u16)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(
            accept("text/html;charset=utf-8;q=0.9").unwrap(),
            (
                "",
                Accept {
                    media_range: MediaType {
                        primary_type: "text",
                        sub_type: "html",
                        parameters: vec![Parameter {
                            name: "charset",
                            value: "utf-8".to_string(),
                        }],
                    },
                    q_millis: 900,
                    extensions: vec![],
                }
            )
        );
    }
    #[test]
    fn params_after_q_are_extensions() {
        assert_eq!(
            accept("a/b;x1=1;x2=2;q=0.9;x3=3;x4=4").unwrap(),
            (
                "",
                Accept {
                    media_range: MediaType {
                        primary_type: "a",
                        sub_type: "b",
                        parameters: vec![
                            Parameter {
                                name: "x1",
                                value: "1".to_string(),
                            },
                            Parameter {
                                name: "x2",
                                value: "2".to_string(),
                            },
                        ],
                    },
                    q_millis: 900,
                    extensions: vec![
                        Parameter {
                            name: "x3",
                            value: "3".to_string(),
                        },
                        Parameter {
                            name: "x4",
                            value: "4".to_string(),
                        },
                    ],
                }
            )
        );
    }
    #[test]
    fn default_q() {
        assert_eq!(
            accept("a/b").unwrap(),
            (
                "",
                Accept {
                    media_range: MediaType {
                        primary_type: "a",
                        sub_type: "b",
                        parameters: vec![],
                    },
                    q_millis: 1000,
                    extensions: vec![],
                }
            )
        );
    }
    #[test]
    fn uppercase_q() {
        assert_eq!(
            accept("a/b;Q=0.5").unwrap(),
            (
                "",
                Accept {
                    media_range: MediaType {
                        primary_type: "a",
                        sub_type: "b",
                        parameters: vec![],
                    },
                    q_millis: 500,
                    extensions: vec![],
                }
            )
        );
    }
}
