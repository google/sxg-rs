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

use super::base::{ows, parameter_value, token};
use nom::{
    character::complete::char as char1,
    combinator::map,
    multi::many0,
    sequence::{preceded, separated_pair, tuple},
    IResult,
};

#[derive(Debug, Eq, PartialEq)]
pub struct MediaType<'a> {
    pub primary_type: &'a str,
    pub sub_type: &'a str,
    pub parameters: Vec<Parameter<'a>>,
}

// https://tools.ietf.org/html/rfc7231#section-3.1.1.1
// `media-type` is defined as
//   media-type = type "/" subtype *( OWS ";" OWS parameter )
//   type       = token
//   subtype    = token
pub fn media_type(input: &str) -> IResult<&str, MediaType<'_>> {
    map(
        tuple((
            separated_pair(token, char1('/'), token),
            many0(preceded(separated_pair(ows, char1(';'), ows), parameter)),
        )),
        |((primary_type, sub_type), parameters)| MediaType {
            primary_type,
            sub_type,
            parameters,
        },
    )(input)
}

#[derive(Debug, Eq, PartialEq)]
pub struct Parameter<'a> {
    pub name: &'a str,
    pub value: String,
}

// https://tools.ietf.org/html/rfc7231#section-3.1.1.1
// `parameter` is defined as
//   parameter  = token "=" ( token / quoted-string )
fn parameter(input: &str) -> IResult<&str, Parameter<'_>> {
    map(
        separated_pair(token, char1('='), parameter_value),
        |(name, value)| Parameter { name, value },
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(
            media_type("text/html;charset=utf-8").unwrap(),
            (
                "",
                MediaType {
                    primary_type: "text",
                    sub_type: "html",
                    parameters: vec![Parameter {
                        name: "charset",
                        value: "utf-8".to_string(),
                    }],
                }
            )
        );
    }
    #[test]
    fn no_params() {
        assert_eq!(
            media_type("a/b").unwrap(),
            (
                "",
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![],
                }
            )
        );
    }
    #[test]
    fn missing_type() {
        assert!(media_type("a").is_err());
        assert!(media_type("a/").is_err());
        assert!(media_type("/b").is_err());
    }
    #[test]
    fn param_in_quoted_string() {
        assert_eq!(
            media_type(r#"a/b;x="1""#).unwrap(),
            (
                "",
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![Parameter {
                        name: "x",
                        value: "1".to_string(),
                    }],
                }
            )
        );
    }
    #[test]
    fn optional_whitespace() {
        assert_eq!(
            media_type("a/b  ;  x=1").unwrap(),
            (
                "",
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![Parameter {
                        name: "x",
                        value: "1".to_string(),
                    }],
                }
            )
        );
    }
    #[test]
    fn multiple_params() {
        assert_eq!(
            media_type("a/b;x=1;y=2").unwrap(),
            (
                "",
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![
                        Parameter {
                            name: "x",
                            value: "1".to_string(),
                        },
                        Parameter {
                            name: "y",
                            value: "2".to_string(),
                        },
                    ],
                }
            )
        );
    }
    #[test]
    fn quoted_pair() {
        assert_eq!(
            media_type(r#"a/b;x="1\"2\\3";y=0"#).unwrap(),
            (
                "",
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![
                        Parameter {
                            name: "x",
                            value: r#"1"2\3"#.to_string(),
                        },
                        Parameter {
                            name: "y",
                            value: "0".to_string(),
                        },
                    ],
                }
            )
        );
    }
    #[test]
    fn unclosed_quoted_string() {
        assert_eq!(
            media_type(r#"a/b;x="1\"23;y=0"#).unwrap(),
            (
                r#";x="1\"23;y=0"#,
                MediaType {
                    primary_type: "a",
                    sub_type: "b",
                    parameters: vec![]
                }
            )
        );
    }
}
