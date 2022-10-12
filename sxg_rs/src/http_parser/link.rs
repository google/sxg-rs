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

use super::base::{is_quoted_pair_payload, is_tchar, ows, quoted_string};
use nom::{
    branch::alt,
    bytes::complete::{take_while, take_while1},
    character::complete::char,
    combinator::{into, map, opt},
    multi::many0,
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};
use std::borrow::Cow;

// Represents an individual link directive i.e. an instance of `link-value`
// from https://datatracker.ietf.org/doc/html/rfc8288#section-3.
// Parameters with alternate character encodings (via RFC8187) are not
// supported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link<'a> {
    pub uri: String,
    pub params: Vec<(Cow<'a, str>, Option<String>)>,
}

fn quote(value: &str) -> Option<String> {
    if value.chars().all(is_tchar) {
        Some(value.into())
    } else if value.chars().all(is_quoted_pair_payload) {
        Some(
            "\"".to_string()
                + &value
                    .chars()
                    .map(|c: char| {
                        if c == '\\' || c == '"' {
                            format!("\\{}", c)
                        } else {
                            format!("{}", c)
                        }
                    })
                    .collect::<String>()
                + "\"",
        )
    } else {
        None
    }
}

impl<'a> Link<'a> {
    pub fn serialize(&self) -> String {
        "<".to_string()
            + &self.uri
            + ">"
            + &self
                .params
                .iter()
                .filter_map(|(k, v)| {
                    Some(if let Some(v) = v {
                        format!(";{}={}", k, quote(v)?)
                    } else {
                        format!(";{}", k)
                    })
                })
                .collect::<String>()
    }
}

fn uri_ref(input: &str) -> IResult<&str, &str> {
    // We don't need to fully parse the URI ref using nom. It would be
    // sufficient to scan up until the closing delimiter '>' and then pass the result to the
    // URL class for parsing and validation. For defense in depth, we only allow
    // the characters specified in
    // https://datatracker.ietf.org/doc/html/rfc3986#appendix-A.
    take_while(|c: char| {
        matches!(c,
            // unreserved
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' |
            // gen-delims
            ':' | '|' | '?' | '#' | '[' | ']' | '@' |
            // sub-delims
            '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' |
            // pct-encoded
            '%' |
            // path
            '/'
        )
    })(input)
}

// https://www.rfc-editor.org/rfc/rfc5987#section-3.2.1
fn parmname(input: &str) -> IResult<&str, &str> {
    take_while1(is_attr_char)(input)
}

// https://www.rfc-editor.org/rfc/rfc5987#section-3.2.1
pub fn is_attr_char(c: char) -> bool {
    matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9' |
        '!' | '#' | '$' | '&' | '+' | '-' | '.' |
        '^' | '_' | '`' | '|' | '~'
    )
}

// https://www.rfc-editor.org/rfc/rfc5988.html#section-5
fn ptoken(input: &str) -> IResult<&str, &str> {
    take_while1(is_ptokenchar)(input)
}

// https://www.rfc-editor.org/rfc/rfc5988.html#section-5
pub fn is_ptokenchar(c: char) -> bool {
    matches!(c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '(' |
        ')' | '*' | '+' | '-' | '.' | '/' | '0'..='9' |
        ':' | '<' | '=' | '>' | '?' | '@' | 'A'..='Z' | 'a'..='z' |
        '[' | ']' | '^' | '_' | '`' | '{' | '|' |
        '}' | '~'
    )
}

fn link_param(input: &str) -> IResult<&str, (Cow<'_, str>, Option<String>)> {
    pair(
        map(terminated(parmname, ows), Cow::Borrowed),
        opt(preceded(
            pair(char('='), ows),
            alt((into(ptoken), quoted_string)),
        )),
    )(input)
}

pub fn link(input: &str) -> IResult<&str, Link> {
    map(
        pair(
            delimited(char('<'), uri_ref, char('>')),
            many0(preceded(tuple((ows, char(';'), ows)), link_param)),
        ),
        |(uri, params)| Link {
            uri: uri.into(),
            params,
        },
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse() {
        assert_eq!(
            link("<>").unwrap(),
            (
                "",
                Link {
                    uri: "".into(),
                    params: vec![]
                }
            )
        );
        assert_eq!(
            link("</foo,bar;baz>").unwrap(),
            (
                "",
                Link {
                    uri: "/foo,bar;baz".into(),
                    params: vec![]
                }
            )
        );
        assert_eq!(
            link("</foo>;bar;baz=quux").unwrap(),
            (
                "",
                Link {
                    uri: "/foo".into(),
                    params: vec![
                        (Cow::Borrowed("bar"), None),
                        (Cow::Borrowed("baz"), Some("quux".into()))
                    ]
                }
            )
        );
        assert_eq!(
            link(r#"</foo>;bar="baz \\\"quux""#).unwrap(),
            (
                "",
                Link {
                    uri: "/foo".into(),
                    params: vec![(Cow::Borrowed("bar"), Some(r#"baz \"quux"#.into()))]
                }
            )
        );
        assert_eq!(
            link(r#"</foo>;bar="baz \""#).unwrap(),
            (
                r#"="baz \""#,
                Link {
                    uri: "/foo".into(),
                    params: vec![(Cow::Borrowed("bar"), None)],
                }
            )
        );
        assert_eq!(
            link(r#"<https://signed-exchange-testing.dev/sxgs/image.jpg>;rel=allowed-alt-sxg;header-integrity=sha256-ypu/jZuGukVK2EEGlEkiN92qQDg3Zw6Fb0kCtees1bo="#).unwrap(),
            (
                "",
                Link {
                    uri: "https://signed-exchange-testing.dev/sxgs/image.jpg".into(),
                    params: vec![
                        (Cow::Borrowed("rel"), Some("allowed-alt-sxg".into())),
                        (Cow::Borrowed("header-integrity"), Some("sha256-ypu/jZuGukVK2EEGlEkiN92qQDg3Zw6Fb0kCtees1bo=".into())),
                    ],
                }
            )
        );
    }
    #[test]
    fn serialize() {
        assert_eq!(
            Link {
                uri: "/foo".into(),
                params: vec![(Cow::Borrowed("bar"), None)]
            }
            .serialize(),
            "</foo>;bar"
        );
        assert_eq!(
            Link {
                uri: "/foo".into(),
                params: vec![(Cow::Borrowed("bar"), Some("baz".into()))]
            }
            .serialize(),
            "</foo>;bar=baz"
        );
        assert_eq!(
            Link {
                uri: "/foo".into(),
                params: vec![(Cow::Borrowed("bar"), Some("baz quux".into()))]
            }
            .serialize(),
            r#"</foo>;bar="baz quux""#
        );
        assert_eq!(
            Link {
                uri: "/foo".into(),
                params: vec![(Cow::Borrowed("bar"), Some(r#"baz\"quux"#.into()))]
            }
            .serialize(),
            r#"</foo>;bar="baz\\\"quux""#
        );
        assert_eq!(
            Link {
                uri: "/foo".into(),
                params: vec![(Cow::Borrowed("bar"), Some("\x7f".into()))]
            }
            .serialize(),
            "</foo>"
        );
    }
}
