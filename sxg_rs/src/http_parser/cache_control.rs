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

use super::base::{parameter_value, token};
use nom::{
    branch::alt,
    bytes::complete::tag_no_case,
    character::complete::char,
    combinator::{map, map_res, opt},
    sequence::pair,
    sequence::preceded,
    IResult,
};
use std::time::Duration;

// https://datatracker.ietf.org/doc/html/rfc7234#section-5.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Directive {
    SMaxAge(Duration),
    MaxAge(Duration),
    // Not relevant to the freshness lifetime computation.
    Other(String, Option<String>),
}

pub fn directive(input: &str) -> IResult<&str, Directive> {
    alt((
        // Nonnegative integers up to 31 bits must be parseable per
        // https://datatracker.ietf.org/doc/html/rfc7234#section-1.2.1.
        // Parsers may allow higher numbers.
        preceded(
            tag_no_case("s-maxage="),
            map(map_res(parameter_value, |s| s.parse::<u32>()), |i| {
                Directive::SMaxAge(Duration::from_secs(i.into()))
            }),
        ),
        preceded(
            tag_no_case("max-age="),
            map(map_res(parameter_value, |s| s.parse::<u32>()), |i| {
                Directive::MaxAge(Duration::from_secs(i.into()))
            }),
        ),
        map(
            pair(token, opt(preceded(char('='), parameter_value))),
            |(k, v)| Directive::Other(k.into(), v),
        ),
    ))(input)
}

// Returns the freshness lifetime for use in a shared cache, as defined by
// https://datatracker.ietf.org/doc/html/rfc7234#section-4.2.1, excluding
// handling of the Expires header. The caller must already have validated the
// response may be stored in the cache per
// https://datatracker.ietf.org/doc/html/rfc7234#section-3. 'None' means the
// lifetime is implicit.
pub fn freshness_lifetime(directives: Vec<Directive>) -> Option<Duration> {
    // RFC7234 does not specify what to do if multiple directives of the same
    // name are present, but it appears that Chromium takes the first:
    // https://source.chromium.org/chromium/chromium/src/+/main:net/http/http_response_headers.cc;l=799;drc=0ce9df69ba9e32bafc53c3d90db8a707c243da40
    let mut s_maxage = None::<Duration>;
    let mut max_age = None::<Duration>;
    for directive in directives {
        match directive {
            Directive::SMaxAge(duration) => {
                s_maxage.get_or_insert(duration);
            }
            Directive::MaxAge(duration) => {
                max_age.get_or_insert(duration);
            }
            Directive::Other(_, _) => (),
        };
    }
    s_maxage.or(max_age)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directive_s_maxage() {
        assert_eq!(
            directive("s-maxage=3600").unwrap(),
            ("", Directive::SMaxAge(Duration::from_secs(3600)))
        );
        assert_eq!(
            directive("s-maxage=\"3600\"").unwrap(),
            ("", Directive::SMaxAge(Duration::from_secs(3600)))
        );
        assert_eq!(
            directive("s-maxage=-1").unwrap(),
            ("", Directive::Other("s-maxage".into(), Some("-1".into())))
        );
        assert_eq!(
            directive("s-maxage=1e6").unwrap(),
            ("", Directive::Other("s-maxage".into(), Some("1e6".into())))
        );
        assert_eq!(
            directive("s-maxage=\"3600").unwrap(),
            ("=\"3600", Directive::Other("s-maxage".into(), None))
        );
    }
    #[test]
    fn directive_max_age() {
        assert_eq!(
            directive("max-age=3600").unwrap(),
            ("", Directive::MaxAge(Duration::from_secs(3600)))
        );
        assert_eq!(
            directive("max-age=\"3600\"").unwrap(),
            ("", Directive::MaxAge(Duration::from_secs(3600)))
        );
        assert_eq!(
            directive("max-age=-1").unwrap(),
            ("", Directive::Other("max-age".into(), Some("-1".into())))
        );
        assert_eq!(
            directive("max-age=1e6").unwrap(),
            ("", Directive::Other("max-age".into(), Some("1e6".into())))
        );
        assert_eq!(
            directive("max-age=\"3600").unwrap(),
            ("=\"3600", Directive::Other("max-age".into(), None))
        );
    }
    #[test]
    fn directive_other() {
        assert_eq!(
            directive("no-store").unwrap(),
            ("", Directive::Other("no-store".into(), None))
        );
        assert_eq!(
            directive("no-cache=set-cookie").unwrap(),
            (
                "",
                Directive::Other("no-cache".into(), Some("set-cookie".into()))
            )
        );
        assert_eq!(
            directive("no-cache=\"set-cookie, set-cookie2\"").unwrap(),
            (
                "",
                Directive::Other("no-cache".into(), Some("set-cookie, set-cookie2".into()))
            )
        );
        assert_eq!(
            directive("no-cache=\"set-cookie").unwrap(),
            ("=\"set-cookie", Directive::Other("no-cache".into(), None))
        );
    }
    #[test]
    fn directive_multiple() {
        assert_eq!(
            directive("no-cache=\"set-cookie, set-cookie2\", no-store").unwrap(),
            (
                ", no-store",
                Directive::Other("no-cache".into(), Some("set-cookie, set-cookie2".into()))
            )
        );
    }
    #[test]
    fn freshness_lifetimes() {
        assert_eq!(freshness_lifetime(vec![]), None);
        assert_eq!(
            freshness_lifetime(vec![Directive::SMaxAge(Duration::from_secs(3600))]),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            freshness_lifetime(vec![Directive::MaxAge(Duration::from_secs(3600))]),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            freshness_lifetime(vec![
                Directive::SMaxAge(Duration::from_secs(3600)),
                Directive::MaxAge(Duration::from_secs(200))
            ]),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            freshness_lifetime(vec![
                Directive::MaxAge(Duration::from_secs(200)),
                Directive::SMaxAge(Duration::from_secs(3600))
            ]),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            freshness_lifetime(vec![
                Directive::MaxAge(Duration::from_secs(3600)),
                Directive::MaxAge(Duration::from_secs(200))
            ]),
            Some(Duration::from_secs(3600))
        );
    }
}
