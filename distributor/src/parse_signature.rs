// Parser for
// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10,
// as required by
// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html.
// This differs from the final RFC 8941, so we can't use the sfv crate.

use anyhow::{anyhow, Result};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{all_consuming, into, map, map_opt, map_res, opt, recognize, value},
    multi::{many0, many_m_n},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};
use std::borrow::Cow;
use sxg_rs::structured_header::{ParamItem, ShItem};

// TODO: See if the individual byte parsers (combined with
// into_iter().collect()) are a performance penalty. If so, switch to some more
// hand-coded "take_while" style parsers.

// TODO: Use matches! for char matching, like the link parser does.

fn byte_if(pred: impl Fn(u8) -> bool) -> impl Fn(&[u8]) -> IResult<&[u8], u8> {
    move |input: &[u8]| {
        map_opt(take(1usize), |c: &[u8]| {
            if c.len() == 1 && pred(c[0]) {
                Some(c[0])
            } else {
                None
            }
        })(input)
    }
}

fn one_of(allowed_bytes: &'static [u8]) -> impl Fn(&[u8]) -> IResult<&[u8], u8> {
    byte_if(move |c| allowed_bytes.contains(&c))
}

fn alpha(input: &[u8]) -> IResult<&[u8], u8> {
    byte_if(|c| (b'a'..=b'z').contains(&c) || (b'A'..=b'Z').contains(&c))(input)
}

fn digit(input: &[u8]) -> IResult<&[u8], u8> {
    byte_if(|c| (b'0'..=b'9').contains(&c))(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.9
fn token(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(pair(alpha, many0(alt((alpha, digit, one_of(b"_-.:%*/")))))),
        std::str::from_utf8,
    )(input)
}

fn lcalpha(input: &[u8]) -> IResult<&[u8], u8> {
    byte_if(|c| (b'a'..=b'z').contains(&c))(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.1
fn key(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(pair(lcalpha, many0(alt((lcalpha, digit, one_of(b"_-")))))),
        std::str::from_utf8,
    )(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.8
fn string(input: &[u8]) -> IResult<&[u8], ShItem> {
    map_res(
        delimited(
            tag(b"\""),
            many0(alt((
                byte_if(|c| (b' '..=b'\x7e').contains(&c) && c != b'"' && c != b'\\'),
                preceded(tag(b"\\"), one_of(br#"\""#)),
            ))),
            tag(b"\""),
        ),
        |s| -> Result<ShItem> {
            Ok(ShItem::String(
                String::from_utf8(s.into_iter().collect())?.into(),
            ))
        },
    )(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.10
fn byte_sequence(input: &[u8]) -> IResult<&[u8], ShItem> {
    map_res(
        delimited(
            tag(b"*"),
            many0(alt((alpha, digit, one_of(b"+/=")))),
            tag(b"*"),
        ),
        |s| -> Result<ShItem> { Ok(ShItem::ByteSequence(base64::decode(s.as_slice())?.into())) },
    )(input)
}

fn integer(input: &[u8]) -> IResult<&[u8], ShItem> {
    map_res(
        recognize(pair(opt(tag(b"-")), many_m_n(0, 15, digit))),
        |n| -> Result<ShItem> { Ok(ShItem::Integer(std::str::from_utf8(n)?.parse()?)) },
    )(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.5
// but limited to string, byte sequence, or integer per
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md
fn item(input: &[u8]) -> IResult<&[u8], ShItem> {
    alt((string, byte_sequence, integer))(input)
}

fn ows(input: &[u8]) -> IResult<&[u8], ()> {
    value((), many0(one_of(b"\t ")))(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.4
fn parameter(input: &[u8]) -> IResult<&[u8], (Cow<'_, str>, Option<ShItem>)> {
    preceded(
        tuple((ows, tag(b";"), ows)),
        pair(into(key), opt(preceded(tag(b"="), item))),
    )(input)
}

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.4
fn parameterised_identifier(input: &[u8]) -> IResult<&[u8], ParamItem> {
    map(
        pair(into(token), many0(parameter)),
        |(primary_id, parameters)| ParamItem {
            primary_id,
            parameters,
        },
    )(input)
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-the-signature-header
// is a parameterised list from
// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-header-structure-10#section-3.4
// but we only allow one parameterised identifier per
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md
pub fn parse(signature: &[u8]) -> Result<ParamItem> {
    let (_rest, param_item) =
        all_consuming(parameterised_identifier)(signature).map_err(|e| anyhow!("{e}"))?;
    Ok(param_item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use byte_strings::const_concat_bytes;

    #[test]
    fn parse_works() {
        #[allow(clippy::transmute_ptr_to_ref)]
        const SIGNATURE: &[u8] = const_concat_bytes!(
            br#"label"#,
            br#";cert-sha256=*P+RLC1rhaO2foPJ39xkEbqkzFU8jW/YkeOmuvijMyts=*"#,
            br#";cert-url="https://signed-exchange-testing.dev/certs/cert.cbor""#,
            br#";date=1665295201"#,
            br#";expires=1665381601"#,
            br#";integrity="digest/mi-sha256-03""#,
            br#";sig=*MEQCIDH21ZeqyZXky/dx8Npb6W66zyUtCfWZluFs0Ui9hiXrAiAD6stLOcQMlXUu8FAvIxtUIHQmlzEiB8CvdwN2SjF2Gg==*"#,
            br#";validity-url="https://signed-exchange-testing.dev/validity.msg""#,
        );
        let ParamItem {
            primary_id,
            parameters,
        } = match parse(SIGNATURE) {
            Ok(p) => p,
            Err(e) => panic!("{}", e),
        };
        assert_eq!(primary_id, "label");
        assert_eq!(parameters.len(), 7);
    }
}
