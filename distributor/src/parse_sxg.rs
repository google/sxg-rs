use anyhow::{anyhow, Result};
use futures::stream::{StreamExt, TryStreamExt};
use hyper::Body;
use nom::{
    bytes::streaming::{tag, take},
    combinator::{map, map_res, verify},
    multi::length_data,
    number::streaming::{be_u16, be_u24},
    sequence::{pair, preceded},
    IResult,
};

#[derive(Debug)]
pub struct Parts {
    pub fallback_url: String,
    pub signature: Vec<u8>,
    pub signed_headers: Vec<u8>,
    pub payload_body: Body,
}

fn signature_and_headers(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let (input, (sig_length, header_length)) = pair(
        verify(be_u24, |len| *len <= 16384),
        verify(be_u24, |len| *len <= 524288),
    )(input)?;
    pair(take(sig_length), take(header_length))(input)
}

fn parse_impl(sxg: &[u8]) -> IResult<&[u8], Parts> {
    preceded(
        tag(b"sxg1-b3\0"),
        map(
            pair(
                map_res(length_data(be_u16), |url: &[u8]| {
                    String::from_utf8(url.to_vec())
                }),
                signature_and_headers,
            ),
            |(fallback_url, (signature, signed_headers))| Parts {
                fallback_url,
                signature: signature.to_vec(),
                signed_headers: signed_headers.to_vec(),
                payload_body: Body::empty(),
            },
        ),
    )(sxg)
}

// TODO: Add a timeout.
pub async fn parse(mut sxg: Body) -> Result<Parts> {
    let mut body: Vec<u8> = vec![];
    while let Some(bytes) = sxg.try_next().await? {
        // TODO: Eliminate the duplicate processing that happens when we don't
        // yet have the SXG prologue fully buffered and need to await more:
        // - Eliminate the copy into body, e.g. by implementing all the
        //   necessary nom input traits for Vec<Bytes>.
        // - Eliminate the duplicate parsing of the SXG prefix, by switching to
        //   some parsing library (or a hand-rolled parser) that can trampoline
        //   with an input stream (buffering internally if necessary).
        // That said, the performance gain may not be worth the complexity
        // cost. SXG prologues are generally <2KB.
        body.extend_from_slice(&bytes);
        match parse_impl(&body) {
            Ok((remaining, parts)) => {
                return Ok(Parts {
                    payload_body: Body::wrap_stream(Body::from(remaining.to_vec()).chain(sxg)),
                    ..parts
                });
            }
            Err(nom::Err::Incomplete(_)) => (),
            Err(e) => {
                return Err(anyhow!(e.to_owned()));
            }
        }
    }
    Err(anyhow!("Truncated SXG"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Bytes;
    async fn assert_parts(parts: Parts) {
        assert_eq!(parts.fallback_url, "https://test.example/");
        assert_eq!(parts.signature, b"abc123");
        assert_eq!(parts.signed_headers, b"\xA2DnameEvalueEname2Fvalue2");

        let payload_body: Vec<Bytes> = parts.payload_body.try_collect().await.unwrap();
        assert_eq!(payload_body.concat(), b"\0\0\0\0\x04\0\0\0testing");
    }
    #[tokio::test]
    async fn parse_complete() {
        let chunk: &[u8] = b"sxg1-b3\0\0\x15https://test.example/\0\0\x06\0\0\x19abc123\xA2DnameEvalueEname2Fvalue2\0\0\0\0\x04\0\0\0testing";
        let body = Body::wrap_stream(Body::from(chunk));

        let parts = parse(body).await.unwrap();
        assert_parts(parts).await;
    }
    #[tokio::test]
    async fn parse_split_prologue() {
        // The prologue is split across chunks.
        let chunk1: &[u8] = b"sxg1-b3\0\0\x15https://test.example/\0\0\x06\0\0";
        let chunk2: &[u8] = b"\x19abc123\xA2DnameEvalueEname2Fvalue2\0\0\0\0\x04\0\0\0testing";
        let body = Body::wrap_stream(Body::from(chunk1).chain(Body::from(chunk2)));

        let parts = parse(body).await.unwrap();
        assert_parts(parts).await;
    }
    #[tokio::test]
    async fn parse_split_body() {
        // The body is split across chunks.
        let chunk1: &[u8] = b"sxg1-b3\0\0\x15https://test.example/\0\0\x06\0\0\x19abc123\xA2DnameEvalueEname2Fvalue2\0\0\0\0";
        let chunk2: &[u8] = b"\x04\0\0\0testing";
        let body = Body::wrap_stream(Body::from(chunk1).chain(Body::from(chunk2)));

        let parts = parse(body).await.unwrap();
        assert_parts(parts).await;
    }
    #[tokio::test]
    async fn parse_truncated() {
        // The prologue is incomplete.
        let chunk: &[u8] =
            b"sxg1-b3\0\0\x15https://test.example/\0\0\x06\0\0\x19abc123\xA2DnameEvalu";
        let body = Body::wrap_stream(Body::from(chunk));

        assert_eq!(
            format!("{}", parse(body).await.unwrap_err()),
            "Truncated SXG"
        );
    }
}
