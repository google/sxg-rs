use crate::parse_signature;
use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use ciborium::value::Value;
use http::{HeaderMap, Uri};
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::RangeInclusive;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sxg_rs::{
    crypto::HashAlgorithm::Sha256,
    http_parser::{
        cache_control::Directive, link::Link, parse_cache_control_directives, parse_link_header,
        parse_token_list, srcset::parse as parse_srcset,
    },
    structured_header::{ParamItem, ShItem, ShParamList},
};
use url::Url;

#[derive(thiserror::Error, Debug)]
pub enum ValidationErrorType {
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#name-application-signed-exchange plus a little bit
    #[error("Unable to be parsed or not known to be representative of the expected URL.")]
    Malformed,
    // https://github.com/google/webpackager/blob/main/docs/cache_requirements.md#google-sxg-cache
    #[error("Well-formed, but not valid for serving as of the validation time.")]
    Invalid,
}

#[derive(thiserror::Error, Debug)]
#[error("{error_type}")]
pub struct ValidationError {
    error_type: ValidationErrorType,
    source: Error,
}

// https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-terminology
fn url_is_absolute(url: &str) -> Result<()> {
    // Ideally we'd consolidate on one URL type. I chose Uri because that's
    // what hyper gives us and there is no way to convert between types without
    // re-parsing. But in this case, we need Url because Uri doesn't tell you
    // if the string contained a fragment.
    let url: Url = url.parse()?;
    ensure!(url.has_host());
    ensure!(url.scheme() == "https");
    ensure!(matches!(url.fragment(), None));
    Ok(())
}

fn parse_query(url: &Uri) -> form_urlencoded::Parse {
    form_urlencoded::parse(url.query().unwrap_or("").as_bytes())
}

fn urls_approximately_equal(url1: &Uri, url2: &Uri) -> Result<()> {
    ensure!(url1.authority() == url2.authority());
    ensure!(percent_decode_str(url1.path()).eq(percent_decode_str(url2.path())));
    ensure!(parse_query(url1).eq(parse_query(url2)));
    Ok(())
}

fn unwrap(
    expected_url: &Uri,
    expected_integrity: &Option<&str>,
    fallback_url: &str,
    signed_headers: &[u8],
) -> Result<HeaderMap> {
    url_is_absolute(fallback_url)?;
    let fallback_url: Uri = fallback_url.parse()?;
    urls_approximately_equal(expected_url, &fallback_url)?;
    if let Some(expected_integrity) = expected_integrity {
        ensure!(
            expected_integrity
                == &base64::encode_config(Sha256.digest(signed_headers), base64::URL_SAFE)
                    .get(..12)
                    .ok_or_else(|| anyhow!("invalid integrity"))?
        );
    }
    let headers: Value =
        ciborium::de::from_reader(signed_headers).with_context(|| "parsing signed headers")?;
    // TODO: Verify header names don't contain uppercase; no duplicates; etc. (canonical serialization)
    let headers: Vec<(Vec<u8>, Vec<u8>)> = match headers {
        Value::Map(pairs) => {
            let mut headers = vec![];
            let mut status = None;
            for pair in pairs {
                headers.push(match pair {
                    (Value::Bytes(name), Value::Bytes(value)) => {
                        // Don't encode :status because http::HeaderName doesn't like the colon.
                        if name == b":status" {
                            status = Some(value);
                            continue;
                        }
                        (name, value)
                    }
                    _ => bail!("invalid signed headers cbor"),
                });
            }
            ensure!(status == Some(b"200".to_vec()));
            headers
        }
        _ => bail!("invalid signed headers cbor"),
    };
    // eprintln!("{:?}", headers.iter().map(|(k,v)| (String::from_utf8_lossy(k).into_owned(), String::from_utf8_lossy(v).into_owned())).collect::<Vec<(String, String)>>());
    headers
        .into_iter()
        .map(|(name, value)| Ok((name.try_into()?, value.try_into()?)))
        .collect()
}

fn get_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| anyhow!("missing {name}"))
        .and_then(|v| {
            v.to_str()
                .map_err(|_| anyhow!("{name} contains non-printable chars"))
        })
}

lazy_static::lazy_static! {
    // Headers are downcased for comparison with HeaderNames.
    static ref DISALLOWED_HEADERS: HashSet<&'static str> = [
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#uncached-headers
        "connection",
        "keep-alive",
        "proxy-connection",
        "trailer",
        "transfer-encoding",
        "upgrade",
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#stateful-headers
        "authentication-control",
        "authentication-info",
        "clear-site-data",
        "optional-www-authenticate",
        "proxy-authenticate",
        "proxy-authentication-info",
        "public-key-pins",
        "sec-websocket-accept",
        "set-cookie",
        "set-cookie2",
        "setprofile",
        "strict-transport-security",
        "www-authenticate",
        // https://github.com/google/webpackager/blob/main/docs/cache_requirements.md
        "variant-key-04",
        "variants-04",
    ].into();

    static ref DISALLOWED_CACHE_CONTROL_DIRECTIVES: HashSet<&'static str> = [
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-4-4.4
        "no-store",
        "private",
        // Not disallowed by the SXG spec, but an indicator that the response
        // might not be suitable for a shared cache, per
        // https://www.rfc-editor.org/rfc/rfc7234#section-4:
        "no-cache",
    ].into();

    static ref LINK_ALLOWED_PARAMS: HashSet<&'static str> = [
        "as",
        "header-integrity",
        "media",
        "rel",
        "imagesrcset",
        "imagesizes",
        "crossorigin",
    ].into();

    static ref LINK_REL_SAFE_TO_IGNORE: HashSet<&'static str> = [
        // The following are popular and known not to trigger recursive prefetch.
        "amphtml",
        "canonical",
        "https://api.w.org/",
    ].into();
}

pub struct Preload {
    pub url: String,
    pub integrity: String,
}

fn get_param(link: &Link, name: &str) -> Result<String> {
    // TODO: Eliminate clones.
    let value: Vec<String> = link
        .params
        .iter()
        .filter(|(k, _)| k == name)
        .filter_map(|(_, v)| v.clone())
        .collect();
    match &value[..] {
        [value] => Ok(value.clone()),
        [] => Err(anyhow!("missing {name} param")),
        _ => Err(anyhow!("duplicate {name} param")),
    }
}

fn validate_link_header(fallback_url: &str, value: &str) -> Result<Vec<Preload>> {
    // TODO: Ensure not present on subresources.
    let links = parse_link_header(value).with_context(|| "parse_link_header")?;
    let mut num_preloads = 0;
    let mut preload_urls = vec![];
    let mut integrities = HashMap::new();
    for link in links {
        url_is_absolute(&link.uri)?;
        ensure!(link
            .params
            .iter()
            .all(|(k, _)| LINK_ALLOWED_PARAMS.contains(k.to_string().as_str())));
        let rel = get_param(&link, "rel")?;
        if LINK_REL_SAFE_TO_IGNORE.contains(rel.as_str()) {
            continue;
        }
        match rel.as_ref() {
            "preload" => {
                num_preloads += 1;
                ensure!(num_preloads <= 20);
                if let Ok(srcset) = get_param(&link, "imagesrcset") {
                    preload_urls.push(link.uri);
                    // Ensure srcset URLs also have allowed-alt-sxg, but don't
                    // increment num_preloads since the browser will only preload
                    // one variant.
                    for href in parse_srcset(&srcset)? {
                        let url = Url::parse(fallback_url)?.join(href)?;
                        preload_urls.push(url.into());
                    }
                } else {
                    preload_urls.push(link.uri);
                }
            }
            "allowed-alt-sxg" => {
                let integrity = get_param(&link, "header-integrity")?;
                ensure!(
                    matches!(integrity.strip_prefix("sha256-"), Some(integrity) if base64::decode(integrity).is_ok())
                );
                match integrities.entry(link.uri) {
                    Entry::Vacant(entry) => entry.insert(integrity),
                    Entry::Occupied(_) => bail!("duplicate allowed-alt-sxg"),
                };
            }
            _ => bail!("disallowed link rel"),
        }
    }
    let expected_len = preload_urls.len();
    // TODO: Eliminate clone.
    let preloads: Vec<Preload> = preload_urls
        .into_iter()
        .filter_map(|url| {
            integrities.get(&url).map(|integrity| Preload {
                url,
                integrity: integrity.clone(),
            })
        })
        .collect();
    // Ensure all preloads are covered by an allowed-alt-sxg.
    ensure!(expected_len == preloads.len());
    Ok(preloads)
}

fn validate_headers(fallback_url: &str, headers: &HeaderMap) -> Result<Vec<Preload>> {
    ensure!(get_header(headers, "content-encoding")? == "mi-sha256-03");
    // Content-Length is only a hint, but it's a useful one to reduce the risk
    // of needing to proxy large responses. We can't cancel SXG responses
    // midstream without the browser seeing a truncated body.
    ensure!(
        get_header(headers, "content-length")
            .unwrap_or("0")
            .parse::<u32>()?
            <= 8_000_000
    );
    // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.8.1
    get_header(headers, "content-type")?;
    get_header(headers, "digest")?;
    // TODO: Validate and return link header.
    let header_names = headers.keys().map(|k| k.as_str()).collect();
    ensure!(DISALLOWED_HEADERS.is_disjoint(&header_names));

    let connection_headers: HashSet<&str> =
        parse_token_list(get_header(headers, "connection").unwrap_or_default())
            .with_context(|| "connection")?
            .into_iter()
            .collect();
    ensure!(connection_headers.is_disjoint(&header_names));
    let cache_directives =
        parse_cache_control_directives(get_header(headers, "cache-control").unwrap_or_default())
            .with_context(|| "cache-control")?;
    for directive in cache_directives {
        match directive {
            Directive::Other(name, Some(value)) => {
                if name == "no-cache" {
                    let no_cache_headers: HashSet<&str> = parse_token_list(&value)
                        .with_context(|| "no-cache=")?
                        .into_iter()
                        .collect();
                    ensure!(no_cache_headers.is_disjoint(&header_names));
                }
            }
            Directive::Other(name, None) => {
                ensure!(!DISALLOWED_CACHE_CONTROL_DIRECTIVES.contains(name.as_str()));
            }
            _ => {}
        }
    }
    if let Some(link) = headers.get("link") {
        validate_link_header(
            fallback_url,
            link.to_str()
                .map_err(|_| anyhow!("link contains non-printable chars"))?,
        )
        .with_context(|| "validate_link_header")
    } else {
        Ok(vec![])
    }
}

fn parse_date(value: &Option<&&Option<ShItem>>) -> Option<SystemTime> {
    match value {
        Some(Some(ShItem::Integer(date))) => {
            Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(*date).ok()?))
        }
        _ => None,
    }
}

fn params_map<'a, 'b>(
    params: &'b [(Cow<'a, str>, Option<ShItem<'a>>)],
) -> Result<HashMap<&'b Cow<'a, str>, &'b Option<ShItem<'a>>>> {
    let mut map = HashMap::new();
    for (key, value) in params {
        // Error if a duplicate key is present.
        ensure!(map.insert(key, value).is_none());
    }
    Ok(map)
}

// Returns the parsed signature.
fn validate_signature<'a>(
    expected_url: &Uri,
    fetch_time: &SystemTime,
    signature: &'a [u8],
) -> Result<ParamItem<'a>> {
    // TODO: Implement a custom parser for header-structure-10. RFC 8941 doesn't match it.
    // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html
    let signature = parse_signature::parse(signature).with_context(|| "parse_signature::parse")?;
    let params = params_map(&signature.parameters)?;
    ensure!(matches!(
        params.get(&Cow::from("sig")),
        Some(Some(ShItem::ByteSequence(_)))
    ));
    ensure!(
        matches!(params.get(&Cow::from("integrity")), Some(Some(ShItem::String(i))) if i == "digest/mi-sha256-03")
    );
    // TODO: Allow data: cert-url (and don't rewrite it).
    ensure!(
        matches!(params.get(&Cow::from("cert-url")), Some(Some(ShItem::String(u))) if url_is_absolute(u).is_ok())
    );
    ensure!(matches!(
        params.get(&Cow::from("cert-sha256")),
        Some(Some(ShItem::ByteSequence(_)))
    ));
    ensure!(
        matches!(params.get(&Cow::from("validity-url")), Some(Some(ShItem::String(validity))) if
            url_is_absolute(validity).is_ok() &&
            matches!(validity.parse::<Uri>(), Ok(validity_uri) if validity_uri.authority() == expected_url.authority())
        )
    );
    let date =
        parse_date(&params.get(&Cow::from("date"))).ok_or_else(|| anyhow!("invalid date"))?;
    // Allow SXGs slightly in the future to account for the possibility that this server's clock is behind both the origin server and the user.
    // TODO: Make this configurable. Does this make sense without caching?
    let nowish = fetch_time
        .checked_add(Duration::from_secs(60))
        .ok_or_else(|| anyhow!("error adding 60s"))?;
    nowish.duration_since(date)?;

    let expires =
        parse_date(&params.get(&Cow::from("expires"))).ok_or_else(|| anyhow!("invalid expires"))?;
    const ALLOWED_DURATION: RangeInclusive<Duration> =
        Duration::from_secs(2 * 60)..=Duration::from_secs(60 * 60 * 24 * 7);
    ensure!(ALLOWED_DURATION.contains(&expires.duration_since(*fetch_time)?));

    Ok(signature)
}

fn rewritten_signature(cache_origin: &str, mut signature: ParamItem) -> Result<Vec<u8>> {
    let cert_sig = match signature
        .parameters
        .iter()
        .find(|(k, _)| k == "cert-sha256")
    {
        Some((_, Some(ShItem::ByteSequence(sha)))) => base64::encode_config(sha, base64::URL_SAFE)
            .get(..12)
            .ok_or_else(|| anyhow!("invalid cert-sha256"))?
            .to_string(),
        _ => bail!("invalid cert-sha256"),
    };
    let cert_url = match signature
        .parameters
        .iter_mut()
        .find(|(k, _)| k == "cert-url")
    {
        Some((_, Some(ShItem::String(cert_url)))) => cert_url,
        _ => bail!("invalid cert-url"),
    };
    let suffix = cert_url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("invalid cert-url"))?;
    *cert_url = format!("{cache_origin}/crt/{cert_sig}/s/{suffix}").into();
    Ok(ShParamList(vec![signature]).to_string().into_bytes())
}

fn validate_and_rewrite(
    cache_origin: &str,
    expected_url: &Uri,
    fetch_time: &SystemTime,
    fallback_url: &str,
    signature: &[u8],
    headers: &HeaderMap,
) -> Result<(Vec<u8>, Vec<Preload>)> {
    let preloads = validate_headers(fallback_url, headers).with_context(|| "validate_headers")?;
    let signature = validate_signature(expected_url, fetch_time, signature)
        .with_context(|| "validate_signature")?;
    Ok((
        rewritten_signature(cache_origin, signature).with_context(|| "rewritten_signature")?,
        preloads,
    ))
}

// TODO: Add with_context everywhere.

// Not a complete validation of SXG (doesn't try to duplicate everything the
// browser does), but enough to serve two purposes:
// 1. Minimize the number of unintentionally invalid SXGs that are sent to the browser.
// 2. Ensure prefetch can be privacy-preserving.
//
// Returns:
// 1. A signature with the cert-url rewritten to point back into the
//    cache; the browser will recursively prefetch cert-url.
// 2. List of preloaded URLs, for building outer Link: rel=alternate header, per
//    https://github.com/WICG/webpackage/blob/main/explainers/signed-exchange-subresource-substitution.md.
pub fn validate(
    cache_origin: &str,
    expected_url: &Uri,
    expected_integrity: &Option<&str>,
    fetch_time: &SystemTime,
    fallback_url: &str,
    signature: &[u8],
    signed_headers: &[u8],
) -> Result<(Vec<u8>, Vec<Preload>), ValidationError> {
    let headers = unwrap(
        expected_url,
        expected_integrity,
        fallback_url,
        signed_headers,
    )
    .map_err(|e| ValidationError {
        error_type: ValidationErrorType::Malformed,
        source: e,
    })?;
    validate_and_rewrite(
        cache_origin,
        expected_url,
        fetch_time,
        fallback_url,
        signature,
        &headers,
    )
    .map_err(|e| ValidationError {
        error_type: ValidationErrorType::Invalid,
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use byte_strings::const_concat_bytes;

    #[test]
    fn validate_signature_works() {
        const URL: &str = "https://signed-exchange-testing.dev/sxgs/valid.html";
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
        let signature = validate_signature(
            &URL.parse().unwrap(),
            &UNIX_EPOCH
                .checked_add(Duration::from_secs(1665295201))
                .unwrap(),
            SIGNATURE,
        );
        let ParamItem {
            primary_id,
            parameters,
        } = match signature {
            Ok(signature) => signature,
            Err(e) => panic!("{}", e),
        };
        assert_eq!(primary_id, "label");
        assert_eq!(
            parameters,
            vec![
                (
                    "cert-sha256".into(),
                    Some(ShItem::ByteSequence(Cow::from(
                        &[
                            63, 228, 75, 11, 90, 225, 104, 237, 159, 160, 242, 119, 247, 25, 4,
                            110, 169, 51, 21, 79, 35, 91, 246, 36, 120, 233, 174, 190, 40, 204,
                            202, 219
                        ][..]
                    )))
                ),
                (
                    "cert-url".into(),
                    Some(ShItem::String(
                        "https://signed-exchange-testing.dev/certs/cert.cbor".into()
                    ))
                ),
                ("date".into(), Some(ShItem::Integer(1665295201))),
                ("expires".into(), Some(ShItem::Integer(1665381601))),
                (
                    "integrity".into(),
                    Some(ShItem::String("digest/mi-sha256-03".into()))
                ),
                (
                    "sig".into(),
                    Some(ShItem::ByteSequence(Cow::from(
                        &[
                            48, 68, 2, 32, 49, 246, 213, 151, 170, 201, 149, 228, 203, 247, 113,
                            240, 218, 91, 233, 110, 186, 207, 37, 45, 9, 245, 153, 150, 225, 108,
                            209, 72, 189, 134, 37, 235, 2, 32, 3, 234, 203, 75, 57, 196, 12, 149,
                            117, 46, 240, 80, 47, 35, 27, 84, 32, 116, 38, 151, 49, 34, 7, 192,
                            175, 119, 3, 118, 74, 49, 118, 26
                        ][..]
                    )))
                ),
                (
                    "validity-url".into(),
                    Some(ShItem::String(
                        "https://signed-exchange-testing.dev/validity.msg".into()
                    ))
                )
            ]
        );
    }

    // TODO: More tests.
}
