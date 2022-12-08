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

use crate::header_integrity::HeaderIntegrityFetcher;
use crate::http::HeaderFields;
use crate::http_parser::{
    media_type::MediaType, parse_accept_header, parse_cache_control_header,
    parse_content_type_header, parse_vary_header,
};
use crate::link::process_link_header;
use crate::MAX_PAYLOAD_SIZE;
use anyhow::{anyhow, ensure, Result};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::{hash_map, BTreeSet, HashMap, HashSet};
use std::time::Duration;
use url::Url;

pub struct Headers(HashMap<String, String>);

/// The preference level of how requestors accepts SXG content.
#[derive(Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum AcceptLevel {
    /// The Accept header does not explicitly mention SXG, even when they accept `*/*`.
    RejectsSxg,
    /// The Accept header indicates they accept an SXG, but generally
    /// prefer the unsigned version. That is, SXG-capable browsers plus the above.
    AcceptsSxg,
    /// The Accept header indicates they prefer an SXG over the unsigned
    /// version, by (explicitly or implicitly) setting `q` value to be `1`.
    /// This does not include the case that the `q` of SXG is the biggest but smaller than `1`.
    PrefersSxg,
}

// A default mobile user agent, for when the upstream request doesn't include one.
const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36";

/// This value is appended to `via` header of all requests sent from an SXG worker.
/// A network loop is believed to have happened when an SXG worker receives a request
/// containing this value.
pub const VIA_SXGRS: &str = "sxgrs";

impl Headers {
    pub fn new(data: HeaderFields, strip_headers: &BTreeSet<String>) -> Self {
        let mut headers = Headers(HashMap::new());
        for (mut k, v) in data {
            k.make_ascii_lowercase();
            if !strip_headers.contains(&k) {
                match headers.0.entry(k) {
                    hash_map::Entry::Occupied(o) => {
                        let o = o.into_mut();
                        o.push(',');
                        o.push_str(&v);
                    }
                    hash_map::Entry::Vacant(va) => {
                        va.insert(v);
                    }
                };
            }
        }
        headers
    }
    pub fn inner(&self) -> &HashMap<String, String> {
        &self.0
    }
    pub fn into_inner(self) -> HashMap<String, String> {
        self.0
    }
    pub fn forward_to_origin_server(
        self,
        required_accept_level: AcceptLevel,
        forwarded_header_names: &BTreeSet<String>,
    ) -> Result<HeaderFields> {
        if self.0.contains_key("authorization") {
            // We should not sign personalized content, but we cannot anonymize this request per
            // https://datatracker.ietf.org/doc/html/rfc7235#section-4.2:
            // "A proxy forwarding a request MUST NOT modify any Authorization fields in that request."
            return Err(anyhow!("The request contains an Authorization header."));
        }
        let accept = self
            .0
            .get("accept")
            .ok_or_else(|| anyhow!("The request does not have an Accept header"))?;
        let mut actual_accept_level = parse_accept_level(accept);
        if let Some(user_agent) = self.0.get("user-agent").as_ref() {
            if let Some(major_version) = parse_chrome_major_version(user_agent) {
                // https://github.com/google/sxg-rs/issues/395
                // Chrome M73-78 incorrectly uses `SXG;q=1` in `Accept` header.
                // Chrome M79 fixed it by replacing it with `SXG;q=0.9`.
                // Hence for M73-78, when the parsed `Accept` header is `PrefersSxg`,
                // we downgrade it to `AcceptsSxg`.
                if (73..=78).contains(&major_version) {
                    actual_accept_level =
                        std::cmp::max(actual_accept_level, AcceptLevel::AcceptsSxg);
                }
            }
        }
        ensure!(actual_accept_level >= required_accept_level);
        // Set Via per https://tools.ietf.org/html/rfc7230#section-5.7.1
        let mut via = VIA_SXGRS.to_string();
        if let Some(upstream_via) = self.0.get("via") {
            via = format!("{}, {}", upstream_via, via);
        }
        // new_headers is ordered to make testing easier.
        let mut new_headers: HashMap<String, String> = self
            .0
            .into_iter()
            .filter_map(|(k, v)| {
                let v = if forwarded_header_names.contains(&k) {
                    v
                } else {
                    return None;
                };
                Some((k, v))
            })
            .collect();
        let default_values = vec![("user-agent", USER_AGENT), ("via", &via)];
        for (k, v) in default_values {
            if !new_headers.contains_key(k) {
                new_headers.insert(k.to_string(), v.to_string());
            }
        }
        Ok(new_headers.into_iter().collect())
    }
    pub fn validate_as_sxg_payload(&self) -> Result<()> {
        for (k, v) in self.0.iter() {
            if DONT_SIGN_RESPONSE_HEADERS.contains(k.as_str()) {
                return Err(anyhow!(r#"A stateful header "{}" is found."#, k));
            }
            if CACHE_CONTROL_HEADERS_SET.contains(k.as_str()) {
                // `private` and `no-store` are disallowed by
                // https://github.com/google/webpackager/blob/master/docs/cache_requirements.md#user-content-google-sxg-cache,
                // while the other two are signals that the document is not usually cached and reused.
                if v.contains("private")
                    || v.contains("no-store")
                    || v.contains("no-cache")
                    || v.contains("max-age=0")
                {
                    return Err(anyhow!(r#"The {} header is "{}"."#, k, v));
                }
            }
            // TODO: Remove this section once https://crbug.com/1250532 is fixed in most clients.
            if let Some(vary) = self.0.get("vary") {
                if let Ok(directives) = parse_vary_header(vary) {
                    if directives.contains(&"*") {
                        return Err(anyhow!(
                            "The response may vary by anything,\
                            because its \"vary\" header is \"{}\".",
                            vary
                        ));
                    }
                }
            }
        }
        // Google SXG cache sets the maximum of SXG to be 8 megabytes.
        if let Some(size) = self.0.get("content-length") {
            if let Ok(size) = size.parse::<usize>() {
                if size > MAX_PAYLOAD_SIZE {
                    return Err(anyhow!(
                        "The content-length header is {}, which exceeds the limit {}.",
                        size,
                        MAX_PAYLOAD_SIZE
                    ));
                }
            }
        }
        // The payload of SXG must have a content-type. See step 8 of
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
        if !self.0.contains_key("content-type") {
            return Err(anyhow!("The content-type header is missing."));
        }
        Ok(())
    }
    // Returns the signed headers via the serializer callback instead of return
    // value, because it contains a mix of &str and String. This makes it easy
    // to test the intermediate Vec<(&str, &str)> without sacrificing
    // performance by copying it into a Vec<(String, String)>.
    async fn get_signed_headers<O, S>(
        &self,
        fallback_url: &Url,
        status_code: u16,
        mice_digest: &[u8],
        header_integrity_fetcher: &mut dyn HeaderIntegrityFetcher,
        serializer: S,
        skip_process_link: bool,
    ) -> O
    where
        S: Fn(Vec<(&str, &str)>) -> O,
    {
        let connection = self.connection_headers();
        let mut fields: Vec<(&str, &str)> = vec![];
        let html = self.0.get("content-type").map_or(false, |t|
            matches!(parse_content_type_header(t),
                     Ok(MediaType {primary_type, sub_type, ..})
                         if primary_type.eq_ignore_ascii_case("text") && sub_type.eq_ignore_ascii_case("html")));
        let link;
        match (skip_process_link, self.0.get("link")) {
            (false, Some(value)) => {
                link = process_link_header(value, fallback_url, header_integrity_fetcher).await;
                if !link.is_empty() {
                    fields.push(("link", &link));
                }
            }
            (true, Some(value)) if !value.is_empty() => fields.push(("link", value)),
            _ => (),
        }
        for (k, v) in self.0.iter() {
            if STRIP_RESPONSE_HEADERS.contains(k.as_str())
                || DONT_SIGN_RESPONSE_HEADERS.contains(k.as_str())
                || connection.contains(k)
            {
                continue;
            }
            if !html
                && (STRIP_SUBRESOURCE_RESPONSE_HEADERS.contains(k.as_str())
                    || crate::id_headers::ID_HEADERS.contains(k.as_str()))
            {
                continue;
            }
            if k == "link" {
                // Handled above.
                continue;
            }
            fields.push((k, v));
        }
        let status_code = status_code.to_string();
        let digest = format!("mi-sha256-03={}", ::base64::encode(mice_digest));
        fields.push((":status", &status_code));
        fields.push(("content-encoding", "mi-sha256-03"));
        fields.push(("digest", &digest));
        serializer(fields)
    }
    pub async fn get_signed_headers_bytes(
        &self,
        fallback_url: &Url,
        status_code: u16,
        mice_digest: &[u8],
        header_integrity_fetcher: &mut dyn HeaderIntegrityFetcher,
        skip_process_link: bool,
    ) -> Vec<u8> {
        self.get_signed_headers(
            fallback_url,
            status_code,
            mice_digest,
            header_integrity_fetcher,
            |fields| {
                use crate::cbor::DataItem;
                let cbor_data = DataItem::Map(
                    fields
                        .iter()
                        .map(|(key, value)| {
                            (
                                DataItem::ByteString(key.as_bytes()),
                                DataItem::ByteString(value.as_bytes()),
                            )
                        })
                        .collect(),
                );
                cbor_data.serialize()
            },
            skip_process_link,
        )
        .await
    }
    // Connection-specific headers per
    // https://datatracker.ietf.org/doc/html/rfc7230#section-6.1.
    // These headers should be removed before signing per
    // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#section-4.1-2.1.
    pub fn connection_headers(&self) -> HashSet<String> {
        // OWS is defined at https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.3.
        const OWS: &[char] = &[' ', '\t'];
        match self.0.get("connection") {
            None => HashSet::new(),
            Some(connection) => connection
                .split(',')
                .map(|w| w.trim_matches(OWS).to_ascii_lowercase())
                .collect(),
        }
    }
    // How long the signature should last, or error if the response shouldn't be signed.
    pub fn signature_duration(&self) -> Result<Duration> {
        // Default to 7 days unless a cache-control directive lowers it.
        // Only look at the most specific cache-control header present. This follows the requirement
        // in https://datatracker.ietf.org/doc/html/draft-cdn-control-header-01#section-2.1.
        let value = CACHE_CONTROL_HEADERS
            .iter()
            .find_map(|name| self.0.get(*name));
        if let Some(value) = value {
            if let Ok(duration) = parse_cache_control_header(value) {
                // https://github.com/google/webpackager/blob/main/docs/cache_requirements.md
                const MIN_DURATION: Duration = Duration::from_secs(120);
                return if duration >= MIN_DURATION {
                    Ok(duration)
                } else {
                    Err(anyhow!("Validity duration is too short."))
                };
            }
        }
        Ok(Duration::MAX)
    }
}

// These headers are always stripped before signing, but preserved when serving unsigned (e.g.
// direct or same-origin navigations, or non-prefetched subresources).
static STRIP_RESPONSE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    vec![
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-uncached-header-fields
        "connection",
        "keep-alive",
        "proxy-connection",
        "trailer",
        "transfer-encoding",
        "upgrade",
        // Include the HSTS header from
        // https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#stateful-headers
        // because it is an origin-wide (not URL-specific) header and origins shouldn't have to
        // choose between HSTS and SXG. (We shouldn't create an artificial reason to disable HSTS.)
        "strict-transport-security",
        // These headers are reserved for SXG
        ":status",
        "content-encoding",
        "digest",
        // These headers are prohibited by Google SXG cache
        // https://github.com/google/webpackager/blob/master/docs/cache_requirements.md
        "variant-key-04",
        "variants-04",
    ]
    .into_iter()
    .collect()
});

// These headers don't affect the semantics of the response inside an
// SXG, but they vary frequently. This prevents the SXG from being used
// as a subresource due to the header-integrity requirement:
// https://github.com/WICG/webpackage/blob/main/explainers/signed-exchange-subresource-substitution.md.
static STRIP_SUBRESOURCE_RESPONSE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    vec![
        // These headers are standard, but signed headers don't affect the
        // browser caching behavior, because the SXG is only stored in the
        // referring document's prefetch cache, per
        // https://wicg.github.io/webpackage/loading.html#document-prefetched-signed-exchanges-for-navigation.
        // The Date header could theoretically have an impact on SXG loading,
        // according to
        // https://wicg.github.io/webpackage/loading.html#mp-http-network-or-cache-fetch,
        // but I don't see evidence of that in
        // https://source.chromium.org/chromium/chromium/src/+/main:content/browser/web_package/.
        "age",
        "date",
        "expires",
        "last-modified",
        "server-timing",
        "via",
        "warning",
    ]
    .into_iter()
    .collect()
});

// These headers prevent signing, unless stripped by the strip_response_headers param.
static DONT_SIGN_RESPONSE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    vec![
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
    ]
    .into_iter()
    .collect()
});

// Cache-Control headers to respect, ordered from most to least specific.
static CACHE_CONTROL_HEADERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        // https://developers.cloudflare.com/cache/about/cdn-cache-control
        "cloudflare-cdn-cache-control",
        // https://developer.fastly.com/reference/http-headers/Surrogate-Control/
        // https://datatracker.ietf.org/doc/html/draft-nottingham-surrogates-00#section-3.6.2
        "surrogate-control",
        // https://datatracker.ietf.org/doc/html/draft-cdn-control-header-01
        "cdn-cache-control",
        // https://datatracker.ietf.org/doc/html/rfc7234#section-5.2
        "cache-control",
    ]
});

static CACHE_CONTROL_HEADERS_SET: Lazy<HashSet<&'static str>> =
    Lazy::new(|| CACHE_CONTROL_HEADERS.clone().into_iter().collect());

// Checks whether to serve SXG based on the Accept header of the HTTP request.
// Returns Ok iff the input string has a `application/signed-exchange;v=b3`,
// and either accept_filter != PrefersSxg or its `q` value is 1.
pub fn parse_accept_level(accept: &str) -> AcceptLevel {
    let accept = accept.trim();
    let accept = match parse_accept_header(accept) {
        Ok(accept) => accept,
        Err(_) => return AcceptLevel::RejectsSxg,
    };
    if accept.is_empty() {
        return AcceptLevel::RejectsSxg;
    }
    let q_sxg = accept
        .iter()
        .filter_map(|t| {
            if t.media_range
                .primary_type
                .eq_ignore_ascii_case("application")
                && t.media_range
                    .sub_type
                    .eq_ignore_ascii_case("signed-exchange")
            {
                let mut v = "";
                for param in &t.media_range.parameters {
                    if param.name.eq_ignore_ascii_case("v") {
                        v = &param.value;
                    }
                }
                if v == "b3" {
                    Some(t.q_millis)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .max()
        .unwrap_or(0);
    if q_sxg == 0 {
        AcceptLevel::RejectsSxg
    } else if q_sxg == 1000 {
        AcceptLevel::PrefersSxg
    } else {
        AcceptLevel::AcceptsSxg
    }
}

fn parse_chrome_major_version(user_agent: &str) -> Option<u32> {
    parse_number_after(user_agent, " Chrome/")
        .or_else(|| parse_number_after(user_agent, " Chromium/"))
}

// Find the substring coming after `pattern`, and parse it as a number.
fn parse_number_after(input: &str, pattern: &str) -> Option<u32> {
    let i = input.find(pattern)? + pattern.len();
    if i >= input.len() {
        return None;
    }
    let (x, _) = input[i..].split_once('.')?;
    x.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_integrity::tests::null_integrity_fetcher;
    use std::iter::FromIterator;

    fn header_fields<T: FromIterator<(String, String)>>(pairs: Vec<(&str, &str)>) -> T {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn headers(pairs: Vec<(&str, &str)>) -> Headers {
        Headers::new(header_fields(pairs), &BTreeSet::new())
    }

    // === new ===
    #[test]
    fn new_strips_headers() {
        assert_eq!(
            Headers::new(
                header_fields(vec![("accept", "*/*"), ("forwarded", "for=192.168.7.1")]),
                &vec!["forwarded".to_string()].into_iter().collect()
            )
            .0,
            header_fields(vec![("accept", "*/*")])
        );
    }

    #[test]
    fn duplicate_headers() {
        assert_eq!(
            headers(vec![
                ("accept", "application/json"),
                ("ACcEpt", "application/xml")
            ])
            .0,
            header_fields(vec![("accept", "application/json,application/xml")])
        )
    }

    // === forward_to_origin_server ===
    #[test]
    fn basic_request_headers() {
        assert_eq!(
            headers(vec![("accept", "application/signed-exchange;v=b3")])
                .forward_to_origin_server(AcceptLevel::PrefersSxg, &BTreeSet::new())
                .unwrap()
                .into_iter()
                .collect::<HashMap<String, String>>(),
            header_fields(vec![("user-agent", USER_AGENT), ("via", "sxgrs")])
        );
    }
    #[test]
    fn upstream_via_header() {
        assert_eq!(
            headers(vec![
                ("accept", "application/signed-exchange;v=b3"),
                ("via", "nginx")
            ])
            .forward_to_origin_server(AcceptLevel::PrefersSxg, &BTreeSet::new())
            .unwrap()
            .into_iter()
            .collect::<HashMap<String, String>>(),
            header_fields(vec![("user-agent", USER_AGENT), ("via", "nginx, sxgrs")])
        );
    }
    #[test]
    fn authenticated_request_headers() {
        assert_eq!(
            headers(vec![
                ("accept", "application/signed-exchange;v=b3"),
                ("authorization", "x")
            ])
            .forward_to_origin_server(AcceptLevel::PrefersSxg, &BTreeSet::new())
            .unwrap_err()
            .to_string(),
            "The request contains an Authorization header."
        );
    }

    #[test]
    fn accept_level_ord() {
        assert!(AcceptLevel::RejectsSxg < AcceptLevel::AcceptsSxg);
        assert!(AcceptLevel::AcceptsSxg < AcceptLevel::PrefersSxg);
    }

    // === parse_accept_level ===
    #[test]
    fn prefers_sxg() {
        assert_eq!(
            parse_accept_level("application/signed-exchange;v=b3"),
            AcceptLevel::PrefersSxg
        );
        assert_eq!(
            parse_accept_level("application/signed-exchange;v=b3;q=1"),
            AcceptLevel::PrefersSxg
        );
        assert_eq!(
            parse_accept_level(
                "  application/signed-exchange  ;  v=b3  ;  q=1  ,  */*  ;  q=0.8  ",
            ),
            AcceptLevel::PrefersSxg
        );
        assert_eq!(
            parse_accept_level("text/html;q=0.5,application/signed-exchange;V=b3;Q=1"),
            AcceptLevel::PrefersSxg
        );
        assert_eq!(
            parse_accept_level("text/html;q=0.5,application/signed-exchange;v=b3"),
            AcceptLevel::PrefersSxg
        );

        assert_eq!(
            parse_accept_level("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8"),
            AcceptLevel::AcceptsSxg
        );
        assert_eq!(
            parse_accept_level("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"),
            AcceptLevel::AcceptsSxg
        );
        assert_eq!(
            // A valid content type requires "v=b3" to come before "q"
            parse_accept_level("application/signed-exchange;q=1;v=b3"),
            AcceptLevel::RejectsSxg
        );
        assert_eq!(parse_accept_level(""), AcceptLevel::RejectsSxg);
        assert_eq!(
            parse_accept_level("application/signed-exchange"),
            AcceptLevel::RejectsSxg
        );
        assert_eq!(
            parse_accept_level("application/signed-exchange;v=b2"),
            AcceptLevel::RejectsSxg
        );
    }

    #[test]
    fn parse_chrome_major_version_works() {
        assert_eq!(parse_chrome_major_version("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/27.0.1453.110 Safari/537.36"), Some(27));
        assert_eq!(
            parse_chrome_major_version("Mozilla Chrome/11.22.33.44"),
            Some(11)
        );
        assert_eq!(
            parse_chrome_major_version("Mozilla Chromium/11.22.33"),
            Some(11)
        );
        assert_eq!(parse_chrome_major_version("Mozilla Chrome/11.22"), Some(11));
        assert_eq!(parse_chrome_major_version("Mozilla Chrome/11"), None);
        assert_eq!(parse_chrome_major_version("Mozilla Chrome/a"), None);
        assert_eq!(parse_chrome_major_version("OtherChrome/11.22.33"), None);
        // Although this should be parsed as `Some(11)`,
        // we know that the User-Agent string of Chrome M73-M78 does not look like this.
        // Hence it is fine to parse it as `None`.
        assert_eq!(parse_chrome_major_version("Chrome/11.22.33"), None);
        assert_eq!(parse_chrome_major_version("Chrome/"), None);
        assert_eq!(parse_chrome_major_version("Chrome/."), None);
        assert_eq!(parse_chrome_major_version("Chrome/-1."), None);
        assert_eq!(parse_chrome_major_version("Internet Explorer"), None);
    }

    // === validate_as_sxg_payload ===
    #[test]
    fn response_headers_minimum_valid() {
        assert!(headers(vec![("content-type", "text/html")])
            .validate_as_sxg_payload()
            .is_ok());
    }
    #[test]
    fn response_headers_caching() {
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("cache-control", "max-age=1")
        ])
        .validate_as_sxg_payload()
        .is_ok());
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("cache-control", "private")
        ])
        .validate_as_sxg_payload()
        .is_err());
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("cdn-cache-control", "no-store")
        ])
        .validate_as_sxg_payload()
        .is_err());
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("cloudflare-cdn-cache-control", "no-cache")
        ])
        .validate_as_sxg_payload()
        .is_err());
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("surrogate-control", "max-age=0")
        ])
        .validate_as_sxg_payload()
        .is_err());
    }
    #[test]
    fn response_headers_stateful() {
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("clear-site-data", r#""*""#)
        ])
        .validate_as_sxg_payload()
        .is_err());
    }
    #[test]
    fn response_headers_size() {
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("content-length", "8000000")
        ])
        .validate_as_sxg_payload()
        .is_ok());
        assert!(headers(vec![
            ("content-type", "text/html"),
            ("content-length", "8000001")
        ])
        .validate_as_sxg_payload()
        .is_err());
    }

    // === connection_headers ===
    #[test]
    fn no_connection_headers() {
        assert_eq!(headers(vec![]).connection_headers(), HashSet::new());
    }
    #[test]
    fn some_connection_headers() {
        assert_eq!(
            headers(vec![("connection", " close\t,  transfer-ENCODING ")]).connection_headers(),
            vec!["close", "transfer-encoding"]
                .into_iter()
                .map(|s| s.into())
                .collect()
        );
    }

    // === signature_duration ===
    #[test]
    fn signature_duration_implicit() {
        assert_eq!(headers(vec![]).signature_duration().unwrap(), Duration::MAX);
    }
    #[test]
    fn signature_duration_explicit() {
        assert_eq!(
            headers(vec![("cache-control", "max-age=3600")])
                .signature_duration()
                .unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            headers(vec![("cache-control", "max-age=100")])
                .signature_duration()
                .unwrap_err()
                .to_string(),
            "Validity duration is too short."
        );
        assert_eq!(
            headers(vec![("cache-control", "max-age=100, s-maxage=3600")])
                .signature_duration()
                .unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            headers(vec![("cache-control", "max-age=3600, s-maxage=100")])
                .signature_duration()
                .unwrap_err()
                .to_string(),
            "Validity duration is too short."
        );
        assert_eq!(
            headers(vec![("cache-control", "max, max-age=3600")])
                .signature_duration()
                .unwrap(),
            Duration::from_secs(3600)
        );
    }
    #[test]
    fn signature_duration_most_specific() {
        assert_eq!(
            headers(vec![
                ("cache-control", "max-age=0"),
                ("cdn-cache-control", "max-age=3600"),
            ])
            .signature_duration()
            .unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            headers(vec![
                ("cache-control", "max-age=3600"),
                ("surrogate-control", "must-revalidate"),
            ])
            .signature_duration()
            .unwrap(),
            Duration::MAX
        );
    }
    #[test]
    fn signature_duration_parse_error() {
        assert_eq!(
            headers(vec![("cache-control", "max-age=fish")])
                .signature_duration()
                .unwrap(),
            Duration::MAX
        );
        assert_eq!(
            headers(vec![("cache-control", "doesn't even parse")])
                .signature_duration()
                .unwrap(),
            Duration::MAX
        );
        assert_eq!(
            headers(vec![("cache-control", "max=, max-age=3600")])
                .signature_duration()
                .unwrap(),
            Duration::MAX
        );
    }

    // === get_signed_headers ===
    #[tokio::test]
    async fn strip_id_headers() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            headers(vec![
                ("content-type", "image/jpeg"),
                ("x-request-id", "abcdef123")
            ])
            .get_signed_headers::<HashMap<String, String>, _>(
                &url,
                200,
                &[],
                &mut null_integrity_fetcher(),
                header_fields,
                false,
            )
            .await,
            header_fields::<HashMap<String, String>>(vec![
                ("content-type", "image/jpeg"),
                // x-request-id is missing
                (":status", "200"),
                ("content-encoding", "mi-sha256-03"),
                ("digest", "mi-sha256-03=")
            ])
        );
        assert_eq!(
            headers(vec![
                ("content-type", "text/html;charset=utf-8"),
                ("x-request-id", "abcdef123")
            ])
            .get_signed_headers::<HashMap<String, String>, _>(
                &url,
                200,
                &[],
                &mut null_integrity_fetcher(),
                header_fields,
                false,
            )
            .await,
            header_fields::<HashMap<String, String>>(vec![
                ("content-type", "text/html;charset=utf-8"),
                ("x-request-id", "abcdef123"),
                (":status", "200"),
                ("content-encoding", "mi-sha256-03"),
                ("digest", "mi-sha256-03=")
            ])
        );
    }
    #[tokio::test]
    async fn includes_link_if_valid() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            headers(vec![
                ("content-type", "text/html"),
                ("link", "</foo>;rel=preload,</foo>;rel=allowed-alt-sxg;header-integrity=blah")
            ])
            .get_signed_headers::<HashMap<String, String>, _>(
                &url,
                200,
                &[],
                &mut null_integrity_fetcher(),
                header_fields,
                false,
            )
            .await,
            header_fields::<HashMap<String, String>>(vec![
                ("content-type", "text/html"),
                ("link", "<https://foo.com/foo>;rel=preload,<https://foo.com/foo>;rel=allowed-alt-sxg;header-integrity=blah"),
                (":status", "200"),
                ("content-encoding", "mi-sha256-03"),
                ("digest", "mi-sha256-03=")
            ])
        );
        assert_eq!(
            headers(vec![
                ("content-type", "text/html"),
                ("link", r#"</foo>;rel=preload"#)
            ])
            .get_signed_headers::<HashMap<String, String>, _>(
                &url,
                200,
                &[],
                &mut null_integrity_fetcher(),
                header_fields,
                false
            )
            .await,
            header_fields::<HashMap<String, String>>(vec![
                ("content-type", "text/html"),
                (":status", "200"),
                ("content-encoding", "mi-sha256-03"),
                ("digest", "mi-sha256-03=")
            ])
        );
    }

    // === get_signed_headers_bytes ===
    #[tokio::test]
    async fn get_signed_headers_bytes() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(headers(vec![("content-type", "image/jpeg")]).get_signed_headers_bytes(&url, 200, &[], &mut null_integrity_fetcher(), false).await,
                   b"\xA4FdigestMmi-sha256-03=G:statusC200Lcontent-typeJimage/jpegPcontent-encodingLmi-sha256-03");
    }
}
