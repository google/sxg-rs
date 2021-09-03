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

use crate::http_parser::{
    parse_accept_header,
    parse_cache_control_header,
    parse_content_type_header,
    parse_link_header,
    link::Link,
    media_type::MediaType,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use once_cell::sync::Lazy;
use crate::http::HeaderFields;
use serde::Deserialize;
use std::cmp::min;
use std::time::Duration;
use url::Url;

#[derive(Debug)]
pub struct Headers(HashMap<String, String>);

// Which requestors to serve an SXG to.
#[derive(Deserialize)]
pub enum AcceptFilter {
    // Those whose Accept header indicates they prefer an SXG over the unsigned
    // version. That is, SXG caches and crawlers only.
    PrefersSxg,
    // Those whose Accept header indicates they accept an SXG, but generally
    // prefer the unsigned version. That is, SXG-capable browsers plus the above.
    AcceptsSxg,
}

// A default mobile user agent, for when the upstream request doesn't include one.
const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36";

// Maximum signature duration per https://wicg.github.io/webpackage/draft-yasskin-http-origin-signed-responses.html#section-3.5-7.3.
const SEVEN_DAYS: Duration = Duration::from_secs(60 * 60 * 24 * 7);

impl Headers {
    pub fn new(data: HeaderFields, strip_headers: &BTreeSet<String>) -> Self {
        let mut headers = Headers(HashMap::new());
        for (mut k, v) in data {
            k.make_ascii_lowercase();
            if !strip_headers.contains(&k) {
                headers.0.insert(k, v);
            }
        }
        headers
    }
    pub fn forward_to_origin_server(self, accept_filter: AcceptFilter, forwarded_header_names: &BTreeSet<String>) -> Result<HeaderFields, String> {
        if self.0.contains_key("authorization") {
            // We should not sign personalized content, but we cannot anonymize this request per
            // https://datatracker.ietf.org/doc/html/rfc7235#section-4.2:
            // "A proxy forwarding a request MUST NOT modify any Authorization fields in that request."
            return Err("The request contains an Authorization header.".to_string());
        }
        let accept = self.0.get("accept").ok_or("The request does not have an Accept header")?;
        validate_accept_header(accept, accept_filter)?;
        // Set Via per https://tools.ietf.org/html/rfc7230#section-5.7.1
        let mut via = format!("sxgrs");
        if let Some(upstream_via) = self.0.get("via") {
            via = format!("{}, {}", upstream_via, via);
        }
        // new_headers is ordered to make testing easier.
        let mut new_headers: HashMap<String, String> = self.0.into_iter().filter_map(|(k, v)| {
            let v = if forwarded_header_names.contains(&k) {
                v
            } else if k == "via" {
                format!("{}, {}", v, via)
            } else {
                return None;
            };
            Some((k, v))
        }).collect();
        let default_values = vec![
            ("user-agent", USER_AGENT),
            ("via", &via),
        ];
        for (k, v) in default_values {
            if new_headers.contains_key(k) == false {
                new_headers.insert(k.to_string(), v.to_string());
            }
        }
        Ok(new_headers.into_iter().collect())
    }
    pub fn validate_as_sxg_payload(&self) -> Result<(), String> {
        for (k, v) in self.0.iter() {
            if DONT_SIGN_RESPONSE_HEADERS.contains(k.as_str()) {
                return Err(format!(r#"A stateful header "{}" is found."#, k));
            }
            if CACHE_CONTROL_HEADERS.contains(k.as_str()) {
                // `private` and `no-store` are disallowed by
                // https://github.com/google/webpackager/blob/master/docs/cache_requirements.md#user-content-google-sxg-cache,
                // while the other two are signals that the document is not usually cached and reused.
                if v.contains("private") || v.contains("no-store") || v.contains("no-cache") || v.contains("max-age=0") {
                    return Err(format!(r#"The {} header is "{}"."#, k, v));
                }
            }
        }
        // Google SXG cache sets the maximum of SXG to be 8 megabytes.
        if let Some(size) = self.0.get("content-length") {
            if let Ok(size) = size.parse::<u64>() {
                const MAX_SIZE: u64 = 8_000_000;
                if size > MAX_SIZE {
                    return Err(format!("The content-length header is {}, which exceeds the limit {}.", size, MAX_SIZE));
                }
            } else {
                return Err(format!(r#"The content-length header "{}" is not a valid length."#, size));
            }
        }
        // The payload of SXG must have a content-type. See step 8 of
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
        if self.0.contains_key("content-type") == false {
            return Err(format!("The content-type header is missing."));
        }
        Ok(())
    }
    // Filters the link header to comply with
    // https://github.com/google/webpackager/blob/main/docs/cache_requirements.md.
    fn process_link_header(value: &str, fallback_url: &Url) -> String {
        static ALLOWED_PARAM: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            vec!["as", "header-integrity", "media", "rel", "imagesrcset", "imagesizes", "crossorigin"].into_iter().collect()});
        static ALLOWED_REL: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            vec!["preload", "allowed-alt-sxg"].into_iter().collect()});
        static ALLOWED_CROSSORIGIN: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            vec!["", "anonymous"].into_iter().collect()});
        match parse_link_header(value) {
            Ok(links) => {
                let mut count = 0;
                links.into_iter().filter_map(|link| {
                    let uri: String = fallback_url.join(&link.uri).ok()?.into();
                    let params_valid = link.params.iter().all(|(k, v)|
                        ALLOWED_PARAM.contains(k) &&
                        match *k {
                            "rel" => matches!(v, Some(v) if ALLOWED_REL.contains(v.as_str())),
                            "crossorigin" => matches!(v, Some(v) if ALLOWED_CROSSORIGIN.contains(v.as_str())),
                            _ => true,
                        }
                    );
                    if params_valid {
                        if link.params.iter().any(|(k,v)| *k == "rel" && matches!(v, Some(v) if v == "preload")) {
                            if count >= 20 {
                                return None
                            }
                            count += 1;
                        }
                        Some(Link{uri: &uri, ..link}.serialize())
                    } else {
                        None
                    }
                }).collect::<Vec<String>>().join(",")
            },
            Err(_) => "".into(),
        }
    }
    // Returns the signed headers via the serializer callback instead of return
    // value, because it contains a mix of &str and String. This makes it easy
    // to test the intermediate Vec<(&str, &str)> without sacrificing
    // performance by copying it into a Vec<(String, String)>.
    fn get_signed_headers<O, F>(&self, fallback_url: &Url, status_code: u16, mice_digest: &[u8], serializer: F) -> O
        where F: Fn(Vec<(&str, &str)>) -> O {
        let connection = self.connection_headers();
        let mut fields: Vec<(&str, &str)> = vec![];
        let html = self.0.get("content-type").map_or(false, |t|
            matches!(parse_content_type_header(t),
                     Ok(MediaType {primary_type, sub_type, ..})
                         if primary_type.eq_ignore_ascii_case("text") && sub_type.eq_ignore_ascii_case("html")));
        let link = self.0.get("link").map_or("".into(), |value| Self::process_link_header(value, fallback_url));
        if !link.is_empty() {
            fields.push(("link", &link));
        }
        for (k, v) in self.0.iter() {
            if STRIP_RESPONSE_HEADERS.contains(k.as_str()) || DONT_SIGN_RESPONSE_HEADERS.contains(k.as_str()) || connection.contains(k) {
                continue;
            }
            if !html && (STRIP_SUBRESOURCE_RESPONSE_HEADERS.contains(k.as_str()) || crate::id_headers::ID_HEADERS.contains(k.as_str())) {
                continue;
            }
            if k == "link" {
                // Handled above.
                continue;
            }
            fields.push((k, v));
        }
        let status_code = status_code.to_string();
        let digest = format!("mi-sha256-03={}", ::base64::encode(&mice_digest));
        fields.push((":status", &status_code));
        fields.push(("content-encoding", "mi-sha256-03"));
        fields.push(("digest", &digest));
        serializer(fields)
    }
    pub fn get_signed_headers_bytes(&self, fallback_url: &Url, status_code: u16, mice_digest: &[u8]) -> Vec<u8> {
        self.get_signed_headers(fallback_url, status_code, mice_digest, |fields| {
            use crate::cbor::DataItem;
            let cbor_data = DataItem::Map(
                fields.iter().map(|(key, value)| {
                    (DataItem::ByteString(key.as_bytes()), DataItem::ByteString(value.as_bytes()))
                }).collect()
            );
            cbor_data.serialize()
        })
    }
    // Connection-specific headers per
    // https://datatracker.ietf.org/doc/html/rfc7230#section-6.1.
    // These headers should be removed before signing per
    // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#section-4.1-2.1.
    fn connection_headers(&self) -> HashSet<String> {
        // OWS is defined at https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.3.
        const OWS: &[char] = &[' ', '\t'];
        match self.0.get("connection") {
            None => HashSet::new(),
            Some(connection) => connection.split(',').map(|w| w.trim_matches(OWS).to_ascii_lowercase()).collect()
        }
    }
    // How long the signature should last, or error if the response shouldn't be signed.
    pub fn signature_duration(&self) -> Result<Duration, String> {
        // Default to 7 days unless a cache-control directive lowers it.
        if let Some(value) = self.0.get("cache-control") {
            if let Ok(duration) = parse_cache_control_header(value) {
                // https://github.com/google/webpackager/blob/main/docs/cache_requirements.md
                const MIN_DURATION: Duration = Duration::from_secs(120);
                return if duration >= MIN_DURATION {
                    Ok(min(SEVEN_DAYS, duration))
                } else {
                    Err("Validity duration is too short.".into())
                }

            }
        }
        Ok(SEVEN_DAYS)
    }
}

// These headers are always stripped before signing.
static STRIP_RESPONSE_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    vec![
        // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-uncached-header-fields
        "connection",
        "keep-alive",
        "proxy-connection",
        "trailer",
        "transfer-encoding",
        "upgrade",

        // These headers are reserved for SXG
        ":status",
        "content-encoding",
        "digest",

        // These headers are prohibited by Google SXG cache
        // https://github.com/google/webpackager/blob/master/docs/cache_requirements.md
        "variant-key-04",
        "variants-04",

    ].into_iter().collect()
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
    ].into_iter().collect()
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
    ].into_iter().collect()
});

static CACHE_CONTROL_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    vec![
        // https://datatracker.ietf.org/doc/html/rfc7234#section-5.2
        "cache-control",
        // https://developers.cloudflare.com/cache/about/cdn-cache-control
        "cdn-cache-control",
        "cloudflare-cdn-cache-control",
        // https://developer.fastly.com/reference/http-headers/Surrogate-Control/
        "surrogate-control",
    ].into_iter().collect()
});

// Checks whether to serve SXG based on the Accept header of the HTTP request.
// Returns Ok iff the input string has a `application/signed-exchange;v=b3`,
// and either accept_filter != PrefersSxg or its `q` value is 1.
fn validate_accept_header(accept: &str, accept_filter: AcceptFilter) -> Result<(), String> {
    let accept = accept.trim();
    let accept = parse_accept_header(accept)?;
    if accept.len() == 0 {
        return Err(format!("Accept header is empty"));
    }
    let q_sxg = accept.iter().filter_map(|t| {
        if t.media_range.primary_type.eq_ignore_ascii_case("application") && t.media_range.sub_type.eq_ignore_ascii_case("signed-exchange") {
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
    }).max().unwrap_or(0);
    const SXG: &str = "application/signed-exchange;v=b3";
    if q_sxg == 0 {
        Err(format!("The request accept header does not contain {}.", SXG))
    } else {
        match accept_filter {
            AcceptFilter::PrefersSxg => {
                if q_sxg == 1000 {
                    Ok(())
                } else {
                    Err(format!("The q value of {} is less than 1 in request Accept header.", SXG))
                }
            },
            AcceptFilter::AcceptsSxg => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;
    use super::*;

    fn header_fields<T: FromIterator<(String, String)>>(pairs: Vec<(&str, &str)>) -> T {
        pairs.into_iter().map(|(k,v)| (k.to_string(), v.to_string())).collect()
    }
    fn headers(pairs: Vec<(&str, &str)>) -> Headers {
        Headers::new(header_fields(pairs), &BTreeSet::new())
    }

    // === new ===
    #[test]
    fn new_strips_headers() {
        assert_eq!(Headers::new(header_fields(vec![("accept", "*/*"), ("forwarded", "for=192.168.7.1")]), &vec!["forwarded".to_string()].into_iter().collect()).0,
                   header_fields(vec![("accept", "*/*")]));
    }

    // === forward_to_origin_server ===
    #[test]
    fn basic_request_headers() {
      assert_eq!(headers(vec![("accept", "application/signed-exchange;v=b3")]).forward_to_origin_server(AcceptFilter::PrefersSxg, &BTreeSet::new()).unwrap().into_iter().collect::<HashMap<String, String>>(),
                 header_fields(vec![("user-agent", USER_AGENT), ("via", "sxgrs")]));
    }
    #[test]
    fn authenticated_request_headers() {
      assert_eq!(headers(vec![("accept", "application/signed-exchange;v=b3"), ("authorization", "x")]).forward_to_origin_server(AcceptFilter::PrefersSxg, &BTreeSet::new()).unwrap_err(),
                 "The request contains an Authorization header.".to_string());
    }

    // === validate_accept_header ===
    #[test]
    fn prefers_sxg() {
        assert!(validate_accept_header("application/signed-exchange;v=b3", AcceptFilter::PrefersSxg).is_ok());
        assert!(validate_accept_header("application/signed-exchange;v=b3;q=1", AcceptFilter::PrefersSxg).is_ok());
        assert!(validate_accept_header("  application/signed-exchange  ;  v=b3  ;  q=1  ,  */*  ;  q=0.8  ", AcceptFilter::PrefersSxg).is_ok());
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;V=b3;Q=1", AcceptFilter::PrefersSxg).is_ok());
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;v=b3", AcceptFilter::PrefersSxg).is_ok());

        assert!(validate_accept_header("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8", AcceptFilter::PrefersSxg).is_err());
        assert!(validate_accept_header("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", AcceptFilter::PrefersSxg).is_err());
        assert!(validate_accept_header("application/signed-exchange;q=1;v=b3", AcceptFilter::PrefersSxg).is_err());
        assert!(validate_accept_header("", AcceptFilter::PrefersSxg).is_err());
        assert!(validate_accept_header("application/signed-exchange", AcceptFilter::PrefersSxg).is_err());
        assert!(validate_accept_header("application/signed-exchange;v=b2", AcceptFilter::PrefersSxg).is_err());
    }
    #[test]
    fn accepts_sxg() {
        // Same list as above, but some more are ok.
        assert!(validate_accept_header("application/signed-exchange;v=b3", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("application/signed-exchange;v=b3;q=1", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("  application/signed-exchange  ;  v=b3  ;  q=1  ,  */*  ;  q=0.8  ", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;V=b3;Q=1", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;v=b3", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8", AcceptFilter::AcceptsSxg).is_ok());
        assert!(validate_accept_header("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", AcceptFilter::AcceptsSxg).is_ok());

        assert!(validate_accept_header("application/signed-exchange;q=1;v=b3", AcceptFilter::AcceptsSxg).is_err());
        assert!(validate_accept_header("", AcceptFilter::AcceptsSxg).is_err());
        assert!(validate_accept_header("application/signed-exchange", AcceptFilter::AcceptsSxg).is_err());
        assert!(validate_accept_header("application/signed-exchange;v=b2", AcceptFilter::AcceptsSxg).is_err());
    }

    // === validate_as_sxg_payload ===
    #[test]
    fn response_headers_minimum_valid() {
        assert!(headers(vec![("content-type", "text/html")]).validate_as_sxg_payload().is_ok());
    }
    #[test]
    fn response_headers_caching() {
        assert!(headers(vec![("content-type", "text/html"), ("cache-control", "max-age=1")]).validate_as_sxg_payload().is_ok());
        assert!(headers(vec![("content-type", "text/html"), ("cache-control", "private")]).validate_as_sxg_payload().is_err());
        assert!(headers(vec![("content-type", "text/html"), ("cdn-cache-control", "no-store")]).validate_as_sxg_payload().is_err());
        assert!(headers(vec![("content-type", "text/html"), ("cloudflare-cdn-cache-control", "no-cache")]).validate_as_sxg_payload().is_err());
        assert!(headers(vec![("content-type", "text/html"), ("surrogate-control", "max-age=0")]).validate_as_sxg_payload().is_err());
    }
    #[test]
    fn response_headers_stateful() {
        assert!(headers(vec![("content-type", "text/html"), ("clear-site-data", r#""*""#)]).validate_as_sxg_payload().is_err());
    }
    #[test]
    fn response_headers_size() {
        assert!(headers(vec![("content-type", "text/html"), ("content-length", "8000000")]).validate_as_sxg_payload().is_ok());
        assert!(headers(vec![("content-type", "text/html"), ("content-length", "8000001")]).validate_as_sxg_payload().is_err());
    }

    // === connection_headers ===
    #[test]
    fn no_connection_headers() {
        assert_eq!(headers(vec![]).connection_headers(), HashSet::new());
    }
    #[test]
    fn some_connection_headers() {
        assert_eq!(headers(vec![("connection", " close\t,  transfer-ENCODING ")]).connection_headers(), vec!["close", "transfer-encoding"].into_iter().map(|s| s.into()).collect());
    }

    // === signature_duration ===
    #[test]
    fn signature_duration_implicit() {
        assert_eq!(headers(vec![]).signature_duration().unwrap(), SEVEN_DAYS);
    }
    #[test]
    fn signature_duration_explicit() {
        assert_eq!(headers(vec![("cache-control", "max-age=3600")]).signature_duration().unwrap(), Duration::from_secs(3600));
        assert_eq!(headers(vec![("cache-control", "max-age=100")]).signature_duration().unwrap_err(), "Validity duration is too short.");
        assert_eq!(headers(vec![("cache-control", "max-age=100, s-maxage=3600")]).signature_duration().unwrap(), Duration::from_secs(3600));
        assert_eq!(headers(vec![("cache-control", "max-age=3600, s-maxage=100")]).signature_duration().unwrap_err(), "Validity duration is too short.");
        assert_eq!(headers(vec![("cache-control", "max, max-age=3600")]).signature_duration().unwrap(), Duration::from_secs(3600));
    }
    #[test]
    fn signature_duration_parse_error() {
        assert_eq!(headers(vec![("cache-control", "max-age=fish")]).signature_duration().unwrap(), SEVEN_DAYS);
        assert_eq!(headers(vec![("cache-control", "doesn't even parse")]).signature_duration().unwrap(), SEVEN_DAYS);
        assert_eq!(headers(vec![("cache-control", "max=, max-age=3600")]).signature_duration().unwrap(), SEVEN_DAYS);
    }

    // === process_link_header ===
    #[test]
    fn process_link_header() {
        use std::iter::repeat;
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(Headers::process_link_header(r#"<https://foo.com/> ; rel = "preload""#, &url),
                   "<https://foo.com/>;rel=preload");
        {
            let link = "<https://foo.com/>;rel=preload";
            assert_eq!(Headers::process_link_header(&repeat(link).take(21).collect::<Vec<&str>>().join(","), &url),
                       repeat(link).take(20).collect::<Vec<&str>>().join(","));
        }
        {
            let link = r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#;
            assert_eq!(Headers::process_link_header(&repeat(link).take(21).collect::<Vec<&str>>().join(","), &url),
                       repeat(link).take(20).collect::<Vec<&str>>().join(",") + r#",<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        }
        assert_eq!(Headers::process_link_header("</foo>;rel=preload", &url),
                   "<https://foo.com/foo>;rel=preload");
        assert_eq!(Headers::process_link_header("<../quux>;rel=preload", &url.join("/bar/baz/").unwrap()),
                   "<https://foo.com/bar/quux>;rel=preload");
        assert_eq!(Headers::process_link_header("<https://foo.com/>;rel=prefetch", &url),
                   "");
        assert_eq!(Headers::process_link_header("<https://foo.com/>;other", &url),
                   "");
        assert_eq!(Headers::process_link_header("<https://foo.com/>;rel=preload,<https://foo.com/>;rel=prefetch", &url),
                   "<https://foo.com/>;rel=preload");
        assert_eq!(Headers::process_link_header(r#"<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w""#, &url),
                   r#"<https://foo.com/img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w""#);
    }

    // === get_signed_headers ===
    #[test]
    fn strip_id_headers() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(headers(vec![("content-type", "image/jpeg"), ("x-request-id", "abcdef123")]).get_signed_headers::<HashMap<String, String>, _>(&url, 200, &[], header_fields),
                   header_fields::<HashMap<String, String>>(vec![
                       ("content-type", "image/jpeg"),
                       // x-request-id is missing
                       (":status", "200"),
                       ("content-encoding", "mi-sha256-03"),
                       ("digest", "mi-sha256-03=")]));
        assert_eq!(headers(vec![("content-type", "text/html;charset=utf-8"), ("x-request-id", "abcdef123")]).get_signed_headers::<HashMap<String, String>, _>(&url, 200, &[], header_fields),
                   header_fields::<HashMap<String, String>>(vec![
                       ("content-type", "text/html;charset=utf-8"),
                       ("x-request-id", "abcdef123"),
                       (":status", "200"),
                       ("content-encoding", "mi-sha256-03"),
                       ("digest", "mi-sha256-03=")]));
    }
    #[test]
    fn includes_link_if_valid() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(headers(vec![("content-type", "text/html"), ("link", "<https://foo.com/>;rel=preload")]).get_signed_headers::<HashMap<String, String>, _>(&url ,200, &[], header_fields),
                   header_fields::<HashMap<String, String>>(vec![
                       ("content-type", "text/html"),
                       ("link", "<https://foo.com/>;rel=preload"),
                       (":status", "200"),
                       ("content-encoding", "mi-sha256-03"),
                       ("digest", "mi-sha256-03=")]));
        assert_eq!(headers(vec![("content-type", "text/html"), ("link", r#"</foo>;rel=prefetch"#)]).get_signed_headers::<HashMap<String, String>, _>(&url, 200, &[], header_fields),
                   header_fields::<HashMap<String, String>>(vec![
                       ("content-type", "text/html"),
                       (":status", "200"),
                       ("content-encoding", "mi-sha256-03"),
                       ("digest", "mi-sha256-03=")]));
    }

    // === get_signed_headers_bytes ===
    #[test]
    fn get_signed_headers_bytes() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(headers(vec![("content-type", "image/jpeg")]).get_signed_headers_bytes(&url, 200, &[]),
                   b"\xA4FdigestMmi-sha256-03=G:statusC200Lcontent-typeJimage/jpegPcontent-encodingLmi-sha256-03");
    }
}
