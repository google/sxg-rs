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

use std::collections::{BTreeMap, HashMap, HashSet};
use once_cell::sync::Lazy;
use crate::http::HeaderFields;

#[derive(Debug)]
pub struct Headers(HashMap<String, String>);

// A default mobile user agent, for when the upstream request doesn't include one.
const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36";

impl Headers {
    pub fn new(data: HeaderFields) -> Self {
        let mut headers = Headers(HashMap::new());
        for (mut k, v) in data.into_iter() {
            k.make_ascii_lowercase();
            headers.0.insert(k, v);
        }
        headers
    }
    pub fn forward_to_origin_server(self, forwarded_header_names: &HashSet<String>) -> Result<HeaderFields, String> {
        if self.0.contains_key("authorization") {
            // We should not sign personalized content, but we cannot anonymize this request per
            // https://datatracker.ietf.org/doc/html/rfc7235#section-4.2:
            // "A proxy forwarding a request MUST NOT modify any Authorization fields in that request."
            return Err("The request contains an Authorization header.".to_string());
        }
        let accept = self.0.get("accept").ok_or("The request does not have accept header")?;
        validate_accept_header(accept)?;
        // Set Via per https://tools.ietf.org/html/rfc7230#section-5.7.1
        let mut via = format!("sxgrs");
        if let Some(upstream_via) = self.0.get("via") {
            via = format!("{}, {}", upstream_via, via);
        }
        // new_headers is ordered to make testing easier.
        let mut new_headers: BTreeMap<String, String> = self.0.into_iter().filter_map(|(k, v)| {
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
    pub fn validate_as_sxg_payload(&self, reject_stateful_headers: bool) -> Result<(), String> {
        for (k, v) in self.0.iter() {
            if reject_stateful_headers && STATEFUL_HEADERS.contains(k.as_str()) {
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
    pub fn get_signed_headers_bytes(&self, status_code: u16, mice_digest: &[u8]) -> Vec<u8> {
        use crate::cbor::DataItem;
        let mut fields: Vec<(&str, &str)> = vec![];
        for (k, v) in self.0.iter() {
            if UNCACHED_HEADERS.contains(k.as_str()) || STATEFUL_HEADERS.contains(k.as_str()) {
                continue;
            }
            fields.push((k, v));
        }
        let status_code = status_code.to_string();
        let digest = format!("mi-sha256-03={}", ::base64::encode(&mice_digest));
        fields.push((":status", &status_code));
        fields.push(("content-encoding", "mi-sha256-03"));
        fields.push(("digest", &digest));
        let cbor_data = DataItem::Map(
            fields.iter().map(|(key, value)| {
                (DataItem::ByteString(key.as_bytes()), DataItem::ByteString(value.as_bytes()))
            }).collect()
        );
        cbor_data.serialize()
    }
}

static UNCACHED_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
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

static STATEFUL_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
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

// Checks whether accept header of a http request, return an Err when the input
// string does not have an `application/signed-exchange;v=b3` with the highest
// `q` value.
fn validate_accept_header(accept: &str) -> Result<(), String> {
    let accept = accept.trim();
    let accept = crate::http_parser::parse_accept_header(accept)?;
    if accept.len() == 0 {
        return Err(format!("Accept header is empty"));
    }
    let q_max = accept.iter().map(|t| t.q_millis).max().unwrap();
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
    const SXG: &'static str = "application/signed-exchange;v=b3";
    if q_sxg == 0 {
        Err(format!("The request accept header does not contain {}.", SXG))
    } else if q_sxg < q_max {
        Err(format!("The q value of {} is not the max in request accept header", SXG))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use super::*;

    fn header_fields(pairs: Vec<(&str, &str)>) -> HeaderFields {
        pairs.into_iter().map(|(k,v)| (k.to_string(), v.to_string())).collect()
    }
    fn headers(pairs: Vec<(&str, &str)>) -> Headers {
        Headers::new(header_fields(pairs))
    }
    fn assert_contains<T, U: 'static>(result: Result<T, U>, value: T) where T: Debug + PartialEq, U: Debug + Send {
      assert!(result.is_ok(), result.unwrap_err());
      assert_eq!(result.unwrap(), value);
    }
    fn assert_contains_err<T: 'static, U>(result: Result<T, U>, err: U) where T: Debug + Send, U: Debug + PartialEq {
      assert!(result.is_err(), result.unwrap());
      assert_eq!(result.unwrap_err(), err);
    }

    // === forward_to_origin_server ===
    #[test]
    fn basic_request_headers() {
      assert_contains(headers(vec![("accept", "application/signed-exchange;v=b3")]).forward_to_origin_server(&HashSet::new()),
                      header_fields(vec![("user-agent", USER_AGENT), ("via", "sxgrs")]));
    }
    #[test]
    fn authenticated_request_headers() {
      assert_contains_err(headers(vec![("accept", "application/signed-exchange;v=b3"), ("authorization", "x")]).forward_to_origin_server(&HashSet::new()),
                          "The request contains an Authorization header.".to_string());
    }

    // === validate_accept_header ===
    #[test]
    fn basic_accept_header() {
        assert!(validate_accept_header("application/signed-exchange;v=b3").is_ok());
        assert!(validate_accept_header("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8").is_ok());
        assert!(validate_accept_header("").is_err());
        assert!(validate_accept_header("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").is_err());
    }
    #[test]
    fn optional_whitespaces() {
        assert!(validate_accept_header("  application/signed-exchange  ;  v=b3  ;  q=0.9  ,  */*  ;  q=0.8  ").is_ok());
    }
    #[test]
    fn uppercase_q_and_v() {
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;V=b3;Q=0.6").is_ok());
    }
    #[test]
    fn default_q() {
        assert!(validate_accept_header("text/html;q=0.5,application/signed-exchange;v=b3").is_ok());
    }
    #[test]
    fn missing_v() {
        assert!(validate_accept_header("application/signed-exchange").is_err());
    }
    #[test]
    fn v_is_not_b3() {
        assert!(validate_accept_header("application/signed-exchange;v=b2").is_err());
    }

    // === validate_as_sxg_payload ===
    #[test]
    fn response_headers_minimum_valid() {
        assert!(headers(vec![("content-type", "text/html")]).validate_as_sxg_payload(true).is_ok());
    }
    #[test]
    fn response_headers_caching() {
        assert!(headers(vec![("content-type", "text/html"), ("cache-control", "max-age=1")]).validate_as_sxg_payload(true).is_ok());
        assert!(headers(vec![("content-type", "text/html"), ("cache-control", "private")]).validate_as_sxg_payload(true).is_err());
        assert!(headers(vec![("content-type", "text/html"), ("cdn-cache-control", "no-store")]).validate_as_sxg_payload(true).is_err());
        assert!(headers(vec![("content-type", "text/html"), ("cloudflare-cdn-cache-control", "no-cache")]).validate_as_sxg_payload(true).is_err());
        assert!(headers(vec![("content-type", "text/html"), ("surrogate-control", "max-age=0")]).validate_as_sxg_payload(true).is_err());
    }
    #[test]
    fn response_headers_stateful() {
        assert!(headers(vec![("content-type", "text/html"), ("clear-site-data", r#""*""#)]).validate_as_sxg_payload(true).is_err());
    }
    #[test]
    fn response_headers_size() {
        assert!(headers(vec![("content-type", "text/html"), ("content-length", "8000000")]).validate_as_sxg_payload(true).is_ok());
        assert!(headers(vec![("content-type", "text/html"), ("content-length", "8000001")]).validate_as_sxg_payload(true).is_err());
    }
}
