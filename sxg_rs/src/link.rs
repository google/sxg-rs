use crate::header_integrity::HeaderIntegrityFetcher;
use crate::http_parser::{link::Link, parse_link_header};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use url::{Origin, Url};

// Filters the link header to comply with
// https://github.com/google/webpackager/blob/main/docs/cache_requirements.md,
// and adds allowed-alt-sxg with header-integrity if not present.
pub(crate) async fn process_link_header(
    value: &str,
    fallback_url: &Url,
    header_integrity_fetcher: &mut dyn HeaderIntegrityFetcher,
) -> String {
    static ALLOWED_PARAM: Lazy<HashSet<&'static str>> = Lazy::new(|| {
        vec![
            "as",
            "header-integrity",
            "media",
            "rel",
            "imagesrcset",
            "imagesizes",
            "crossorigin",
        ]
        .into_iter()
        .collect()
    });
    static ALLOWED_REL: Lazy<HashSet<&'static str>> =
        Lazy::new(|| vec!["preload", "allowed-alt-sxg"].into_iter().collect());
    static ALLOWED_CROSSORIGIN: Lazy<HashSet<&'static str>> =
        Lazy::new(|| vec!["", "anonymous"].into_iter().collect());
    match parse_link_header(value) {
        Ok(links) => {
            let links: Vec<Link> = links.into_iter().filter(|link|
                link.params.iter().all(|(k, v)|
                    ALLOWED_PARAM.contains(k) &&
                    match *k {
                        "rel" => matches!(v, Some(v) if ALLOWED_REL.contains(v.as_str())),
                        "crossorigin" => matches!(v, Some(v) if ALLOWED_CROSSORIGIN.contains(v.as_str())),
                        _ => true,
                    }
                )
            ).collect();

            let (mut preloads, allowed_alt_sxgs) = links
                .into_iter()
                .filter_map(|link| {
                    let uri: String = fallback_url.join(&link.uri).ok()?.into();
                    match get_param(&link.params, "rel") {
                        Some(rel) if ALLOWED_REL.contains(rel.as_str()) => {
                            Some((rel == "preload", Link { uri, ..link }))
                        }
                        _ => None,
                    }
                })
                .partition::<Vec<(bool, Link)>, _>(|(is_preload, _)| *is_preload);
            preloads.truncate(20);

            let preloads: Vec<Link> = preloads.into_iter().map(|(_, link)| link).collect();
            let allowed_alt_sxgs: HashMap<String, Link> = allowed_alt_sxgs
                .into_iter()
                .map(|(_, link)| (link.uri.clone(), link))
                .collect();

            let mut directives: Vec<String> = vec![];
            let fallback_origin = fallback_url.origin();
            for link in preloads {
                directives.push(link.serialize());
                match allowed_alt_sxgs.get(&link.uri) {
                    Some(allowed_alt_sxg) => directives.push(allowed_alt_sxg.serialize()),
                    None => {
                        if origin_is(&fallback_origin, &link.uri) {
                            // TODO: Make this fetch concurrent.
                            if let Ok(integrity) = header_integrity_fetcher.fetch(&link.uri).await {
                                directives.push(
                                    Link {
                                        uri: link.uri.clone(),
                                        params: vec![
                                            ("rel", Some("allowed-alt-sxg".into())),
                                            ("header-integrity", Some(integrity)),
                                        ],
                                    }
                                    .serialize(),
                                )
                            }
                        }
                    }
                };
            }
            directives.join(",")
        }
        Err(_) => "".into(),
    }
}

fn get_param(params: &Vec<(&str, Option<String>)>, name: &str) -> Option<String> {
    let values: Vec<&Option<String>> = params
        .iter()
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .collect();
    if values.len() == 1 {
        values[0].clone()
    } else {
        None
    }
}

fn origin_is(origin: &Origin, uri: &str) -> bool {
    Url::parse(uri).map_or(false, |u| &u.origin() == origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_integrity::tests::null_integrity_fetcher;
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;

    struct FakeIntegrityFetcher(std::result::Result<String, String>);

    #[async_trait(?Send)]
    impl HeaderIntegrityFetcher for FakeIntegrityFetcher {
        async fn fetch(&mut self, _url: &str) -> Result<String> {
            self.0.clone().map_err(|e| anyhow!(e))
        }
    }

    #[async_std::test]
    async fn sanitizes_preloads() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header(
                r#"<https://foo.com/> ; rel = "preload""#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload"
        );

        let preloads: Vec<String> = (0..21)
            .map(|n| format!("<https://foo.com/{}.js>;rel=preload", n))
            .collect();
        assert_eq!(
            process_link_header(&preloads.join(","), &url, &mut null_integrity_fetcher())
                .await,
            preloads
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<String>>()
                .join(",")
        );
        let allowed_alt_sxgs: Vec<String> = (0..20).map(|n|
            format!(r#"<https://foo.com/{}.js>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#, n)).collect();
        let preloads_mixed: Vec<String> = preloads
            .iter()
            .zip(allowed_alt_sxgs)
            .map(|(preload, allowed_alt_sxg)| preload.to_string() + "," + &allowed_alt_sxg)
            .collect();
        assert_eq!(
            process_link_header(
                &preloads_mixed.join(","),
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            preloads_mixed.join(",")
        );

        assert_eq!(
            process_link_header("</foo>;rel=preload", &url, &mut null_integrity_fetcher())
                .await,
            "<https://foo.com/foo>;rel=preload"
        );
        assert_eq!(
            process_link_header(
                "<../quux>;rel=preload",
                &url.join("/bar/baz/").unwrap(),
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/bar/quux>;rel=preload"
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;rel=prefetch",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header("</foo>", &url, &mut null_integrity_fetcher())
                .await,
            ""
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;other",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=prefetch",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload"
        );
        assert_eq!(
            process_link_header(
                r#"<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w""#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            r#"<https://foo.com/img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w""#
        );
    }
    #[async_std::test]
    async fn fetch_header_integrity_ok() {
        let mut fetcher = FakeIntegrityFetcher(Ok(
            "sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into(),
        ));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher)
                .await,
            r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
        );
        assert_eq!(process_link_header(r#"</>;rel=preload,</>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        assert_eq!(process_link_header(r#"</>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
    }
    #[async_std::test]
    async fn fetch_header_integrity_ok_none() {
        let mut fetcher = FakeIntegrityFetcher(Err("some error".into()));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher)
                .await,
            "<https://foo.com/>;rel=preload"
        );
        assert_eq!(process_link_header(r#"</>;rel=preload,</>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        assert_eq!(process_link_header(r#"</>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
    }
}
