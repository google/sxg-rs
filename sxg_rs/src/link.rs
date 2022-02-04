use crate::header_integrity::HeaderIntegrityFetcher;
use crate::http_parser::{link::Link, parse_link_header};
use futures::{stream, stream::StreamExt};
use once_cell::sync::Lazy;
use std::cell::RefCell;
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
            let links = links.into_iter().filter(|link| {
                link.params.iter().all(|(k, v)| {
                    ALLOWED_PARAM.contains(k)
                        && match *k {
                            "rel" => matches!(v, Some(v) if ALLOWED_REL.contains(v.as_str())),
                            "crossorigin" => {
                                matches!(v, Some(v) if ALLOWED_CROSSORIGIN.contains(v.as_str()))
                            }
                            _ => true,
                        }
                })
            });

            let (mut preloads, allowed_alt_sxgs) = links
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

            let fallback_origin = fallback_url.origin();
            let directives = RefCell::new(vec![]);
            stream::iter(preloads)
                .for_each_concurrent(None, |link| async {
                    let link = link;
                    match allowed_alt_sxgs.get(&link.uri) {
                        Some(allowed_alt_sxg) => {
                            if let Ok(mut directives) = directives.try_borrow_mut() {
                                directives.push(link.clone());
                                directives.push(allowed_alt_sxg.clone());
                            }
                        }
                        None => {
                            if origin_is(&fallback_origin, &link.uri) {
                                if let Ok(integrity) =
                                    header_integrity_fetcher.fetch(&link.uri).await
                                {
                                    if let Ok(mut directives) = directives.try_borrow_mut() {
                                        directives.push(link.clone());
                                        directives.push(Link {
                                            uri: link.uri.clone(),
                                            params: vec![
                                                ("rel", Some("allowed-alt-sxg".into())),
                                                ("header-integrity", Some(integrity)),
                                            ],
                                        });
                                    }
                                }
                            }
                        }
                    };
                })
                .await;
            directives
                .take()
                .iter()
                .map(|link| link.serialize())
                .collect::<Vec<String>>()
                .join(",")
        }
        Err(_) => "".into(),
    }
}

fn get_param(params: &[(&str, Option<String>)], name: &str) -> Option<String> {
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
        async fn fetch(&self, _url: &str) -> Result<String> {
            self.0.clone().map_err(|e| anyhow!(e))
        }
    }

    #[async_std::test]
    async fn sanitizes_preloads() {
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header(
                r#"<https://foo.com/> ; rel = "preload",</>;rel=allowed-alt-sxg;header-integrity=blah"#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah"
        );

        let preloads: Vec<String> = (0..21)
            .map(|n| format!("<https://foo.com/{}.js>;rel=preload", n))
            .collect();
        assert_eq!(
            process_link_header(&preloads.join(","), &url, &mut null_integrity_fetcher()).await,
            ""
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
            process_link_header("</foo>;rel=preload,<https://foo.com/foo>;rel=allowed-alt-sxg;header-integrity=blah", &url, &mut null_integrity_fetcher()).await,
            "<https://foo.com/foo>;rel=preload,<https://foo.com/foo>;rel=allowed-alt-sxg;header-integrity=blah"
        );
        assert_eq!(
            process_link_header(
                "<../quux>;rel=preload,<../quux>;rel=allowed-alt-sxg;header-integrity=blah",
                &url.join("/bar/baz/").unwrap(),
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/bar/quux>;rel=preload,<https://foo.com/bar/quux>;rel=allowed-alt-sxg;header-integrity=blah"
        );
        assert_eq!(
            process_link_header(
                "<https://foo.com/>;rel=prefetch,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            ""
        );
        assert_eq!(
            process_link_header("</foo>", &url, &mut null_integrity_fetcher()).await,
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
                "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=prefetch,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah",
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            "<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity=blah"
        );
        assert_eq!(
            process_link_header(
                r#"<img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w",<img.jpg>;rel=allowed-alt-sxg;header-integrity=blah"#,
                &url,
                &mut null_integrity_fetcher()
            )
            .await,
            r#"<https://foo.com/img.jpg>;rel=preload;as=image;imagesizes=800px;imagesrcset="img.jpg 800w",<https://foo.com/img.jpg>;rel=allowed-alt-sxg;header-integrity=blah"#
        );
    }
    #[async_std::test]
    async fn fetch_header_integrity_ok() {
        let mut fetcher = FakeIntegrityFetcher(Ok(
            "sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into(),
        ));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher).await,
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
    async fn fetch_header_integrity_multiple() {
        let mut fetcher = FakeIntegrityFetcher(Ok(
            "sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into(),
        ));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</a>;rel=preload,</b>;rel=preload", &url, &mut fetcher).await,
            concat!(
                r#"<https://foo.com/a>;rel=preload,<https://foo.com/a>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=","#,
                r#"<https://foo.com/b>;rel=preload,<https://foo.com/b>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
            ),
        );
    }
    #[async_std::test]
    async fn fetch_header_integrity_out_of_order() {
        use crate::utils::tests::{out_of_order, OutOfOrderState};
        use futures::future::BoxFuture;
        struct OutOfOrderFetcher<F: Fn() -> BoxFuture<'static, Result<String>>>(F);
        #[async_trait(?Send)]
        impl<F: Fn() -> BoxFuture<'static, Result<String>>> HeaderIntegrityFetcher
            for OutOfOrderFetcher<F>
        {
            async fn fetch(&self, url: &str) -> Result<String> {
                println!("url = {}", url);
                self.0().await
            }
        }
        let state = OutOfOrderState::new();
        let mut fetcher = OutOfOrderFetcher(|| {
            out_of_order(state.clone(), || {
                Ok("sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=".into())
            })
        });
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</a>;rel=preload,</b>;rel=preload", &url, &mut fetcher).await,
            concat!(
                r#"<https://foo.com/b>;rel=preload,<https://foo.com/b>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=","#,
                r#"<https://foo.com/a>;rel=preload,"#,
                r#"<https://foo.com/a>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#
            ),
        );
    }
    #[async_std::test]
    async fn fetch_header_integrity_ok_none() {
        let mut fetcher = FakeIntegrityFetcher(Err("some error".into()));
        let url = Url::parse("https://foo.com").unwrap();
        assert_eq!(
            process_link_header("</>;rel=preload", &url, &mut fetcher).await,
            ""
        );
        assert_eq!(process_link_header(r#"</>;rel=preload,</>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
        assert_eq!(process_link_header(r#"</>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#,
        &url, &mut fetcher).await,
                   r#"<https://foo.com/>;rel=preload,<https://foo.com/>;rel=allowed-alt-sxg;header-integrity="sha256-OcpYAC5zFQtAXUURzXkMDDxMbxuEeWVjdRCDcLcBhBY=""#);
    }
}
