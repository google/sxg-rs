use crate::http::HttpResponse;
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use js_sys::Function as JsFunction;
use wasm_bindgen::JsValue;

/// An interface for storing HTTP responses in a cache.
#[async_trait(?Send)]
pub trait HttpCache {
    async fn get(&mut self, url: &str) -> Result<HttpResponse>;
    async fn put(&mut self, url: &str, response: &HttpResponse) -> Result<()>;
}

pub struct NullCache;

#[async_trait(?Send)]
impl HttpCache for NullCache {
    async fn get(&mut self, _url: &str) -> Result<HttpResponse> {
        Err(anyhow!("No cache entry found in NullCache"))
    }
    async fn put(&mut self, _url: &str, _response: &HttpResponse) -> Result<()> {
        Ok(())
    }
}

pub struct JsHttpCache {
    pub get: JsFunction,
    pub put: JsFunction,
}

#[async_trait(?Send)]
impl HttpCache for JsHttpCache {
    async fn get(&mut self, url: &str) -> Result<HttpResponse> {
        let url = JsValue::from_serde(&url)
            .map_err(|e| Error::new(e).context("serializing url to JS"))?;
        let this = JsValue::null();
        let response = self
            .get
            .call1(&this, &url)
            .map_err(|_| anyhow!("Error invoking JS get"))?;
        let response = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(response));
        let response = response
            .await
            .map_err(|_| anyhow!("Error returned by JS get"))?;
        let response = response
            .into_serde()
            .map_err(|e| Error::new(e).context("parsing response from JS"))?;
        Ok(response)
    }
    async fn put(&mut self, url: &str, response: &HttpResponse) -> Result<()> {
        let url = JsValue::from_serde(&url)
            .map_err(|e| Error::new(e).context("serializing url to JS"))?;
        let response = JsValue::from_serde(&response)
            .map_err(|e| Error::new(e).context("serializing response to JS"))?;
        let this = JsValue::null();
        let ret = self
            .put
            .call2(&this, &url, &response)
            .map_err(|_| anyhow!("Error invoking JS put"))?;
        let ret = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(ret));
        let ret = ret.await.map_err(|_| anyhow!("Error returned by JS put"))?;
        let _ret = ret
            .into_serde()
            .map_err(|e| Error::new(e).context("parsing ack from JS"))?;
        Ok(())
    }
}
