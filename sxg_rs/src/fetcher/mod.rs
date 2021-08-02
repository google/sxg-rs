#[cfg(feature="js_fetcher")]
pub mod js_fetcher;

use async_trait::async_trait;
use crate::http::{HttpRequest, HttpResponse};

#[async_trait(?Send)]
pub trait Fetcher {
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

