use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sxg_rs::acme::Account as AcmeAccount;
use sxg_rs::crypto::EcPrivateKey;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Artifact {
    pub acme_account: Option<AcmeAccount>,
    pub acme_private_key: Option<EcPrivateKey>,
    pub acme_private_key_instructions: BTreeMap<String, String>,
    pub cloudflare_kv_namespace_id: Option<String>,
    pub fastly_service_id: Option<String>,
    pub fastly_dictionary_id: Option<String>,
}
