use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

const BOLTZ_API_URL: &str = "http://127.0.0.1:9001";

#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

pub type Nodes = HashMap<String, HashMap<String, Node>>;

pub async fn nodes() -> Result<Nodes> {
    let nodes: Nodes = reqwest::get(format!("{}/v2/nodes", BOLTZ_API_URL))
        .await?
        .json()
        .await?;
    Ok(nodes)
}
