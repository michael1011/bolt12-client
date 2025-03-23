use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

const BOLTZ_API_URL: &str = "http://127.0.0.1:9006";

#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

pub type Nodes = HashMap<String, HashMap<String, Node>>;

#[derive(Debug, Clone, Deserialize)]
pub struct MagicRoutingHint {
    #[serde(rename = "channelId")]
    pub channel_id: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Bolt12Params {
    #[serde(rename = "minCltv")]
    pub min_cltv: u64,
    #[serde(rename = "magicRoutingHint")]
    pub magic_routing_hint: MagicRoutingHint,
}

pub async fn nodes() -> Result<Nodes> {
    let nodes: Nodes = reqwest::get(format!("{}/v2/nodes", BOLTZ_API_URL))
        .await?
        .json()
        .await?;
    Ok(nodes)
}

pub async fn bolt12_params(receiving_symbol: &str) -> Result<Bolt12Params> {
    Ok(reqwest::get(format!(
        "{}/v2/lightning/BTC/bolt12/{}",
        BOLTZ_API_URL, receiving_symbol
    ))
    .await?
    .json()
    .await?)
}
