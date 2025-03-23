use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use bitcoin::{key::Keypair, secp256k1::PublicKey};
use bitcoin_hashes::Sha256;
use lightning::offers::{invoice_request::InvoiceRequest, offer::OfferId};
use rand::RngCore;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::boltz;

const ADDR: &str = "127.0.0.1:7678";

#[derive(Debug, Serialize, Deserialize)]
pub struct Data {
    #[serde(rename = "invoiceRequest")]
    pub invoice_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub data: Data,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub invoice: String,
}

pub struct State {
    pub keypair: Keypair,
    pub cln: PublicKey,
    pub offer_id: OfferId,
}

pub async fn listen_webhooks(state: State) {
    let app = Router::new()
        .route("/", post(handle_webhook))
        .layer(Extension(Arc::new(state)));

    println!("Listening for webhooks on {}", ADDR);
    let listener = TcpListener::bind(ADDR).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

pub async fn handle_webhook(
    Extension(state): Extension<Arc<State>>,
    Json(body): Json<Message>,
) -> impl IntoResponse {
    let invoice_request =
        InvoiceRequest::try_from(hex::decode(body.data.invoice_request.clone()).unwrap()).unwrap();

    let params = boltz::bolt12_params("L-BTC").await.unwrap();
    let magic_address = "el1qqwml59kfp9fn5dhq4g5jy680dt6pr6zrudlwvvyvnqxp02zzzr0tefcysmulpmvf7zq0e4jhl7zg0qkur5ks2x0rd9cz7lkqs";

    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    println!("Preimage: {}", hex::encode(preimage));
    let payment_hash = Sha256::hash(&preimage).to_byte_array();

    let (invoice, address_signature) = crate::bolt12::create_invoice(
        &state.offer_id,
        &state.keypair,
        &state.cln,
        &payment_hash,
        &params,
        Some(magic_address.to_string()),
        invoice_request.clone(),
    );
    let invoice = crate::bolt12::encode_invoice(&invoice);
    println!("Created invoice: {}", invoice);
    if let Some(address_signature) = address_signature {
        println!("Address signature: {}", hex::encode(address_signature));
    }

    (StatusCode::OK, Json(WebhookResponse { invoice })).into_response()
}
