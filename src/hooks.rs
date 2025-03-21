use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use bitcoin::{key::Keypair, secp256k1::PublicKey};
use lightning::offers::{invoice_request::InvoiceRequest, offer::OfferId};
use rand::RngCore;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::bolt12;

const ADDR: &str = "127.0.0.1:7678";

#[derive(Debug, Serialize, Deserialize)]
pub struct OnionMessage {
    pub reply_blindedpath: Option<ReplyBlindedPath>,
    pub invoice_request: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReplyBlindedPath {
    pub first_node_id: Option<Vec<u8>>,
    pub first_scid: Option<String>,
    pub first_scid_dir: Option<u64>,
    pub blinded: Option<Vec<u8>>,
    pub hops: Vec<Hop>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hop {
    pub blinded_node_id: Option<Vec<u8>>,
    pub encrypted_recipient_data: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub blinding_point: String,
    pub onion: String,
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
    Json(body): Json<OnionMessage>,
) -> impl IntoResponse {
    println!("Received webhook request: {:#?}", body);

    let invoice_request = InvoiceRequest::try_from(body.invoice_request.clone()).unwrap();

    let mut payment_hash = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut payment_hash);

    let invoice = crate::bolt12::create_invoice(
        &state.offer_id,
        &state.keypair,
        &state.cln,
        &payment_hash,
        invoice_request.clone(),
    );
    println!(
        "Created invoice: {}",
        crate::bolt12::encode_invoice(&invoice)
    );

    let (blinding_point, onion) =
        bolt12::blind_onion(invoice, body.reply_blindedpath.unwrap(), state.cln);

    (
        StatusCode::OK,
        Json(WebhookResponse {
            onion: hex::encode(onion),
            blinding_point: hex::encode(blinding_point.serialize()),
        }),
    )
        .into_response()
}
