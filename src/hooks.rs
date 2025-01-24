use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use bitcoin::{key::Keypair, secp256k1::PublicKey};
use lightning::{
    offers::{invoice_request::InvoiceRequest, offer::Offer},
    onion_message::{messenger::create_onion_message, offers::OffersMessage},
    util::ser::Writeable,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::bolt12;

const ADDR: &str = "127.0.0.1:7678";

#[derive(Debug, Deserialize)]
pub struct OnionReplyPath {
    pub first_node_id: String,
    pub hops: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebhookRequest {
    pub invoice_request: String,
    pub path: OnionReplyPath,
}

#[derive(Debug, Serialize)]
struct WebhookResponse {
    pub invoice: String,
}

pub struct State {
    pub keypair: Keypair,
    pub cln: PublicKey,
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
    Json(body): Json<WebhookRequest>,
) -> impl IntoResponse {
    println!("Received webhook request: {:#?}", body);

    let req = hex::decode(body.invoice_request).unwrap();
    let invoice_request = InvoiceRequest::try_from(req).unwrap();

    // TODO: random payment hash
    let invoice =
        crate::bolt12::create_invoice(&state.keypair, &state.cln, &[0u8; 32], invoice_request);
    println!("Created invoice");

    bolt12::blind_onion(invoice, body.path.first_node_id, body.path.hops);

    (
        StatusCode::OK,
        Json(WebhookResponse {
            invoice: "".to_string(),
        }),
    )
        .into_response()
}
