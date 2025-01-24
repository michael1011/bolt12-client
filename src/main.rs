use bitcoin::hex::DisplayHex;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::PublicKey;
use std::str::FromStr;

mod bolt12;
mod boltz;
mod hooks;
mod keys;

#[tokio::main]
async fn main() {
    let nodes = boltz::nodes().await.unwrap();
    let cln = nodes
        .get("BTC")
        .unwrap()
        .get("CLN")
        .unwrap()
        .public_key
        .clone();
    println!("Boltz CLN node: {}", cln);
    let cln = PublicKey::from_str(&cln).unwrap();

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let signing_key = keys::get_signing_key(&secp, &mut rng);
    println!(
        "Signing key: {}",
        signing_key.public_key().serialize().as_hex()
    );

    let offer = bolt12::create_offer(&signing_key, &cln, &secp);
    println!("Offer: {}", offer.to_string());

    hooks::listen_webhooks(hooks::State {
        cln,
        keypair: signing_key,
    })
    .await;
}
