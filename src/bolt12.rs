use std::{str::FromStr, sync::Arc};

use bitcoin::{
    key::{Keypair, Secp256k1, Verification},
    secp256k1::{PublicKey, Signing},
};
use lightning::{
    blinded_path::{
        message::{BlindedMessagePath, MessageContext, OffersContext},
        payment::{
            BlindedPaymentPath, Bolt12OfferContext, PaymentConstraints, PaymentContext,
            UnauthenticatedReceiveTlvs,
        },
        EmptyNodeIdLookUp,
    },
    ln::inbound_payment::ExpandedKey,
    offers::{
        invoice::{Bolt12Invoice, UnsignedBolt12Invoice},
        invoice_request::{InvoiceRequest, InvoiceRequestFields},
        nonce::Nonce,
        offer::{Offer, OfferBuilder, OfferId},
    },
    onion_message::{
        messenger::{create_onion_message, Destination, OnionMessagePath},
        offers::OffersMessage,
    },
    sign::{KeysManager, RandomBytes},
    types::payment::{PaymentHash, PaymentSecret},
    util::{ser::Writeable, string::UntrustedString},
};
use rand::RngCore;

pub fn create_offer<C: Signing + Verification>(
    signing_key: &Keypair,
    cln: &PublicKey,
    secp: &Secp256k1<C>,
) -> Offer {
    let entropy_source = entropy_source();
    let message_context = MessageContext::Offers(OffersContext::InvoiceRequest {
        nonce: Nonce::from_entropy_source(&entropy_source),
    });

    let offer = OfferBuilder::new(signing_key.public_key())
        .chain(bitcoin::Network::Regtest)
        // TODO: do we want more hops?
        .path(BlindedMessagePath::one_hop(*cln, message_context, &entropy_source, &secp).unwrap())
        .build()
        .unwrap();

    offer
}

pub fn create_invoice(
    keypair: &Keypair,
    cln: &PublicKey,
    payment_hash: &[u8; 32],
    invoice_request: InvoiceRequest,
) -> Bolt12Invoice {
    let entropy_source = entropy_source();
    let secp_ctx = Secp256k1::new();

    let nonce = Nonce::from_entropy_source(&entropy_source);
    let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
        // TODO: use offer id from offer
        offer_id: OfferId([42; 32]),
        invoice_request: InvoiceRequestFields {
            payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
            quantity: invoice_request.quantity(),
            payer_note_truncated: invoice_request
                .payer_note()
                .map(|s| UntrustedString(s.to_string())),
            human_readable_name: None,
        },
    });

    let mut payment_secret = [42; 32];
    rand::thread_rng().fill_bytes(&mut payment_secret);
    let payee_tlvs = UnauthenticatedReceiveTlvs {
        payment_secret: PaymentSecret(payment_secret),
        payment_constraints: PaymentConstraints {
            max_cltv_expiry: 1_000_000,
            htlc_minimum_msat: 1,
        },
        payment_context,
    };

    let expanded_key = ExpandedKey::new(keypair.secret_key().secret_bytes());
    let payee_tlvs = payee_tlvs.authenticate(nonce, &expanded_key);

    // TODO: more hops?
    let payment_path =
        BlindedPaymentPath::one_hop(*cln, payee_tlvs, 144, &entropy_source, &secp_ctx).unwrap();

    let unsigned = invoice_request
        .respond_with(vec![payment_path], PaymentHash(*payment_hash))
        .unwrap();

    unsigned
        .build()
        .unwrap()
        .sign(|msg: &UnsignedBolt12Invoice| {
            Ok(secp_ctx.sign_schnorr_no_aux_rand(msg.as_ref().as_digest(), keypair))
        })
        .unwrap()
}

fn entropy_source() -> RandomBytes {
    let mut entropy_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy_bytes);
    RandomBytes::new(entropy_bytes)
}

pub fn blind_onion(invoice: Bolt12Invoice, first_node_id: String, hops: Vec<String>) {
    let entropy = entropy_source();

    let mut entropy_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy_bytes);
    let keysmanager = KeysManager::new(&entropy_bytes, 0, 0);

    let secp_ctx = Secp256k1::new();

    let onion = create_onion_message(
        &Box::new(entropy),
        &Box::new(keysmanager),
        &EmptyNodeIdLookUp {},
        &secp_ctx,
        OnionMessagePath {
            intermediate_nodes: hops
                .into_iter()
                .map(|s| PublicKey::from_str(&s).unwrap())
                .collect(),
            destination: Destination::Node(PublicKey::from_str(&first_node_id).unwrap()),
            first_node_addresses: None,
        },
        OffersMessage::Invoice(invoice),
        None,
    )
    .unwrap();
    println!(
        "Blinding point: {:?}",
        hex::encode(onion.1.blinding_point.serialize())
    );
    let packet = onion.1.onion_routing_packet;
    let mut packet_bytes = vec![];
    packet.write(&mut packet_bytes).unwrap();
    println!("Packet: {:?}", hex::encode(packet_bytes));
}

/*

    let expanded_key = ExpandedKey::new([42; 32]);
    let entropy_source = Randomness {};
    let nonce = Nonce::from_entropy_source(&entropy_source);
    let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
        offer_id: OfferId([42; 32]),
        invoice_request: InvoiceRequestFields {
            payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
            quantity: invoice_request.quantity(),
            payer_note_truncated: invoice_request
                .payer_note()
                .map(|s| UntrustedString(s.to_string())),
            human_readable_name: None,
        },
    });
    let payee_tlvs = UnauthenticatedReceiveTlvs {
        payment_secret: PaymentSecret([42; 32]),
        payment_constraints: PaymentConstraints {
            max_cltv_expiry: 1_000_000,
            htlc_minimum_msat: 1,
        },
        payment_context,
    };
    let payee_tlvs = payee_tlvs.authenticate(nonce, &expanded_key);
    let intermediate_nodes = [PaymentForwardNode {
        tlvs: ForwardTlvs {
            short_channel_id: 43,
            payment_relay: PaymentRelay {
                cltv_expiry_delta: 40,
                fee_proportional_millionths: 1_000,
                fee_base_msat: 1,
            },
            payment_constraints: PaymentConstraints {
                max_cltv_expiry: payee_tlvs.tlvs().payment_constraints.max_cltv_expiry + 40,
                htlc_minimum_msat: 100,
            },
            features: BlindedHopFeatures::empty(),
            next_blinding_override: None,
        },
        node_id: pubkey(43),
        htlc_maximum_msat: 1_000_000_000_000,
    }];
    let payment_path = BlindedPaymentPath::new(
        &intermediate_nodes,
        pubkey(42),
        payee_tlvs,
        u64::MAX,
        MIN_FINAL_CLTV_EXPIRY_DELTA,
        &entropy_source,
        secp_ctx,
    )
    .unwrap();
*/
