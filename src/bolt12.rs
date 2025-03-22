use bitcoin::{
    bech32::{self, Hrp},
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
    },
    ln::inbound_payment::ExpandedKey,
    offers::{
        invoice::{Bolt12Invoice, UnsignedBolt12Invoice},
        invoice_request::{InvoiceRequest, InvoiceRequestFields},
        nonce::Nonce,
        offer::{Offer, OfferBuilder, OfferId},
    },
    sign::RandomBytes,
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
        .path(BlindedMessagePath::one_hop(*cln, message_context, &entropy_source, secp).unwrap())
        .build()
        .unwrap();

    offer
}

pub fn create_invoice(
    offer_id: &OfferId,
    keypair: &Keypair,
    cln: &PublicKey,
    payment_hash: &[u8; 32],
    invoice_request: InvoiceRequest,
) -> Bolt12Invoice {
    let entropy_source = entropy_source();
    let secp_ctx = Secp256k1::new();

    let nonce = Nonce::from_entropy_source(&entropy_source);
    let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
        offer_id: *offer_id,
        invoice_request: InvoiceRequestFields {
            payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
            quantity: invoice_request.quantity(),
            payer_note_truncated: invoice_request
                .payer_note()
                .map(|s| UntrustedString(s.to_string())),
            human_readable_name: invoice_request.offer_from_hrn().clone(),
        },
    });

    let mut payment_secret = [0u8; 32];
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

pub fn encode_invoice(invoice: &Bolt12Invoice) -> String {
    let mut writer = Vec::new();
    invoice.write(&mut writer).unwrap();

    let hrp = Hrp::parse("lni").unwrap();
    bech32::encode::<bitcoin::bech32::NoChecksum>(hrp, &writer).unwrap()
}

fn entropy_source() -> RandomBytes {
    let mut entropy_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy_bytes);
    RandomBytes::new(entropy_bytes)
}
