use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Signing;
use bitcoin::{key::Secp256k1, secp256k1::Keypair};
use rand::RngCore;
use std::fs;

const KEYS_FILE: &str = "keys";

pub fn get_signing_key<C: Signing>(secp: &Secp256k1<C>, rng: &mut impl RngCore) -> Keypair {
    if fs::exists(KEYS_FILE).unwrap() {
        let key = fs::read_to_string(KEYS_FILE).unwrap();
        Keypair::from_seckey_str(secp, &key).unwrap()
    } else {
        let keypair = Keypair::new(secp, rng);
        fs::write(
            KEYS_FILE,
            keypair
                .secret_bytes()
                .to_hex_string(bitcoin::hex::Case::Lower),
        )
        .unwrap();
        keypair
    }
}
