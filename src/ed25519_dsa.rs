use ring::{
    error::Unspecified,
    pkcs8::Document,
    rand,
    signature::{self, Ed25519KeyPair, Signature},
};

pub fn generate_pkcs8() -> Result<Document, Unspecified> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng);

    pkcs8_bytes
}

pub fn sign_message(message: &[u8], pkcs8_bytes: &[u8]) -> (Ed25519KeyPair, Signature) {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();
    let sig = key_pair.sign(message);

    (key_pair, sig)
}

pub fn verify_message(message: &[u8], sig: Signature, public_key: &[u8]) {
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    match peer_public_key.verify(message, sig.as_ref()) {
        Ok(_) => println!("Successful Verification"),
        Err(e) => eprintln!("Verification failed {}", e),
    }
}
