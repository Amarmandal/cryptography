use base64::Engine;
use std::fs;

use ring::{
    rand,
    signature::{self, KeyPair},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    const MESSAGE: &[u8] = b"Hello, world";
    const _WRONG_MESSAGE: &[u8] = b"hfsafa";
    let sig = key_pair.sign(MESSAGE);

    let peer_public_key_bytes = key_pair.public_key().as_ref();

    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
    match peer_public_key.verify(MESSAGE, sig.as_ref()) {
        Ok(_) => println!("Successful Verification"),
        Err(e) => eprintln!("Verification failed {}", e),
    }

    let base64_encoded =
        base64::engine::general_purpose::STANDARD.encode(&key_pair.public_key().as_ref());

    let pem_data = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        base64_encoded
    );

    fs::write("ed25519_key.pem", pem_data)?;

    println!("Success!");

    Ok(())
}
