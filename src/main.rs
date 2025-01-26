use base64::Engine;
use ed25519_dsa::{generate_pkcs8, sign_message, verify_message};
use ring::signature::KeyPair;
use std::fs;

mod ed25519_dsa;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8_bytes = generate_pkcs8().unwrap();

    const MESSAGE: &[u8] = b"Hello, world";
    const WRONG_MESSAGE: &[u8] = b"Verification will fail"; //substiture original message to pass verification
    let (key_pair, sig) = sign_message(MESSAGE, pkcs8_bytes.as_ref());

    let peer_public_key_bytes = key_pair.public_key().as_ref();
    verify_message(WRONG_MESSAGE, sig, peer_public_key_bytes);

    let base64_encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes.as_ref());
    let pem_data = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64_encoded
    );

    fs::write("ed25519_key.pem", pem_data)?;
    println!("Private key saved to ed25519_key.pem");

    println!("Success!");
    Ok(())
}
