use generic_ec::curves::{Ed25519, Secp256k1, Secp384r1};
use generic_ec::{Curve, Point, SecretScalar};
use lockness_challenge::{decrypt, encrypt_to_bytes, Ciphertext};
use rand::rngs::OsRng;

fn run<E: Curve>(label: &str) {
    let sk = SecretScalar::<E>::random(&mut OsRng);
    let pk = Point::generator() * &sk;

    let msg = b"Lockness Mentorship 2026";
    let ct_bytes = encrypt_to_bytes::<E>(&pk, msg, &mut OsRng).expect("encryption failed");
    let ct = Ciphertext::<E>::from_bytes(&ct_bytes).expect("deserialize failed");
    let plaintext = decrypt::<E>(&sk, &ct).expect("decryption failed");

    println!("[{}]", label);
    println!("  plaintext  : {}", String::from_utf8_lossy(msg));
    println!("  ciphertext : {}...", hex::encode(&ct_bytes[..16]));
    println!("  decrypted  : {}", String::from_utf8_lossy(&plaintext));
    println!("  ok         : {}", plaintext == msg);
    println!();
}

fn main() {
    run::<Secp256k1>("secp256k1");
    run::<Ed25519>("ed25519");
    run::<Secp384r1>("secp384r1");
}
