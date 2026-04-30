use generic_ec::{Curve, Point, SecretScalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::ciphertext::Ciphertext;
use crate::error::Error;
use crate::expand::expand;

pub fn encrypt<E: Curve>(
    pk: &Point<E>,
    msg: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Ciphertext<E>, Error> {
    if msg.is_empty() {
        return Err(Error::EmptyInput);
    }
    let eph = SecretScalar::<E>::random(rng);
    encrypt_with_ephemeral(pk, msg, &eph)
}

pub(crate) fn encrypt_with_ephemeral<E: Curve>(
    pk: &Point<E>,
    msg: &[u8],
    eph: &SecretScalar<E>,
) -> Result<Ciphertext<E>, Error> {
    if msg.is_empty() {
        return Err(Error::EmptyInput);
    }

    let r = Point::<E>::generator() * eph;
    let s = pk * eph;
    let keystream = derive_keystream::<E>(&s, msg.len());
    let body = xor(msg, &keystream);

    Ok(Ciphertext { ephemeral: r, body })
}

pub(crate) fn derive_keystream<E: Curve>(shared: &Point<E>, len: usize) -> Vec<u8> {
    let encoded = shared.to_bytes(true);
    let mut hash = Sha256::digest(encoded.as_ref()).to_vec();
    let ks = expand(&hash, len);
    hash.zeroize();
    ks
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn encrypt_to_bytes<E: Curve>(
    pk: &Point<E>,
    msg: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, Error> {
    encrypt(pk, msg, rng).map(|ct| ct.to_bytes())
}

pub fn ciphertext_len<E: Curve>(plaintext_len: usize) -> usize {
    Point::<E>::serialized_len(true) + plaintext_len
}
