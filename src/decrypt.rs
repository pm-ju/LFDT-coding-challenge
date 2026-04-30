use generic_ec::{Curve, SecretScalar};

use crate::ciphertext::Ciphertext;
use crate::encrypt::derive_keystream;
use crate::error::Error;

pub fn decrypt<E: Curve>(sk: &SecretScalar<E>, ct: &Ciphertext<E>) -> Result<Vec<u8>, Error> {
    if ct.body().is_empty() {
        return Err(Error::InvalidCiphertext);
    }

    let s = ct.ephemeral() * sk;
    let keystream = derive_keystream::<E>(&s, ct.body().len());

    Ok(ct
        .body()
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect())
}

pub fn decrypt_from_bytes<E: Curve>(sk: &SecretScalar<E>, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt(sk, &Ciphertext::<E>::from_bytes(bytes)?)
}
