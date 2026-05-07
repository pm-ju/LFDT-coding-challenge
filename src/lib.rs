#![doc = include_str!("../readme.md")]
#![forbid(unsafe_code)]

mod expand;

pub mod ciphertext;
pub mod decrypt;
pub mod encrypt;
pub mod error;

pub use ciphertext::Ciphertext;
pub use decrypt::{decrypt, decrypt_from_bytes};
pub use encrypt::{encrypt, encrypt_to_bytes};
pub use error::Error;

#[cfg(test)]
mod tests;
