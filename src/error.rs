#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ciphertext too short to contain a valid ephemeral point")]
    InvalidCiphertext,

    #[error("failed to decode elliptic-curve point from ciphertext")]
    InvalidPointEncoding,

    #[error("plaintext must not be empty")]
    EmptyInput,
}
