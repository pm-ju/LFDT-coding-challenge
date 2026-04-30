use generic_ec::{Curve, Point};

use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<E: Curve> {
    pub(crate) ephemeral: Point<E>,
    pub(crate) body: Vec<u8>,
}

impl<E: Curve> Ciphertext<E> {
    pub fn ephemeral(&self) -> &Point<E> {
        &self.ephemeral
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let r = self.ephemeral.to_bytes(true);
        let r = r.as_ref();
        let mut buf = Vec::with_capacity(r.len() + self.body.len());
        buf.extend_from_slice(r);
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point_len = Point::<E>::serialized_len(true);
        if bytes.len() <= point_len {
            return Err(Error::InvalidCiphertext);
        }

        let (r_bytes, body) = bytes.split_at(point_len);
        let ephemeral = Point::<E>::from_bytes(r_bytes).map_err(|_| Error::InvalidPointEncoding)?;

        Ok(Self {
            ephemeral,
            body: body.to_vec(),
        })
    }

    pub fn encoded_len(&self) -> usize {
        Point::<E>::serialized_len(true) + self.body.len()
    }
}
