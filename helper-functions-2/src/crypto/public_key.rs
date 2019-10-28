use milagro_bls::{Signature as RawSignature, PublicKey as RawPublicKey};
pub use milagro_bls::SecretKey;
use ssz::{Decode, DecodeError, Encode};
use std::default;
use rand;
use super::*;

// #[derive(Clone, Eq)]
pub struct PublicKey(RawPublicKey);

impl PublicKey {
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        PublicKey(RawPublicKey::from_secret_key(secret_key))
    }

    pub fn from_raw(raw: RawPublicKey) -> Self {
        Self(raw)
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawPublicKey {
        &self.0
    }

    /// Returns the underlying point as compressed bytes.
    ///
    /// Identical to `self.as_uncompressed_bytes()`.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.as_raw().as_bytes()
    }

    /// Converts compressed bytes to PublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        match RawPublicKey::from_bytes(&bytes) {
            Err(_) => {
                Err(DecodeError::BytesInvalid("Invalid PublicKey bytes: {:?}.".to_string()))
            }
            Ok(raw_pubkey) => Ok(PublicKey(raw_pubkey))
        }
    }

    /// Returns the PublicKey as (x, y) bytes
    pub fn as_uncompressed_bytes(&self) -> Vec<u8> {
        RawPublicKey::as_uncompressed_bytes(&mut self.0.clone())
    }

    /// Converts (x, y) bytes to PublicKey
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        match RawPublicKey::from_uncompressed_bytes(&bytes) {
            Err(_) => {
                Err(DecodeError::BytesInvalid("Invalid PublicKey uncompressed bytes.".to_string()))
            }
            Ok(raw_pubkey) => Ok(PublicKey(raw_pubkey))
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.as_ssz_bytes() == other.as_ssz_bytes()
    }
}

impl default::Default for PublicKey {
    fn default() -> Self {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        PublicKey::from_secret_key(&secret_key)
    }

}

impl ssz::Encode for PublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        BLS_PUBLIC_KEY_BYTE_SIZE
    }

    fn ssz_bytes_len(&self) -> usize {
        BLS_PUBLIC_KEY_BYTE_SIZE
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.as_bytes())
    }
}

impl ssz::Decode for PublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        BLS_PUBLIC_KEY_BYTE_SIZE
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as ssz::Decode>::ssz_fixed_len();

        if len != expected {
            Err(ssz::DecodeError::InvalidByteLength { len, expected })
        } else {
            PublicKey::from_bytes(bytes)
        }
    }
}