use crate::error::SchnorrError;
use crate::util::{
    scalar_from_be_bytes, scalar_from_le_bytes, scalar_to_fixed_be_bytes, scalar_to_fixed_le_bytes,
    serialize_point, words32_from_scalar, words32_to_scalar,
};
use ibig::UBig;
use nockchain_math_core::crypto::cheetah::{ch_scal_big, CheetahPoint, G_ORDER};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretKey {
    scalar: UBig,
    bytes_le: [u8; 32],
}

impl SecretKey {
    pub fn from_bytes_le(bytes: [u8; 32]) -> Result<Self, SchnorrError> {
        let scalar = scalar_from_le_bytes(&bytes);
        if scalar == UBig::from(0u8) {
            return Err(SchnorrError::ZeroSecretKey);
        }
        if scalar >= *G_ORDER {
            return Err(SchnorrError::SecretKeyOutOfRange);
        }
        Ok(Self {
            scalar,
            bytes_le: bytes,
        })
    }

    pub fn from_words32_le(words: &[u32; 8]) -> Result<Self, SchnorrError> {
        let mut bytes = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        Self::from_bytes_le(bytes)
    }

    pub fn from_bytes_be(bytes: [u8; 32]) -> Result<Self, SchnorrError> {
        let scalar = scalar_from_be_bytes(&bytes);
        if scalar == UBig::from(0u8) {
            return Err(SchnorrError::ZeroSecretKey);
        }
        if scalar >= *G_ORDER {
            return Err(SchnorrError::SecretKeyOutOfRange);
        }
        let mut le = bytes;
        le.reverse();
        Ok(Self {
            scalar,
            bytes_le: le,
        })
    }

    pub fn scalar(&self) -> &UBig {
        &self.scalar
    }

    pub fn bytes_le(&self) -> &[u8; 32] {
        &self.bytes_le
    }

    pub fn bytes_be(&self) -> [u8; 32] {
        let mut be = self.bytes_le;
        be.reverse();
        be
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        scalar_to_fixed_be_bytes(&self.scalar)
    }

    pub fn words32_le(&self) -> [u32; 8] {
        words32_from_scalar(&self.scalar)
    }

    pub fn public_key(&self) -> Result<PublicKey, SchnorrError> {
        let point = ch_scal_big(&self.scalar, &nockchain_math_core::crypto::cheetah::A_GEN)?;
        Ok(PublicKey(point))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey(pub CheetahPoint);

impl PublicKey {
    pub fn into_point(self) -> CheetahPoint {
        self.0
    }

    pub fn as_point(&self) -> &CheetahPoint {
        &self.0
    }

    pub fn to_base58(&self) -> Result<String, SchnorrError> {
        Ok(self.0.into_base58()?)
    }

    pub fn from_base58(encoded: &str) -> Result<Self, SchnorrError> {
        Ok(Self(CheetahPoint::from_base58(encoded)?))
    }

    pub fn to_bytes(&self) -> [u8; 97] {
        serialize_point(&self.0)
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};

        let serialized = self.to_bytes();
        let sha = Sha256::digest(&serialized);
        let ripemd = Ripemd160::digest(&sha);
        ripemd[..4].try_into().expect("fingerprint slice")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    pub challenge: UBig,
    pub response: UBig,
}

impl Signature {
    pub fn new(challenge: UBig, response: UBig) -> Self {
        Self {
            challenge,
            response,
        }
    }

    pub fn challenge_words32(&self) -> [u32; 8] {
        words32_from_scalar(&self.challenge)
    }

    pub fn response_words32(&self) -> [u32; 8] {
        words32_from_scalar(&self.response)
    }

    pub fn challenge_bytes_le(&self) -> [u8; 32] {
        scalar_to_fixed_le_bytes(&self.challenge)
    }

    pub fn response_bytes_le(&self) -> [u8; 32] {
        scalar_to_fixed_le_bytes(&self.response)
    }

    pub fn challenge_bytes_be(&self) -> [u8; 32] {
        scalar_to_fixed_be_bytes(&self.challenge)
    }

    pub fn response_bytes_be(&self) -> [u8; 32] {
        scalar_to_fixed_be_bytes(&self.response)
    }

    pub fn from_words32_le(challenge: &[u32; 8], response: &[u32; 8]) -> Self {
        let challenge_scalar = words32_to_scalar(challenge);
        let response_scalar = words32_to_scalar(response);
        Signature::new(challenge_scalar, response_scalar)
    }
}
