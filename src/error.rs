use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchnorrError {
    #[error("secret key is zero")]
    ZeroSecretKey,
    #[error("secret key is not reduced modulo group order")]
    SecretKeyOutOfRange,
    #[error("derived nonce is zero; this indicates transcript collision")]
    ZeroNonce,
    #[error("challenge hash collapsed to zero")]
    ZeroChallenge,
    #[error("response component collapsed to zero")]
    ZeroSignature,
    #[error("group operation failed: {0}")]
    Math(&'static str),
    #[error("mnemonic error: {0}")]
    Mnemonic(String),
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    #[error("cannot derive hardened child from public key")]
    HardenedDerivationFromPublic,
    #[error("extended key error: {0}")]
    ExtendedKey(String),
    #[error("public key encoding error: {0}")]
    PublicKeyEncoding(String),
}

impl From<nockchain_math_core::math_error::MathError> for SchnorrError {
    fn from(err: nockchain_math_core::math_error::MathError) -> Self {
        SchnorrError::Math(match err {
            nockchain_math_core::math_error::MathError::DivisionByZero => "division by zero",
            nockchain_math_core::math_error::MathError::Field(_) => "field arithmetic error",
        })
    }
}

impl From<bip39::Error> for SchnorrError {
    fn from(err: bip39::Error) -> Self {
        SchnorrError::Mnemonic(err.to_string())
    }
}

impl From<bs58::decode::Error> for SchnorrError {
    fn from(err: bs58::decode::Error) -> Self {
        SchnorrError::ExtendedKey(err.to_string())
    }
}

impl From<nockchain_math_core::crypto::cheetah::CheetahError> for SchnorrError {
    fn from(err: nockchain_math_core::crypto::cheetah::CheetahError) -> Self {
        SchnorrError::PublicKeyEncoding(err.to_string())
    }
}

impl From<hmac::digest::InvalidLength> for SchnorrError {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        SchnorrError::ExtendedKey("invalid HMAC key length".into())
    }
}
