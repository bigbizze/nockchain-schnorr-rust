mod error;
mod hd;
mod types;
mod util;

pub use error::SchnorrError;
pub use hd::{
    ChildNumber, DerivationPath, ExtendedKey, ExtendedPrivateKey, ExtendedPublicKey, WalletMnemonic,
};
pub use types::{PublicKey, SecretKey, Signature};
pub use util::Tip5Digest;

use ibig::UBig;
use nockchain_math_core::belt::Belt;
use nockchain_math_core::crypto::cheetah::{
    ch_add, ch_neg, ch_scal_big, trunc_g_order, A_GEN, A_ID, G_ORDER,
};
use nockchain_math_core::tip5::hash::hash_varlen;
use util::{
    extend_with_digest, extend_with_point_xy, extend_with_words32, hash_bytes_to_digest,
    scalar_is_zero,
};

pub fn derive_public_key(secret: &SecretKey) -> Result<PublicKey, SchnorrError> {
    secret.public_key()
}

pub fn hash_message(message: &[u8]) -> Tip5Digest {
    hash_bytes_to_digest(message)
}

pub fn sign_message(secret: &SecretKey, message: &[u8]) -> Result<Signature, SchnorrError> {
    let digest = hash_message(message);
    sign_digest(secret, &digest)
}

pub fn verify_message(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let digest = hash_message(message);
    verify_signature(public_key, &digest, signature)
}

pub fn sign_digest(secret: &SecretKey, message: &Tip5Digest) -> Result<Signature, SchnorrError> {
    let public_key = secret.public_key()?;
    let mut transcript = Vec::<Belt>::new();
    extend_with_point_xy(public_key.as_point(), &mut transcript);
    extend_with_digest(message, &mut transcript);
    let secret_words = secret.words32_le();
    extend_with_words32(&secret_words, &mut transcript);

    let nonce = hash_vec_to_scalar(transcript)?;
    if scalar_is_zero(&nonce) {
        return Err(SchnorrError::ZeroNonce);
    }
    let nonce_point = ch_scal_big(&nonce, &A_GEN)?;

    let mut preimage = Vec::<Belt>::new();
    extend_with_point_xy(&nonce_point, &mut preimage);
    extend_with_point_xy(public_key.as_point(), &mut preimage);
    extend_with_digest(message, &mut preimage);

    let challenge = hash_vec_to_scalar(preimage)?;
    if scalar_is_zero(&challenge) {
        return Err(SchnorrError::ZeroChallenge);
    }

    let response = {
        let product = (&challenge * secret.scalar()) % &*G_ORDER;
        let sum = (&nonce + product) % &*G_ORDER;
        sum
    };

    if scalar_is_zero(&response) {
        return Err(SchnorrError::ZeroSignature);
    }

    Ok(Signature::new(challenge, response))
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &Tip5Digest,
    signature: &Signature,
) -> bool {
    if signature.challenge >= *G_ORDER || signature.response >= *G_ORDER {
        return false;
    }
    if scalar_is_zero(&signature.challenge) || scalar_is_zero(&signature.response) {
        return false;
    }

    let left = match ch_scal_big(&signature.response, &A_GEN) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let right = match ch_scal_big(&signature.challenge, public_key.as_point()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let neg_right = ch_neg(&right);
    let scalar_point = match ch_add(&left, &neg_right) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if scalar_point.inf || scalar_point == A_ID {
        return false;
    }

    let mut preimage = Vec::<Belt>::new();
    extend_with_point_xy(&scalar_point, &mut preimage);
    extend_with_point_xy(public_key.as_point(), &mut preimage);
    extend_with_digest(message, &mut preimage);

    match hash_vec_to_scalar(preimage) {
        Ok(expected) => expected == signature.challenge,
        Err(_) => false,
    }
}

pub fn batch_verify<'a, I>(items: I) -> bool
where
    I: IntoIterator<Item = (&'a PublicKey, &'a Tip5Digest, &'a Signature)>,
{
    items
        .into_iter()
        .all(|(pk, msg, sig)| verify_signature(pk, msg, sig))
}

fn hash_vec_to_scalar(mut belts: Vec<Belt>) -> Result<UBig, SchnorrError> {
    let digest = hash_varlen(&mut belts);
    let scalar = trunc_g_order(&digest);
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret_key() -> SecretKey {
        let bytes = [
            0x1cu8, 0x15, 0x33, 0x08, 0xa4, 0x97, 0x42, 0x0f, 0xd1, 0x5e, 0x6f, 0x0b, 0x92, 0x8c,
            0xa7, 0x11, 0x6e, 0xb8, 0x32, 0x5c, 0x42, 0xa6, 0x7f, 0x55, 0x3a, 0x62, 0xfa, 0x0c,
            0x19, 0x41, 0x6d, 0x01,
        ];
        SecretKey::from_bytes_le(bytes).expect("valid secret key")
    }

    fn sample_digest() -> Tip5Digest {
        [
            0x0102030405060708,
            0x1112131415161718,
            0x2122232425262728,
            0x3132333435363738,
            0x4142434445464748,
        ]
    }

    #[test]
    fn signing_and_verifying_roundtrip() {
        let sk = sample_secret_key();
        let pk = sk.public_key().unwrap();
        let digest = sample_digest();
        let sig = sign_digest(&sk, &digest).expect("signing succeeds");
        assert!(verify_signature(&pk, &digest, &sig));

        let mut tampered = digest;
        tampered[0] ^= 0x55;
        assert!(!verify_signature(&pk, &tampered, &sig));
    }

    #[test]
    fn signature_values_are_deterministic() {
        let sk = sample_secret_key();
        let digest = sample_digest();
        let sig = sign_digest(&sk, &digest).unwrap();
        let challenge_bytes = sig.challenge_bytes_le();
        let response_bytes = sig.response_bytes_le();
        assert_eq!(
            hex::encode(challenge_bytes),
            "a226a7c5c5119af3ea6a7cdf90567b5b37ac97ce507c919e69e27e5c28ba2718"
        );
        assert_eq!(
            hex::encode(response_bytes),
            "317ca9dccf0e2a20d9c36f9ab5de4fdada2f2309efd0e4591ec513ad6ae2754a"
        );
    }

    #[test]
    fn batch_verification_agrees() {
        let sk = sample_secret_key();
        let pk = sk.public_key().unwrap();
        let digest = sample_digest();
        let sig = sign_digest(&sk, &digest).unwrap();
        assert!(batch_verify([(&pk, &digest, &sig)]));
    }

    #[test]
    fn message_signing_roundtrip() {
        let sk = sample_secret_key();
        let pk = sk.public_key().unwrap();
        let message = b"nockchain signing test";
        let sig = sign_message(&sk, message).unwrap();
        assert!(verify_message(&pk, message, &sig));

        let mut tampered = message.to_vec();
        tampered.push(0u8);
        assert!(!verify_message(&pk, &tampered, &sig));
    }
}
