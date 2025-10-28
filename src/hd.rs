use std::fmt;
use std::str::FromStr;

use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use ibig::UBig;
use nockchain_math_core::crypto::cheetah::{ch_add, ch_scal_big, A_GEN, A_ID, G_ORDER};
use num_traits::Zero;
use sha2::{Digest, Sha256, Sha512};

use crate::error::SchnorrError;
use crate::types::{PublicKey, SecretKey};
use crate::util::{deserialize_point, scalar_is_zero, scalar_to_fixed_be_bytes};

type HmacSha512 = Hmac<Sha512>;

const DOMAIN_SEPARATOR: &[u8] = b"dees niahckcoN";
const HARDENED_OFFSET: u32 = 1 << 31;
const STANDARD_EXTENDED_PRIVATE_VERSION: u32 = 0x04B2_430C;
const STANDARD_EXTENDED_PUBLIC_VERSION: u32 = 0x04B2_4746;
const HOON_EXTENDED_PRIVATE_VERSION: u32 = 0x0110_6331;
const HOON_EXTENDED_PUBLIC_VERSION: u32 = 0x0C0E_BB09;

fn to_hoon_little_endian(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.reverse();
    out
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; 64], SchnorrError> {
    let key_le = to_hoon_little_endian(key);

    let mut mac = HmacSha512::new_from_slice(&key_le)?;
    mac.update(message);
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

fn split_digest(digest: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&digest[..32]);
    right.copy_from_slice(&digest[32..]);
    (left, right)
}

fn ser32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    second.into()
}

fn add_checksum(payload: &[u8]) -> Vec<u8> {
    let checksum = double_sha256(payload);
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&checksum[..4]);
    out.extend_from_slice(payload);
    out
}

fn verify_checksum(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let payload = &data[4..];
    let checksum = &data[..4];
    let expected = double_sha256(payload);
    checksum == &expected[..4]
}

fn decode_base58(s: &str) -> Result<Vec<u8>, SchnorrError> {
    let decoded = bs58::decode(s).into_vec()?;
    if !verify_checksum(&decoded) {
        return Err(SchnorrError::ExtendedKey("checksum mismatch".into()));
    }
    Ok(decoded[4..].to_vec())
}

fn encode_base58(payload: &[u8]) -> String {
    bs58::encode(add_checksum(payload)).into_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildNumber {
    index: u32,
    hardened: bool,
}

impl ChildNumber {
    pub fn normal(index: u32) -> Result<Self, SchnorrError> {
        if index >= HARDENED_OFFSET {
            return Err(SchnorrError::InvalidDerivationPath(
                "normal child index exceeds maximum".into(),
            ));
        }
        Ok(Self {
            index,
            hardened: false,
        })
    }

    pub fn hardened(index: u32) -> Result<Self, SchnorrError> {
        if index >= HARDENED_OFFSET {
            return Err(SchnorrError::InvalidDerivationPath(
                "hardened child index exceeds maximum".into(),
            ));
        }
        Ok(Self {
            index,
            hardened: true,
        })
    }

    pub fn is_hardened(&self) -> bool {
        self.hardened
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn value(&self) -> u32 {
        if self.hardened {
            self.index + HARDENED_OFFSET
        } else {
            self.index
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hardened {
            write!(f, "{}'", self.index)
        } else {
            write!(f, "{}", self.index)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<ChildNumber>);

impl DerivationPath {
    pub fn new(path: Vec<ChildNumber>) -> Self {
        Self(path)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChildNumber> {
        self.0.iter()
    }
}

impl IntoIterator for DerivationPath {
    type Item = ChildNumber;
    type IntoIter = std::vec::IntoIter<ChildNumber>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = std::slice::Iter<'a, ChildNumber>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromStr for DerivationPath {
    type Err = SchnorrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let mut components = trimmed.split('/').filter(|seg| !seg.is_empty());

        let mut path = Vec::new();
        if let Some(first) = components.next() {
            if first != "m" && first != "M" {
                path.push(parse_child(first)?);
            }
        }

        for comp in components {
            path.push(parse_child(comp)?);
        }

        Ok(DerivationPath::new(path))
    }
}

fn parse_child(segment: &str) -> Result<ChildNumber, SchnorrError> {
    let hardened = segment.ends_with('\'') || segment.ends_with('h') || segment.ends_with('H');
    let digits = segment.trim_end_matches(|c| c == '\'' || c == 'h' || c == 'H');
    if digits.is_empty() {
        return Err(SchnorrError::InvalidDerivationPath(
            "empty child index".into(),
        ));
    }
    let index: u32 = digits
        .parse()
        .map_err(|_| SchnorrError::InvalidDerivationPath(segment.into()))?;
    if hardened {
        ChildNumber::hardened(index)
    } else {
        ChildNumber::normal(index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletMnemonic {
    inner: Mnemonic,
}

impl WalletMnemonic {
    pub fn from_phrase(phrase: &str) -> Result<Self, SchnorrError> {
        Ok(Self {
            inner: Mnemonic::parse_in_normalized(Language::English, phrase)?,
        })
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<Self, SchnorrError> {
        Ok(Self {
            inner: Mnemonic::from_entropy_in(Language::English, entropy)?,
        })
    }

    pub fn phrase(&self) -> String {
        self.inner.to_string()
    }

    pub fn seed(&self, passphrase: &str) -> Vec<u8> {
        self.inner.to_seed(passphrase).to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedPrivateKey {
    secret_key: SecretKey,
    public_key: PublicKey,
    chain_code: [u8; 32],
    depth: u8,
    index: u32,
    parent_fingerprint: [u8; 4],
    version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    public_key: PublicKey,
    chain_code: [u8; 32],
    depth: u8,
    index: u32,
    parent_fingerprint: [u8; 4],
    version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtendedKey {
    Private(ExtendedPrivateKey),
    Public(ExtendedPublicKey),
}

impl ExtendedPrivateKey {
    pub fn from_seed(seed: &[u8], version: u8) -> Result<Self, SchnorrError> {
        if seed.is_empty() {
            return Err(SchnorrError::Mnemonic(
                "seed must contain at least one byte".into(),
            ));
        }
        let mut message = seed.to_vec();
        loop {
            let digest = hmac_sha512(DOMAIN_SEPARATOR, &message)?;
            let (left_bytes, right_bytes) = split_digest(&digest);
            let scalar = UBig::from_be_bytes(&left_bytes);
            if scalar.is_zero() || scalar >= *G_ORDER {
                message = digest.to_vec();
                continue;
            }
            let secret = SecretKey::from_bytes_be(left_bytes)?;
            let public = secret.public_key()?;
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&right_bytes);
            return Ok(Self {
                secret_key: secret,
                public_key: public,
                chain_code,
                depth: 0,
                index: 0,
                parent_fingerprint: [0u8; 4],
                version,
            });
        }
    }

    pub fn from_mnemonic(
        phrase: &str,
        passphrase: &str,
        version: u8,
    ) -> Result<Self, SchnorrError> {
        let mnemonic = WalletMnemonic::from_phrase(phrase)?;
        let seed = mnemonic.seed(passphrase);
        Self::from_seed(&seed, version)
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, SchnorrError> {
        let index_bytes = ser32(child.value());
        let parent_pub_bytes = self.public_key.to_bytes();
        let mut data = Vec::with_capacity(if child.is_hardened() { 37 } else { 101 });
        data.extend_from_slice(&index_bytes);
        if child.is_hardened() {
            data.extend_from_slice(&self.secret_key.to_be_bytes());
            data.push(0);
        } else {
            data.extend_from_slice(&parent_pub_bytes);
        }

        let mut digest = hmac_sha512(&self.chain_code, &data)?;
        loop {
            let (left_bytes, right_bytes) = split_digest(&digest);
            let left_scalar = UBig::from_be_bytes(&left_bytes);
            let candidate = (&left_scalar + self.secret_key.scalar()) % &*G_ORDER;

            if left_scalar < *G_ORDER && !scalar_is_zero(&candidate) {
                let secret_bytes = scalar_to_fixed_be_bytes(&candidate);
                let secret = SecretKey::from_bytes_be(secret_bytes)?;
                let public = secret.public_key()?;
                let mut chain_code = [0u8; 32];
                chain_code.copy_from_slice(&right_bytes);
                return Ok(Self {
                    secret_key: secret,
                    public_key: public,
                    chain_code,
                    depth: self.depth.wrapping_add(1),
                    index: child.value(),
                    parent_fingerprint: self.public_key.fingerprint(),
                    version: self.version,
                });
            }

            let mut retry = Vec::with_capacity(37);
            retry.extend_from_slice(&index_bytes);
            retry.extend_from_slice(&right_bytes);
            retry.push(0x01);
            digest = hmac_sha512(&self.chain_code, &retry)?;
        }
    }

    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, SchnorrError> {
        let mut current = self.clone();
        for child in path.iter() {
            current = current.derive_child(*child)?;
        }
        Ok(current)
    }

    pub fn extended_private_key(&self) -> Result<String, SchnorrError> {
        let mut key_data = [0u8; 33];
        key_data[1..].copy_from_slice(&self.secret_key.to_be_bytes());
        let payload = serialize_extended(
            &key_data,
            &self.chain_code,
            self.index,
            self.parent_fingerprint,
            self.depth,
            self.version,
            STANDARD_EXTENDED_PRIVATE_VERSION,
        );
        Ok(encode_base58(&payload))
    }

    pub fn extended_public_key(&self) -> Result<String, SchnorrError> {
        self.public_extended_key().extended_public_key()
    }

    pub fn public_extended_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            public_key: self.public_key.clone(),
            chain_code: self.chain_code,
            depth: self.depth,
            index: self.index,
            parent_fingerprint: self.parent_fingerprint,
            version: self.version,
        }
    }

    pub fn from_extended_str(s: &str) -> Result<Self, SchnorrError> {
        let payload = decode_base58(s)?;
        parse_extended_private(&payload)
    }
}

impl ExtendedPublicKey {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, SchnorrError> {
        if child.is_hardened() {
            return Err(SchnorrError::HardenedDerivationFromPublic);
        }
        let index_bytes = ser32(child.value());
        let mut data = Vec::with_capacity(101);
        data.extend_from_slice(&index_bytes);
        data.extend_from_slice(&self.public_key.to_bytes());
        let mut digest = hmac_sha512(&self.chain_code, &data)?;

        loop {
            let (left_bytes, right_bytes) = split_digest(&digest);
            let left_scalar = UBig::from_be_bytes(&left_bytes);
            let scalar_point = match ch_scal_big(&left_scalar, &A_GEN) {
                Ok(p) => p,
                Err(_) => {
                    let mut retry = Vec::with_capacity(37);
                    retry.extend_from_slice(&index_bytes);
                    retry.extend_from_slice(&right_bytes);
                    retry.push(0x01);
                    digest = hmac_sha512(&self.chain_code, &retry)?;
                    continue;
                }
            };
            let candidate_point = match ch_add(&scalar_point, self.public_key.as_point()) {
                Ok(p) => p,
                Err(_) => {
                    let mut retry = Vec::with_capacity(37);
                    retry.extend_from_slice(&index_bytes);
                    retry.extend_from_slice(&right_bytes);
                    retry.push(0x01);
                    digest = hmac_sha512(&self.chain_code, &retry)?;
                    continue;
                }
            };

            if left_scalar < *G_ORDER && !(candidate_point.inf || candidate_point == A_ID) {
                let mut chain_code = [0u8; 32];
                chain_code.copy_from_slice(&right_bytes);
                return Ok(Self {
                    public_key: PublicKey(candidate_point),
                    chain_code,
                    depth: self.depth.wrapping_add(1),
                    index: child.value(),
                    parent_fingerprint: self.public_key.fingerprint(),
                    version: self.version,
                });
            }

            let mut retry = Vec::with_capacity(37);
            retry.extend_from_slice(&index_bytes);
            retry.extend_from_slice(&right_bytes);
            retry.push(0x01);
            digest = hmac_sha512(&self.chain_code, &retry)?;
        }
    }

    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, SchnorrError> {
        let mut current = self.clone();
        for child in path.iter() {
            if child.is_hardened() {
                return Err(SchnorrError::HardenedDerivationFromPublic);
            }
            current = current.derive_child(*child)?;
        }
        Ok(current)
    }

    pub fn extended_public_key(&self) -> Result<String, SchnorrError> {
        let key_data = self.public_key.to_bytes();
        let payload = serialize_extended(
            &key_data,
            &self.chain_code,
            self.index,
            self.parent_fingerprint,
            self.depth,
            self.version,
            STANDARD_EXTENDED_PUBLIC_VERSION,
        );
        Ok(encode_base58(&payload))
    }

    pub fn from_extended_str(s: &str) -> Result<Self, SchnorrError> {
        let payload = decode_base58(s)?;
        parse_extended_public(&payload)
    }
}

impl FromStr for ExtendedKey {
    type Err = SchnorrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(private) = ExtendedPrivateKey::from_extended_str(s) {
            return Ok(ExtendedKey::Private(private));
        }
        if let Ok(public) = ExtendedPublicKey::from_extended_str(s) {
            return Ok(ExtendedKey::Public(public));
        }
        Err(SchnorrError::ExtendedKey(
            "unrecognised extended key encoding".into(),
        ))
    }
}

fn serialize_extended(
    key_data: &[u8],
    chain_code: &[u8; 32],
    index: u32,
    parent_fingerprint: [u8; 4],
    depth: u8,
    version: u8,
    typ: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(key_data.len() + 46);
    payload.extend_from_slice(&typ.to_be_bytes());
    payload.push(depth);
    payload.extend_from_slice(&parent_fingerprint);
    payload.extend_from_slice(&ser32(index));
    payload.extend_from_slice(chain_code);
    payload.extend_from_slice(key_data);
    payload.push(version);
    payload
}

fn parse_extended_private(payload: &[u8]) -> Result<ExtendedPrivateKey, SchnorrError> {
    let key_size = 33;
    if payload.len() < 4 {
        return Err(SchnorrError::ExtendedKey(
            "extended private key is truncated".into(),
        ));
    }

    let prefix: [u8; 4] = payload[..4]
        .try_into()
        .map_err(|_| SchnorrError::ExtendedKey("invalid version prefix".into()))?;

    if prefix == STANDARD_EXTENDED_PRIVATE_VERSION.to_be_bytes() {
        if payload.len() != key_size + 46 {
            return Err(SchnorrError::ExtendedKey(
                "invalid extended private key length".into(),
            ));
        }
        let depth = payload[4];
        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&payload[5..9]);
        let index = u32::from_be_bytes(
            payload[9..13]
                .try_into()
                .map_err(|_| SchnorrError::ExtendedKey("invalid child index".into()))?,
        );
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        let key_data = &payload[45..45 + key_size];
        let version = payload[45 + key_size];

        if key_data[0] != 0 {
            return Err(SchnorrError::ExtendedKey(
                "extended private key is missing leading 0x00".into(),
            ));
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&key_data[1..]);
        let secret = SecretKey::from_bytes_be(secret_bytes)?;
        let public = secret.public_key()?;
        return Ok(ExtendedPrivateKey {
            secret_key: secret,
            public_key: public,
            chain_code,
            depth,
            index,
            parent_fingerprint: parent_fp,
            version,
        });
    }

    parse_extended_private_hoon(payload)
}

fn parse_extended_private_hoon(payload: &[u8]) -> Result<ExtendedPrivateKey, SchnorrError> {
    let key_size = 33;
    if payload.len() != key_size + 46 && payload.len() != key_size + 45 {
        return Err(SchnorrError::ExtendedKey(
            "invalid extended private key length".into(),
        ));
    }
    let has_version = payload.len() == key_size + 46;
    let key_data = &payload[..key_size];
    if key_data[0] != 0 {
        return Err(SchnorrError::ExtendedKey(
            "extended private key is missing leading 0x00".into(),
        ));
    }
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&key_data[1..]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[key_size..key_size + 32]);
    let index = u32::from_be_bytes(
        payload[key_size + 32..key_size + 36]
            .try_into()
            .map_err(|_| SchnorrError::ExtendedKey("invalid child index".into()))?,
    );
    let mut parent_fp = [0u8; 4];
    parent_fp.copy_from_slice(&payload[key_size + 36..key_size + 40]);
    let depth = payload[key_size + 40];
    let version = if has_version {
        payload[key_size + 41]
    } else {
        0
    };
    let typ_offset = key_size + 41 + (has_version as usize);
    if payload.len() < typ_offset + 4 {
        return Err(SchnorrError::ExtendedKey(
            "extended private key is truncated".into(),
        ));
    }
    let typ_bytes: [u8; 4] = payload[typ_offset..typ_offset + 4]
        .try_into()
        .map_err(|_| SchnorrError::ExtendedKey("invalid private key type".into()))?;
    if typ_bytes != HOON_EXTENDED_PRIVATE_VERSION.to_be_bytes() {
        return Err(SchnorrError::ExtendedKey(
            "unexpected extended private key type".into(),
        ));
    }
    let secret = SecretKey::from_bytes_be(secret_bytes)?;
    let public = secret.public_key()?;
    Ok(ExtendedPrivateKey {
        secret_key: secret,
        public_key: public,
        chain_code,
        depth,
        index,
        parent_fingerprint: parent_fp,
        version,
    })
}

fn parse_extended_public(payload: &[u8]) -> Result<ExtendedPublicKey, SchnorrError> {
    let key_size = 97;
    if payload.len() < 4 {
        return Err(SchnorrError::ExtendedKey(
            "extended public key is truncated".into(),
        ));
    }

    let prefix: [u8; 4] = payload[..4]
        .try_into()
        .map_err(|_| SchnorrError::ExtendedKey("invalid version prefix".into()))?;

    if prefix == STANDARD_EXTENDED_PUBLIC_VERSION.to_be_bytes() {
        if payload.len() != key_size + 46 {
            return Err(SchnorrError::ExtendedKey(
                "invalid extended public key length".into(),
            ));
        }
        let depth = payload[4];
        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&payload[5..9]);
        let index = u32::from_be_bytes(
            payload[9..13]
                .try_into()
                .map_err(|_| SchnorrError::ExtendedKey("invalid child index".into()))?,
        );
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        let mut point_bytes = [0u8; 97];
        point_bytes.copy_from_slice(&payload[45..45 + key_size]);
        let version = payload[45 + key_size];
        let point =
            deserialize_point(&point_bytes).map_err(|err| SchnorrError::ExtendedKey(err.into()))?;

        return Ok(ExtendedPublicKey {
            public_key: PublicKey(point),
            chain_code,
            depth,
            index,
            parent_fingerprint: parent_fp,
            version,
        });
    }

    parse_extended_public_hoon(payload)
}

fn parse_extended_public_hoon(payload: &[u8]) -> Result<ExtendedPublicKey, SchnorrError> {
    let key_size = 97;
    if payload.len() != key_size + 46 && payload.len() != key_size + 45 {
        return Err(SchnorrError::ExtendedKey(
            "invalid extended public key length".into(),
        ));
    }
    let has_version = payload.len() == key_size + 46;
    let key_data = &payload[..key_size];
    let mut point_bytes = [0u8; 97];
    point_bytes.copy_from_slice(key_data);
    let point =
        deserialize_point(&point_bytes).map_err(|err| SchnorrError::ExtendedKey(err.into()))?;

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[key_size..key_size + 32]);
    let index = u32::from_be_bytes(
        payload[key_size + 32..key_size + 36]
            .try_into()
            .map_err(|_| SchnorrError::ExtendedKey("invalid child index".into()))?,
    );
    let mut parent_fp = [0u8; 4];
    parent_fp.copy_from_slice(&payload[key_size + 36..key_size + 40]);
    let depth = payload[key_size + 40];
    let version = if has_version {
        payload[key_size + 41]
    } else {
        0
    };
    let typ_offset = key_size + 41 + (has_version as usize);
    if payload.len() < typ_offset + 4 {
        return Err(SchnorrError::ExtendedKey(
            "extended public key is truncated".into(),
        ));
    }
    let typ_bytes: [u8; 4] = payload[typ_offset..typ_offset + 4]
        .try_into()
        .map_err(|_| SchnorrError::ExtendedKey("invalid public key type".into()))?;
    if typ_bytes != HOON_EXTENDED_PUBLIC_VERSION.to_be_bytes() {
        return Err(SchnorrError::ExtendedKey(
            "unexpected extended public key type".into(),
        ));
    }
    Ok(ExtendedPublicKey {
        public_key: PublicKey(point),
        chain_code,
        depth,
        index,
        parent_fingerprint: parent_fp,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_roundtrip() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.seed("nockchain");
        assert_eq!(seed.len(), 64);
        let reconstructed = WalletMnemonic::from_entropy(&seed[0..16]).unwrap();
        assert_eq!(reconstructed.phrase().split_whitespace().count(), 12);
    }

    #[test]
    fn derive_master_key_from_mnemonic() {
        let master = ExtendedPrivateKey::from_mnemonic(TEST_MNEMONIC, "", 1).unwrap();
        let xprv = master.extended_private_key().unwrap();
        let parsed = ExtendedPrivateKey::from_extended_str(&xprv).unwrap();
        assert_eq!(
            master.secret_key().to_be_bytes(),
            parsed.secret_key().to_be_bytes()
        );
        assert_eq!(master.chain_code(), parsed.chain_code());
        assert_eq!(master.depth(), parsed.depth());
        assert_eq!(master.index(), parsed.index());
    }

    #[test]
    fn derive_path_consistency() {
        let master = ExtendedPrivateKey::from_mnemonic(TEST_MNEMONIC, "", 1).unwrap();
        let path: DerivationPath = "m/0'/1/2'".parse().unwrap();
        let child = master.derive_path(&path).unwrap();
        let serialized = child.extended_private_key().unwrap();
        let reparsed = ExtendedPrivateKey::from_extended_str(&serialized).unwrap();
        assert_eq!(
            child.secret_key().to_be_bytes(),
            reparsed.secret_key().to_be_bytes()
        );
        assert_eq!(child.chain_code(), reparsed.chain_code());
    }

    #[test]
    fn master_public_matches_cli_vector() {
        let master = ExtendedPrivateKey::from_mnemonic(TEST_MNEMONIC, "", 0).unwrap();
        let public_bytes = master.public_key().to_bytes();
        let expected_hex = "0199504a8a7bc93f083d244623c458410dd300c9ea8c2c822841d5a706285c06ec25595d68b0912d0c80488556f45b95390fa1239e1327643b138caf5c879d9e44cbab87a8dde3147e7102985af71fae78d1141f457adfe23d2c523e5b70c88604";
        assert_eq!(hex::encode(public_bytes), expected_hex);

        let expected_address = "3Rzu9ga8nUCm3LSiSs6oh4uNYFos8cL6TmwQP8dXMheJTsvwCZjvDKndhU8dKvBvrrU88exM7fTo5WpEG75EwUrSPxgXLC8VhGESektqKUbFFPjTX8b4DJvZ6t9U3L4PGXeK";
        let address = bs58::encode(public_bytes).into_string();
        assert_eq!(address, expected_address);
    }
}
