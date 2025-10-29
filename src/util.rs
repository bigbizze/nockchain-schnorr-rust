use ibig::UBig;
use nockchain_math_core::belt::{Belt, PRIME};
use nockchain_math_core::crypto::cheetah::{CheetahPoint, F6lt};
use nockchain_math_core::tip5::hash::hash_varlen;

pub type Tip5Digest = [u64; 5];

pub fn scalar_from_le_bytes(bytes: &[u8; 32]) -> UBig {
    UBig::from_le_bytes(bytes)
}

pub fn scalar_from_be_bytes(bytes: &[u8; 32]) -> UBig {
    UBig::from_be_bytes(bytes)
}

pub fn scalar_to_fixed_le_bytes(scalar: &UBig) -> [u8; 32] {
    let mut bytes = scalar.to_le_bytes();
    if bytes.len() > 32 {
        bytes.truncate(32);
    }
    bytes.resize(32, 0);
    bytes.try_into().expect("resized to 32 bytes")
}

pub fn scalar_to_fixed_be_bytes(scalar: &UBig) -> [u8; 32] {
    let mut bytes = scalar.to_be_bytes();
    if bytes.len() > 32 {
        bytes.truncate(32);
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes.try_into().expect("resized to 32 bytes")
}

pub fn words32_from_scalar(scalar: &UBig) -> [u32; 8] {
    let bytes = scalar_to_fixed_le_bytes(scalar);
    let mut words = [0u32; 8];
    for (chunk, word) in bytes.chunks_exact(4).zip(words.iter_mut()) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    words
}

pub fn words32_to_scalar(words: &[u32; 8]) -> UBig {
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    scalar_from_le_bytes(&bytes)
}

pub fn extend_with_point(coords: &F6lt, out: &mut Vec<Belt>) {
    out.extend_from_slice(&coords.0);
}

pub fn extend_with_point_xy(point: &CheetahPoint, out: &mut Vec<Belt>) {
    extend_with_point(&point.x, out);
    extend_with_point(&point.y, out);
}

pub fn extend_with_digest(digest: &Tip5Digest, out: &mut Vec<Belt>) {
    out.extend(digest.iter().map(|&value| Belt(value)));
}

pub fn extend_with_words32(words: &[u32], out: &mut Vec<Belt>) {
    out.extend(words.iter().map(|&word| Belt(word as u64)));
}

pub fn scalar_is_zero(value: &UBig) -> bool {
    value == &UBig::from(0u8)
}

pub fn belts_from_bytes(message: &[u8]) -> Vec<Belt> {
    if message.is_empty() {
        return vec![Belt(0)];
    }
    message
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(buf) % PRIME;
            Belt(value)
        })
        .collect()
}

pub fn hash_bytes_to_digest(message: &[u8]) -> Tip5Digest {
    let mut belts = belts_from_bytes(message);
    belts.push(Belt((message.len() as u64) % PRIME));
    hash_varlen(&mut belts)
}

fn rip32_words(message: &[u8]) -> Vec<u32> {
    if message.is_empty() {
        return vec![0];
    }

    let mut words = Vec::with_capacity((message.len() + 3) / 4);
    let mut chunk = [0u8; 4];
    for (idx, byte) in message.iter().enumerate() {
        chunk[idx % 4] = *byte;
        if idx % 4 == 3 {
            words.push(u32::from_le_bytes(chunk));
            chunk = [0u8; 4];
        }
    }
    let rem = message.len() % 4;
    if rem != 0 {
        for i in rem..4 {
            chunk[i] = 0;
        }
        words.push(u32::from_le_bytes(chunk));
    }
    words
}

pub fn hash_page_message(message: &[u8]) -> Tip5Digest {
    let mut words = rip32_words(message);
    words.push(0);

    let mut belts = Vec::with_capacity(1 + words.len() + (words.len().saturating_sub(1) * 2));
    belts.push(Belt((words.len() as u64) % PRIME));
    for word in &words {
        belts.push(Belt((*word as u64) % PRIME));
    }

    if words.len() > 0 {
        for _ in 0..(words.len() - 1) {
            belts.push(Belt(0));
            belts.push(Belt(1));
        }
    }

    hash_varlen(&mut belts)
}

pub fn serialize_point(point: &CheetahPoint) -> [u8; 97] {
    let mut bytes = [0u8; 97];
    bytes[0] = 1;
    let mut offset = 1;
    // Match the Hoon `ser-a-pt` ordering (y limbs first, then x limbs, little-end per limb).
    for belt in point.y.0.iter().rev().chain(point.x.0.iter().rev()) {
        bytes[offset..offset + 8].copy_from_slice(&belt.0.to_be_bytes());
        offset += 8;
    }
    bytes
}

pub fn deserialize_point(bytes: &[u8; 97]) -> Result<CheetahPoint, &'static str> {
    if bytes[0] != 1 {
        return Err("invalid leading byte");
    }
    let mut x_array = [Belt(0); 6];
    let mut y_array = [Belt(0); 6];
    let mut iter = bytes[1..].chunks_exact(8);
    for belt in y_array.iter_mut().rev() {
        let chunk = iter.next().ok_or("invalid y coordinate chunk")?;
        let arr: [u8; 8] = chunk.try_into().map_err(|_| "invalid chunk")?;
        *belt = Belt(u64::from_be_bytes(arr));
    }
    
    for belt in x_array.iter_mut().rev() {
        let chunk = iter.next().ok_or("invalid x coordinate chunk")?;
        let arr: [u8; 8] = chunk.try_into().map_err(|_| "invalid chunk")?;
        *belt = Belt(u64::from_be_bytes(arr));
    }

    let point = CheetahPoint {
        x: F6lt(x_array),
        y: F6lt(y_array),
        inf: false,
    };

    if !point.in_curve() {
        return Err("point not on curve");
    }

    Ok(point)
}
