use rand::rngs::OsRng;
use rand_core::RngCore;
use subtle::ConstantTimeEq;

use crate::block::{decrypt_blocks, encrypt_blocks};
use crate::constants::{
    MAGIC_V4, MAX_HEADER_BYTES, MAX_PBKDF2_ITERATIONS, NONCE_BYTES, SALT_BYTES, TAG_BYTES,
};
use crate::error::KrcmError;
use crate::header_v4::HeaderV4;
use crate::kdf::{derive_keys, make_tag};
use crate::padding::{pad, unpad};

#[derive(Clone)]
pub struct EncryptV4Options {
    pub iterations: u32,
    pub salt: Option<[u8; SALT_BYTES]>,
    pub nonce: Option<[u8; NONCE_BYTES]>,
}

impl Default for EncryptV4Options {
    fn default() -> Self {
        Self {
            iterations: crate::constants::DEFAULT_ITERATIONS,
            salt: None,
            nonce: None,
        }
    }
}

pub fn encrypt_v4(
    data: &[u8],
    password: &[u8],
    opts: EncryptV4Options,
) -> Result<Vec<u8>, KrcmError> {
    if opts.iterations == 0 || opts.iterations > MAX_PBKDF2_ITERATIONS {
        return Err(KrcmError::InvalidParameter);
    }
    let mut rng = OsRng;
    let salt = opts.salt.unwrap_or_else(|| {
        let mut out = [0u8; SALT_BYTES];
        rng.fill_bytes(&mut out);
        out
    });
    let nonce = opts.nonce.unwrap_or_else(|| {
        let mut out = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut out);
        out
    });
    let header = HeaderV4::new(opts.iterations, salt, nonce, data.len() as u64);
    let (enc_key, auth_key) = derive_keys(password, &salt, opts.iterations)?;
    let ciphertext = encrypt_blocks(&pad(data), &enc_key, &nonce)?;
    let header_bytes = header.to_json_bytes();
    let tag = make_tag(&auth_key, &header_bytes, &ciphertext);
    let mut out =
        Vec::with_capacity(MAGIC_V4.len() + 4 + header_bytes.len() + ciphertext.len() + TAG_BYTES);
    out.extend_from_slice(MAGIC_V4);
    out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn decrypt_v4(container: &[u8], password: &[u8]) -> Result<Vec<u8>, KrcmError> {
    let min_len = MAGIC_V4.len() + 4 + TAG_BYTES;
    if container.len() < min_len || &container[..MAGIC_V4.len()] != MAGIC_V4 {
        return Err(KrcmError::Format);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&container[MAGIC_V4.len()..MAGIC_V4.len() + 4]);
    let header_len = u32::from_be_bytes(len_bytes) as usize;
    let start = MAGIC_V4.len() + 4;
    let end = start.checked_add(header_len).ok_or(KrcmError::Format)?;
    if header_len == 0 || header_len > MAX_HEADER_BYTES || end + TAG_BYTES > container.len() {
        return Err(KrcmError::Format);
    }
    let header_bytes = &container[start..end];
    let header = HeaderV4::from_json_bytes(header_bytes)?;
    let ciphertext = &container[end..container.len() - TAG_BYTES];
    let tag = &container[container.len() - TAG_BYTES..];
    let (enc_key, auth_key) = derive_keys(password, &header.salt, header.iterations)?;
    let expected = make_tag(&auth_key, header_bytes, ciphertext);
    if tag.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(KrcmError::Authentication);
    }
    let padded = decrypt_blocks(ciphertext, &enc_key, &header.nonce)?;
    let plain = unpad(&padded)?;
    if plain.len() as u64 != header.original_length {
        return Err(KrcmError::Authentication);
    }
    Ok(plain)
}
