use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

use crate::constants::{
    BLOCK_BYTES, MAX_PBKDF2_ITERATIONS, NONCE_BYTES, ROUNDS, SALT_BYTES, VERSION_V4,
};
use crate::error::KrcmError;

pub struct HeaderV4 {
    pub version: u8,
    pub iterations: u32,
    pub salt: [u8; SALT_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub original_length: u64,
}

impl HeaderV4 {
    pub fn new(
        iterations: u32,
        salt: [u8; SALT_BYTES],
        nonce: [u8; NONCE_BYTES],
        original_length: u64,
    ) -> Self {
        Self {
            version: VERSION_V4,
            iterations,
            salt,
            nonce,
            original_length,
        }
    }

    pub fn to_json_bytes(&self) -> Vec<u8> {
        let construction = if self.version == 3 {
            "AMPC-AffineSubstitution-Matrix-v3"
        } else {
            "AMPC-Permutation-Matrix-v4"
        };
        format!(
            "{{\"block_bytes\":{},\"construction\":\"{}\",\"iterations\":{},\"magic\":\"AMPCRYPT\",\"nonce\":\"{}\",\"original_length\":{},\"rounds\":{},\"salt\":\"{}\",\"version\":{},\"word_bits\":64}}",
            BLOCK_BYTES,
            construction,
            self.iterations,
            STANDARD.encode(self.nonce),
            self.original_length,
            ROUNDS,
            STANDARD.encode(self.salt),
            self.version
        )
        .into_bytes()
    }

    pub fn from_json_bytes(data: &[u8]) -> Result<Self, KrcmError> {
        let payload: Value = serde_json::from_slice(data).map_err(|_| KrcmError::Format)?;
        if payload.get("magic").and_then(Value::as_str) != Some("AMPCRYPT") {
            return Err(KrcmError::Format);
        }
        let version = payload
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(KrcmError::Format)? as u8;
        if !matches!(version, 2..=4) {
            return Err(KrcmError::UnsupportedVersion);
        }
        if payload.get("block_bytes").and_then(Value::as_u64) != Some(BLOCK_BYTES as u64) {
            return Err(KrcmError::Format);
        }
        if payload.get("rounds").and_then(Value::as_u64) != Some(ROUNDS as u64) {
            return Err(KrcmError::Format);
        }
        let iterations = payload
            .get("iterations")
            .and_then(Value::as_u64)
            .ok_or(KrcmError::Format)?;
        if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS as u64 {
            return Err(KrcmError::Format);
        }
        let original_length = payload
            .get("original_length")
            .and_then(Value::as_u64)
            .ok_or(KrcmError::Format)?;
        let salt = decode_fixed::<SALT_BYTES>(
            payload
                .get("salt")
                .and_then(Value::as_str)
                .ok_or(KrcmError::Format)?,
        )?;
        let nonce = decode_fixed::<NONCE_BYTES>(
            payload
                .get("nonce")
                .and_then(Value::as_str)
                .ok_or(KrcmError::Format)?,
        )?;
        Ok(Self {
            version,
            iterations: iterations as u32,
            salt,
            nonce,
            original_length,
        })
    }
}

fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], KrcmError> {
    let bytes = STANDARD.decode(text).map_err(|_| KrcmError::Format)?;
    bytes.try_into().map_err(|_| KrcmError::Format)
}
