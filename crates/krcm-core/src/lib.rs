pub mod block;
pub mod constants;
pub mod error;
pub mod format_v4;
pub mod format_v5;
pub mod header_v4;
pub mod header_v5;
pub mod hmac_util;
pub mod inner_v5;
pub mod kdf;
pub mod matrix;
pub mod padding;
pub mod permutation;
pub mod rng;
pub mod segment;
pub mod transcript;

pub use error::KrcmError;
pub use format_v4::{decrypt_v4, encrypt_v4, EncryptV4Options};
pub use format_v5::{decrypt_v5, encrypt_v5, DecryptV5Options, EncryptV5Options, PaddingPolicy};
pub use kdf::KdfParams;

pub enum EncryptOptions {
    V4(EncryptV4Options),
    V5(EncryptV5Options),
}

pub fn decrypt_auto(container: &[u8], password: &[u8]) -> Result<Vec<u8>, KrcmError> {
    if container.starts_with(constants::MAGIC_V4) {
        return decrypt_v4(container, password);
    }
    if container.starts_with(constants::MAGIC_V5) {
        return decrypt_v5(container, password, DecryptV5Options);
    }
    Err(KrcmError::UnsupportedVersion)
}

pub fn encrypt_auto(
    data: &[u8],
    password: &[u8],
    opts: EncryptOptions,
) -> Result<Vec<u8>, KrcmError> {
    match opts {
        EncryptOptions::V4(opts) => encrypt_v4(data, password, opts),
        EncryptOptions::V5(opts) => encrypt_v5(data, password, opts),
    }
}
