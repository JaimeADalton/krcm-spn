use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::constants::{MAX_PBKDF2_ITERATIONS, SALT_BYTES};
use crate::error::KrcmError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, ZeroizeOnDrop)]
pub struct EncKey(pub(crate) [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct AuthKey(pub(crate) [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct RootKey(pub(crate) [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct SivKey(pub(crate) [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct BlockKey(pub(crate) [u8; 32]);

#[derive(Clone, ZeroizeOnDrop)]
pub struct SegmentKey(pub(crate) [u8; 32]);

#[derive(Clone)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Scrypt { n_log2: u8, r: u32, p: u32 },
}

pub struct V5Keys {
    pub(crate) enc_key: EncKey,
    pub(crate) auth_key: AuthKey,
    pub(crate) siv_key: SivKey,
    pub(crate) block_key: BlockKey,
    pub(crate) segment_key: SegmentKey,
}

impl From<[u8; 32]> for RootKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl EncKey {
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub fn expose_for_tests(&self) -> [u8; 32] {
        self.0
    }
}

impl AuthKey {
    pub fn expose_for_tests(&self) -> [u8; 32] {
        self.0
    }
}

impl SivKey {
    pub fn expose_for_tests(&self) -> [u8; 32] {
        self.0
    }
}

impl BlockKey {
    pub fn expose_for_tests(&self) -> [u8; 32] {
        self.0
    }
}

impl SegmentKey {
    pub fn expose_for_tests(&self) -> [u8; 32] {
        self.0
    }
}

impl V5Keys {
    pub fn enc_key_for_tests(&self) -> [u8; 32] {
        self.enc_key.expose_for_tests()
    }

    pub fn auth_key_for_tests(&self) -> [u8; 32] {
        self.auth_key.expose_for_tests()
    }

    pub fn siv_key_for_tests(&self) -> [u8; 32] {
        self.siv_key.expose_for_tests()
    }

    pub fn block_key_for_tests(&self) -> [u8; 32] {
        self.block_key.expose_for_tests()
    }

    pub fn segment_key_for_tests(&self) -> [u8; 32] {
        self.segment_key.expose_for_tests()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn derive_keys(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<(EncKey, AuthKey), KrcmError> {
    if password.is_empty() {
        return Err(KrcmError::InvalidPassword);
    }
    if salt.len() != SALT_BYTES || iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(KrcmError::InvalidParameter);
    }
    let mut root = [0u8; 64];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut root);
    let enc = hmac_sha256(&root[..32], b"AMPC-ENC");
    let auth = hmac_sha256(&root[32..], b"AMPC-AUTH");
    Ok((EncKey(enc), AuthKey(auth)))
}

pub fn make_tag(auth_key: &AuthKey, header_bytes: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(header_bytes.len() + ciphertext.len());
    data.extend_from_slice(header_bytes);
    data.extend_from_slice(ciphertext);
    hmac_sha256(&auth_key.0, &data)
}

pub fn derive_root_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<RootKey, KrcmError> {
    if password.is_empty() || salt.len() != SALT_BYTES {
        return Err(KrcmError::InvalidParameter);
    }
    let mut root = [0u8; 32];
    match *params {
        KdfParams::Pbkdf2 { iterations } => {
            if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
                return Err(KrcmError::InvalidParameter);
            }
            pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut root);
        }
        KdfParams::Scrypt { n_log2, r, p } => {
            if n_log2 > 15 || r == 0 || r > 8 || p == 0 || p > 2 {
                return Err(KrcmError::InvalidParameter);
            }
            let params = ScryptParams::new(n_log2, r, p, root.len())
                .map_err(|_| KrcmError::InvalidParameter)?;
            scrypt(password, salt, &params, &mut root).map_err(|_| KrcmError::InvalidParameter)?;
        }
    }
    Ok(RootKey(root))
}

impl V5Keys {
    pub fn derive(root: &RootKey) -> Self {
        fn subkey(root: &RootKey, label: &[u8]) -> [u8; 32] {
            let mut data = Vec::with_capacity(b"KRCM-v5-subkey".len() + label.len());
            data.extend_from_slice(b"KRCM-v5-subkey");
            data.extend_from_slice(label);
            hmac_sha256(&root.0, &data)
        }
        Self {
            enc_key: EncKey(subkey(root, b"KRCM-v5-enc")),
            auth_key: AuthKey(subkey(root, b"KRCM-v5-auth")),
            siv_key: SivKey(subkey(root, b"KRCM-v5-siv")),
            block_key: BlockKey(subkey(root, b"KRCM-v5-block")),
            segment_key: SegmentKey(subkey(root, b"KRCM-v5-segment")),
        }
    }
}
