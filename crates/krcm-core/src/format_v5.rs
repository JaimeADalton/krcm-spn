use rand::rngs::OsRng;
use rand_core::RngCore;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::block::{decrypt_blocks, encrypt_blocks};
use crate::constants::{BLOCK_BYTES, HEADER_V5_SIZE, MAGIC_V5, NONCE_BYTES, ROUNDS, SALT_BYTES};
use crate::error::KrcmError;
use crate::kdf::{derive_root_key, hmac_sha256, KdfParams, V5Keys};
use crate::padding::{pad, unpad};

const INNER_MAGIC: &[u8; 8] = b"KRCMIN5\0";
const TAG_DOMAIN: &[u8] = b"KRCM-v5-TAG";
const OUTER_PREFIX_BYTES: usize = 8 + 1 + 4;
const SYNTHETIC_IV_BYTES: usize = 32;
const TAG_BYTES: usize = 32;
const SEGMENT_ENTRY_BYTES: usize = 40;
const INNER_HEADER_BYTES: usize = 76;

#[derive(Clone)]
pub enum PaddingPolicy {
    MinimalBlock,
    RandomBlocks { max_blocks: u8 },
}

pub struct EncryptV5Options {
    pub kdf: KdfParams,
    pub padding_policy: PaddingPolicy,
    pub segment_size: usize,
    pub workers: usize,
    pub salt: Option<[u8; SALT_BYTES]>,
    pub public_nonce: Option<[u8; NONCE_BYTES]>,
}

pub struct DecryptV5Options;

#[derive(Clone, Debug)]
struct SegmentEntry {
    segment_index: u64,
    plain_offset: u64,
    plain_length: u64,
    ciphertext_offset: u64,
    ciphertext_length: u64,
}

pub fn encrypt_v5(
    data: &[u8],
    password: &[u8],
    opts: EncryptV5Options,
) -> Result<Vec<u8>, KrcmError> {
    let mut rng = OsRng;
    let salt = opts.salt.unwrap_or_else(|| {
        let mut out = [0u8; SALT_BYTES];
        rng.fill_bytes(&mut out);
        out
    });
    let public_nonce = opts.public_nonce.unwrap_or_else(|| {
        let mut out = [0u8; NONCE_BYTES];
        rng.fill_bytes(&mut out);
        out
    });
    let public_header = pack_public_header(&opts, salt, public_nonce)?;
    let root = derive_root_key(password, &salt, &opts.kdf)?;
    let keys = V5Keys::derive(&root);
    let inner = pack_inner(data, &opts.padding_policy)?;
    let synthetic_iv = synthetic_iv(&keys, &public_header, &inner);
    let _effective_nonce = effective_nonce(&keys, &public_nonce, &synthetic_iv);
    let (segment_table, ciphertext) = encrypt_segments(
        &inner,
        &keys,
        &public_nonce,
        &synthetic_iv,
        opts.segment_size,
        opts.workers,
    )?;
    let tag = tag_v5(
        &keys,
        &public_header,
        &synthetic_iv,
        &segment_table,
        &ciphertext,
    );

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_V5);
    out.push(5);
    out.extend_from_slice(&(HEADER_V5_SIZE as u32).to_be_bytes());
    out.extend_from_slice(&public_header);
    out.extend_from_slice(&synthetic_iv);
    out.extend_from_slice(&(segment_table.len() as u64).to_be_bytes());
    out.extend_from_slice(&segment_table);
    out.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn decrypt_v5(
    container: &[u8],
    password: &[u8],
    _opts: DecryptV5Options,
) -> Result<Vec<u8>, KrcmError> {
    if container.len() < OUTER_PREFIX_BYTES + HEADER_V5_SIZE + SYNTHETIC_IV_BYTES + TAG_BYTES {
        return Err(KrcmError::Format);
    }
    if &container[..8] != MAGIC_V5 || container[8] != 5 {
        return Err(KrcmError::Format);
    }
    let public_header_len = read_u32(&container[9..13])? as usize;
    if public_header_len != HEADER_V5_SIZE {
        return Err(KrcmError::Format);
    }
    let public_header = &container[13..13 + HEADER_V5_SIZE];
    let parsed = parse_public_header(public_header)?;
    let mut offset = 13 + HEADER_V5_SIZE;
    let stored_synthetic_iv = read_fixed_32(container, &mut offset)?;
    let segment_table_len = read_u64_at(container, &mut offset)? as usize;
    if segment_table_len % SEGMENT_ENTRY_BYTES != 0 || offset + segment_table_len > container.len()
    {
        return Err(KrcmError::Format);
    }
    let segment_table = &container[offset..offset + segment_table_len];
    offset += segment_table_len;
    let ciphertext_len = read_u64_at(container, &mut offset)? as usize;
    if offset + ciphertext_len + TAG_BYTES != container.len() {
        return Err(KrcmError::Format);
    }
    let ciphertext = &container[offset..offset + ciphertext_len];
    offset += ciphertext_len;
    let tag = &container[offset..];

    let root = derive_root_key(password, &parsed.salt, &parsed.kdf)?;
    let keys = V5Keys::derive(&root);
    let expected = tag_v5(
        &keys,
        public_header,
        &stored_synthetic_iv,
        segment_table,
        ciphertext,
    );
    if tag.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(KrcmError::Authentication);
    }
    let entries = parse_segment_table(segment_table, ciphertext.len() as u64)?;
    let _effective_nonce = effective_nonce(&keys, &parsed.public_nonce, &stored_synthetic_iv);
    let inner = decrypt_segments(
        &entries,
        ciphertext,
        &keys,
        &parsed.public_nonce,
        &stored_synthetic_iv,
    )?;
    let recomputed = synthetic_iv(&keys, public_header, &inner);
    if stored_synthetic_iv.ct_eq(&recomputed).unwrap_u8() != 1 {
        return Err(KrcmError::Authentication);
    }
    let info = inspect_inner(&inner)?;
    let segment_plain_sum: u64 = entries.iter().map(|entry| entry.plain_length).sum();
    if segment_plain_sum != inner.len() as u64 || info.payload_length > inner.len() as u64 {
        return Err(KrcmError::Format);
    }
    unpack_inner(&inner)
}

fn pack_public_header(
    opts: &EncryptV5Options,
    salt: [u8; SALT_BYTES],
    public_nonce: [u8; NONCE_BYTES],
) -> Result<[u8; HEADER_V5_SIZE], KrcmError> {
    let mut out = [0u8; HEADER_V5_SIZE];
    out[0..8].copy_from_slice(MAGIC_V5);
    out[8] = 5;
    out[9] = 1;
    match opts.kdf {
        KdfParams::Pbkdf2 { iterations } => {
            if iterations == 0 || iterations > crate::constants::MAX_PBKDF2_ITERATIONS {
                return Err(KrcmError::InvalidParameter);
            }
            out[10] = 1;
            out[12..16].copy_from_slice(&iterations.to_be_bytes());
        }
        KdfParams::Scrypt { n_log2, r, p } => {
            if n_log2 > 15 || r == 0 || r > 8 || p == 0 || p > 2 {
                return Err(KrcmError::InvalidParameter);
            }
            out[10] = 2;
            out[16] = n_log2;
            out[17..21].copy_from_slice(&r.to_be_bytes());
            out[21..25].copy_from_slice(&p.to_be_bytes());
        }
    }
    out[25] = (opts
        .segment_size
        .max(BLOCK_BYTES)
        .next_power_of_two()
        .trailing_zeros()) as u8;
    out[26] = match opts.padding_policy {
        PaddingPolicy::MinimalBlock => 0,
        PaddingPolicy::RandomBlocks { .. } => 1,
    };
    out[32..48].copy_from_slice(&salt);
    out[48..64].copy_from_slice(&public_nonce);
    Ok(out)
}

struct ParsedHeader {
    kdf: KdfParams,
    salt: [u8; SALT_BYTES],
    public_nonce: [u8; NONCE_BYTES],
}

pub fn parse_public_header_for_fuzz(header: &[u8]) -> Result<(), KrcmError> {
    parse_public_header(header).map(|_| ())
}

fn parse_public_header(header: &[u8]) -> Result<ParsedHeader, KrcmError> {
    if header.len() != HEADER_V5_SIZE || &header[0..8] != MAGIC_V5 || header[8] != 5 {
        return Err(KrcmError::Format);
    }
    if header[9] != 1 || header[11] != 0 || header[27..32].iter().any(|&b| b != 0) {
        return Err(KrcmError::Format);
    }
    if header[26] > 1 {
        return Err(KrcmError::InvalidParameter);
    }
    let kdf = match header[10] {
        1 => KdfParams::Pbkdf2 {
            iterations: read_u32(&header[12..16])?,
        },
        2 => KdfParams::Scrypt {
            n_log2: header[16],
            r: read_u32(&header[17..21])?,
            p: read_u32(&header[21..25])?,
        },
        _ => return Err(KrcmError::InvalidParameter),
    };
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&header[32..48]);
    let mut public_nonce = [0u8; NONCE_BYTES];
    public_nonce.copy_from_slice(&header[48..64]);
    Ok(ParsedHeader {
        kdf,
        salt,
        public_nonce,
    })
}

fn pack_inner(data: &[u8], padding: &PaddingPolicy) -> Result<Vec<u8>, KrcmError> {
    let random_padding_len = match *padding {
        PaddingPolicy::MinimalBlock => 0,
        PaddingPolicy::RandomBlocks { max_blocks } => {
            let max_blocks = max_blocks.min(15);
            if max_blocks == 0 {
                0
            } else {
                let mut count = [0u8; 1];
                OsRng.fill_bytes(&mut count);
                (usize::from(count[0] % (max_blocks + 1))) * BLOCK_BYTES
            }
        }
    };
    let mut out = Vec::with_capacity(INNER_HEADER_BYTES + data.len() + random_padding_len);
    out.extend_from_slice(INNER_MAGIC);
    out.push(1);
    out.push(0);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(&Sha256::digest(data));
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(BLOCK_BYTES as u16).to_be_bytes());
    out.extend_from_slice(&(ROUNDS as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 10]);
    out.extend_from_slice(data);
    if random_padding_len > 0 {
        let mut random = vec![0u8; random_padding_len];
        OsRng.fill_bytes(&mut random);
        out.extend_from_slice(&random);
    }
    Ok(out)
}

struct InnerInfo {
    original_length: u64,
    payload_length: u64,
}

pub fn unpack_inner_for_fuzz(inner: &[u8]) -> Result<(), KrcmError> {
    inspect_inner(inner).map(|_| ())
}

fn inspect_inner(inner: &[u8]) -> Result<InnerInfo, KrcmError> {
    if inner.len() < INNER_HEADER_BYTES || &inner[0..8] != INNER_MAGIC || inner[8] != 1 {
        return Err(KrcmError::Authentication);
    }
    if inner[9] != 0
        || inner[10..12] != [0, 0]
        || read_u16(&inner[60..62])? != 1
        || read_u16(&inner[62..64])? != BLOCK_BYTES as u16
        || read_u16(&inner[64..66])? != ROUNDS as u16
        || inner[66..76].iter().any(|&b| b != 0)
    {
        return Err(KrcmError::Authentication);
    }
    let original_length = read_u64(&inner[12..20])?;
    let payload_length = read_u64(&inner[20..28])?;
    if INNER_HEADER_BYTES as u64 + payload_length > inner.len() as u64
        || original_length > payload_length
    {
        return Err(KrcmError::Authentication);
    }
    let payload_start = INNER_HEADER_BYTES;
    let payload_end = payload_start + payload_length as usize;
    let payload = &inner[payload_start..payload_end];
    let hash = Sha256::digest(payload);
    if inner[28..60].ct_eq(hash.as_slice()).unwrap_u8() != 1 {
        return Err(KrcmError::Authentication);
    }
    Ok(InnerInfo {
        original_length,
        payload_length,
    })
}

fn unpack_inner(inner: &[u8]) -> Result<Vec<u8>, KrcmError> {
    let info = inspect_inner(inner)?;
    let payload_start = INNER_HEADER_BYTES;
    let payload_end = payload_start + info.payload_length as usize;
    Ok(inner[payload_start..payload_end][..info.original_length as usize].to_vec())
}

fn synthetic_iv(keys: &V5Keys, public_header: &[u8], inner: &[u8]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"KRCM-v5-SIV");
    data.extend_from_slice(&(public_header.len() as u64).to_be_bytes());
    data.extend_from_slice(public_header);
    data.extend_from_slice(&(inner.len() as u64).to_be_bytes());
    data.extend_from_slice(inner);
    hmac_sha256(&keys.siv_key.0, &data)
}

fn effective_nonce(
    keys: &V5Keys,
    public_nonce: &[u8; NONCE_BYTES],
    synthetic_iv: &[u8; 32],
) -> [u8; 16] {
    let mut data = Vec::new();
    data.extend_from_slice(b"KRCM-v5-effective-nonce");
    data.extend_from_slice(public_nonce);
    data.extend_from_slice(synthetic_iv);
    let digest = hmac_sha256(&keys.block_key.0, &data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn segment_nonce(
    keys: &V5Keys,
    public_nonce: &[u8; NONCE_BYTES],
    synthetic_iv: &[u8; 32],
    segment_index: u64,
) -> [u8; 16] {
    let mut data = Vec::new();
    data.extend_from_slice(b"KRCM-v5-segment");
    data.extend_from_slice(public_nonce);
    data.extend_from_slice(synthetic_iv);
    data.extend_from_slice(&segment_index.to_be_bytes());
    let digest = hmac_sha256(&keys.segment_key.0, &data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn tag_v5(
    keys: &V5Keys,
    public_header: &[u8],
    synthetic_iv: &[u8; 32],
    segment_table: &[u8],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut transcript = Vec::new();
    append_field(&mut transcript, TAG_DOMAIN);
    append_field(&mut transcript, public_header);
    append_field(&mut transcript, synthetic_iv);
    append_field(&mut transcript, segment_table);
    append_field(&mut transcript, ciphertext);
    hmac_sha256(&keys.auth_key.0, &transcript)
}

fn append_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

fn encrypt_segments(
    inner: &[u8],
    keys: &V5Keys,
    public_nonce: &[u8; NONCE_BYTES],
    synthetic_iv: &[u8; 32],
    requested_segment_size: usize,
    workers: usize,
) -> Result<(Vec<u8>, Vec<u8>), KrcmError> {
    let segment_size = requested_segment_size.max(BLOCK_BYTES);
    let chunks = inner
        .chunks(segment_size)
        .enumerate()
        .map(|(index, plain)| (index as u64, plain.to_vec()))
        .collect::<Vec<_>>();
    let encrypted = if workers > 1 && chunks.len() > 1 {
        chunks
            .par_iter()
            .map(|(index, plain)| encrypt_segment(*index, plain, keys, public_nonce, synthetic_iv))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        chunks
            .iter()
            .map(|(index, plain)| encrypt_segment(*index, plain, keys, public_nonce, synthetic_iv))
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut ciphertext = Vec::new();
    let mut entries = Vec::with_capacity(encrypted.len());
    let mut plain_offset = 0u64;
    let mut ciphertext_offset = 0u64;
    for (index, plain_length, encrypted_segment) in encrypted {
        let ciphertext_length = encrypted_segment.len() as u64;
        entries.push(SegmentEntry {
            segment_index: index,
            plain_offset,
            plain_length,
            ciphertext_offset,
            ciphertext_length,
        });
        plain_offset += plain_length;
        ciphertext_offset += ciphertext_length;
        ciphertext.extend_from_slice(&encrypted_segment);
    }
    Ok((serialize_segment_table(&entries), ciphertext))
}

fn encrypt_segment(
    index: u64,
    plain: &[u8],
    keys: &V5Keys,
    public_nonce: &[u8; NONCE_BYTES],
    synthetic_iv: &[u8; 32],
) -> Result<(u64, u64, Vec<u8>), KrcmError> {
    let nonce = segment_nonce(keys, public_nonce, synthetic_iv, index);
    let ciphertext = encrypt_blocks(&pad(plain), &keys.enc_key, &nonce)?;
    Ok((index, plain.len() as u64, ciphertext))
}

fn decrypt_segments(
    entries: &[SegmentEntry],
    ciphertext: &[u8],
    keys: &V5Keys,
    public_nonce: &[u8; NONCE_BYTES],
    synthetic_iv: &[u8; 32],
) -> Result<Vec<u8>, KrcmError> {
    let mut inner = Vec::new();
    for entry in entries {
        let start = entry.ciphertext_offset as usize;
        let end = start + entry.ciphertext_length as usize;
        let nonce = segment_nonce(keys, public_nonce, synthetic_iv, entry.segment_index);
        let plain = unpad(&decrypt_blocks(
            &ciphertext[start..end],
            &keys.enc_key,
            &nonce,
        )?)?;
        if plain.len() as u64 != entry.plain_length {
            return Err(KrcmError::Authentication);
        }
        inner.extend_from_slice(&plain);
    }
    Ok(inner)
}

fn serialize_segment_table(entries: &[SegmentEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * SEGMENT_ENTRY_BYTES);
    for entry in entries {
        for value in [
            entry.segment_index,
            entry.plain_offset,
            entry.plain_length,
            entry.ciphertext_offset,
            entry.ciphertext_length,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    out
}

pub fn parse_segment_table_for_fuzz(table: &[u8], ciphertext_len: u64) -> Result<(), KrcmError> {
    parse_segment_table(table, ciphertext_len).map(|_| ())
}

fn parse_segment_table(table: &[u8], ciphertext_len: u64) -> Result<Vec<SegmentEntry>, KrcmError> {
    if table.is_empty() || table.len() % SEGMENT_ENTRY_BYTES != 0 {
        return Err(KrcmError::Format);
    }
    let mut entries = Vec::with_capacity(table.len() / SEGMENT_ENTRY_BYTES);
    let mut expected_plain_offset = 0u64;
    let mut expected_ciphertext_offset = 0u64;
    for (ordinal, chunk) in table.chunks_exact(SEGMENT_ENTRY_BYTES).enumerate() {
        let entry = SegmentEntry {
            segment_index: read_u64(&chunk[0..8])?,
            plain_offset: read_u64(&chunk[8..16])?,
            plain_length: read_u64(&chunk[16..24])?,
            ciphertext_offset: read_u64(&chunk[24..32])?,
            ciphertext_length: read_u64(&chunk[32..40])?,
        };
        if entry.segment_index != ordinal as u64
            || entry.plain_offset != expected_plain_offset
            || entry.ciphertext_offset != expected_ciphertext_offset
            || entry.ciphertext_length == 0
            || entry.ciphertext_length % BLOCK_BYTES as u64 != 0
        {
            return Err(KrcmError::Format);
        }
        expected_plain_offset = expected_plain_offset
            .checked_add(entry.plain_length)
            .ok_or(KrcmError::Format)?;
        expected_ciphertext_offset = expected_ciphertext_offset
            .checked_add(entry.ciphertext_length)
            .ok_or(KrcmError::Format)?;
        entries.push(entry);
    }
    if expected_ciphertext_offset != ciphertext_len {
        return Err(KrcmError::Format);
    }
    Ok(entries)
}

fn read_fixed_32(container: &[u8], offset: &mut usize) -> Result<[u8; 32], KrcmError> {
    if *offset + 32 > container.len() {
        return Err(KrcmError::Format);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&container[*offset..*offset + 32]);
    *offset += 32;
    Ok(out)
}

fn read_u64_at(container: &[u8], offset: &mut usize) -> Result<u64, KrcmError> {
    if *offset + 8 > container.len() {
        return Err(KrcmError::Format);
    }
    let value = read_u64(&container[*offset..*offset + 8])?;
    *offset += 8;
    Ok(value)
}

fn read_u32(data: &[u8]) -> Result<u32, KrcmError> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| KrcmError::Format)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u16(data: &[u8]) -> Result<u16, KrcmError> {
    let bytes: [u8; 2] = data.try_into().map_err(|_| KrcmError::Format)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(data: &[u8]) -> Result<u64, KrcmError> {
    let bytes: [u8; 8] = data.try_into().map_err(|_| KrcmError::Format)?;
    Ok(u64::from_be_bytes(bytes))
}
