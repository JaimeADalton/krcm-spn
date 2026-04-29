use sha2::{Digest, Sha256};

use crate::constants::{BLOCK_BYTES, ROUNDS, WORD_COUNT};
use crate::error::KrcmError;
use crate::kdf::{hmac_sha256, EncKey};

fn hkdf_expand_like(key: &[u8], label: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter: u32 = 1;
    let mut previous = Vec::new();
    while out.len() < length {
        let mut data = Vec::with_capacity(previous.len() + label.len() + 4);
        data.extend_from_slice(&previous);
        data.extend_from_slice(label);
        data.extend_from_slice(&counter.to_be_bytes());
        previous = hmac_sha256(key, &data).to_vec();
        out.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

fn hkdf_expand_64(key: &[u8], label: &[u8]) -> [u8; 64] {
    let mut first_input = Vec::with_capacity(label.len() + 4);
    first_input.extend_from_slice(label);
    first_input.extend_from_slice(&[0, 0, 0, 1]);
    let first = hmac_sha256(key, &first_input);
    let mut second_input = Vec::with_capacity(32 + label.len() + 4);
    second_input.extend_from_slice(&first);
    second_input.extend_from_slice(label);
    second_input.extend_from_slice(&[0, 0, 0, 2]);
    let second = hmac_sha256(key, &second_input);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&first);
    out[32..].copy_from_slice(&second);
    out
}

fn take_u64(seed: &[u8], label_prefix: &[u8], stream: &mut Vec<u8>, cursor: &mut usize) -> u64 {
    if *cursor + 8 > stream.len() {
        let mut label = Vec::with_capacity(label_prefix.len() + 4);
        label.extend_from_slice(label_prefix);
        label.extend_from_slice(&(stream.len() as u32).to_be_bytes());
        stream.extend_from_slice(&hkdf_expand_64(seed, &label));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&stream[*cursor..*cursor + 8]);
    *cursor += 8;
    u64::from_be_bytes(bytes)
}

fn permutation_from_seed(seed: &[u8]) -> Vec<usize> {
    let mut values: Vec<usize> = (0..256).collect();
    let mut stream = Vec::new();
    let mut cursor = 0usize;
    for i in (1..=255usize).rev() {
        let modulus = (i + 1) as u128;
        let limit = (1u128 << 64) - ((1u128 << 64) % modulus);
        let mut r = take_u64(seed, b"perm", &mut stream, &mut cursor);
        while (r as u128) >= limit {
            r = take_u64(seed, b"perm", &mut stream, &mut cursor);
        }
        let j = ((r as u128) % modulus) as usize;
        values.swap(i, j);
    }
    values
}

fn small_permutation(seed: &[u8], size: usize) -> Vec<usize> {
    let mut values: Vec<usize> = (0..size).collect();
    let mut stream = Vec::new();
    let mut cursor = 0usize;
    for i in (1..size).rev() {
        let modulus = (i + 1) as u128;
        let limit = (1u128 << 64) - ((1u128 << 64) % modulus);
        let mut r = take_u64(seed, b"small-perm", &mut stream, &mut cursor);
        while (r as u128) >= limit {
            r = take_u64(seed, b"small-perm", &mut stream, &mut cursor);
        }
        let j = ((r as u128) % modulus) as usize;
        values.swap(i, j);
    }
    values
}

fn inverse_permutation(perm: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; perm.len()];
    for (i, &v) in perm.iter().enumerate() {
        inv[v] = i;
    }
    inv
}

fn read_u64_be(chunk: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(chunk);
    u64::from_be_bytes(bytes)
}

fn matrix_from_seed(seed: &[u8]) -> [u64; 4] {
    let material = hkdf_expand_like(seed, b"matrix", 64);
    [
        read_u64_be(&material[0..8]) | 1,
        read_u64_be(&material[8..16]) & !1u64,
        read_u64_be(&material[16..24]) & !1u64,
        read_u64_be(&material[24..32]) | 1,
    ]
}

fn matrix_det(matrix: &[u64; 4]) -> u64 {
    matrix[0]
        .wrapping_mul(matrix[3])
        .wrapping_sub(matrix[1].wrapping_mul(matrix[2]))
}

fn modinv_odd_u64(a: u64) -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

fn matrix_inv(matrix: &[u64; 4]) -> [u64; 4] {
    let inv_det = modinv_odd_u64(matrix_det(matrix));
    [
        matrix[3].wrapping_mul(inv_det),
        0u64.wrapping_sub(matrix[1]).wrapping_mul(inv_det),
        0u64.wrapping_sub(matrix[2]).wrapping_mul(inv_det),
        matrix[0].wrapping_mul(inv_det),
    ]
}

fn matrix_mul(left: &[u64; 4], right: &[u64; 4]) -> [u64; 4] {
    [
        left[0]
            .wrapping_mul(right[0])
            .wrapping_add(left[1].wrapping_mul(right[2])),
        left[0]
            .wrapping_mul(right[1])
            .wrapping_add(left[1].wrapping_mul(right[3])),
        left[2]
            .wrapping_mul(right[0])
            .wrapping_add(left[3].wrapping_mul(right[2])),
        left[2]
            .wrapping_mul(right[1])
            .wrapping_add(left[3].wrapping_mul(right[3])),
    ]
}

fn words_from_block(block: &[u8; BLOCK_BYTES]) -> [u64; WORD_COUNT] {
    [
        read_u64_be(&block[0..8]),
        read_u64_be(&block[8..16]),
        read_u64_be(&block[16..24]),
        read_u64_be(&block[24..32]),
    ]
}

fn block_from_words(words: &[u64; WORD_COUNT]) -> [u8; BLOCK_BYTES] {
    let mut out = [0u8; BLOCK_BYTES];
    for (i, word) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn pre_substitute(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let perm = permutation_from_seed(seed);
    let mask = hkdf_expand_like(seed, b"mask", BLOCK_BYTES);
    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..BLOCK_BYTES {
        out[i] = perm[block[i].wrapping_add(mask[i]) as usize] as u8;
    }
    out
}

fn post_unsubstitute(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let perm = permutation_from_seed(seed);
    let inv = inverse_permutation(&perm);
    let mask = hkdf_expand_like(seed, b"mask", BLOCK_BYTES);
    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..BLOCK_BYTES {
        out[i] = (inv[block[i] as usize] as u8).wrapping_sub(mask[i]);
    }
    out
}

fn diffuse_bytes(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let mask = hkdf_expand_like(seed, b"diffuse", BLOCK_BYTES * 2);
    let mut state = *block;
    for i in 1..BLOCK_BYTES {
        state[i] = state[i].wrapping_add(state[i - 1]).wrapping_add(mask[i]);
    }
    for i in (0..BLOCK_BYTES - 1).rev() {
        state[i] = state[i]
            .wrapping_add(state[i + 1])
            .wrapping_add(mask[BLOCK_BYTES + i]);
    }
    state
}

fn undiffuse_bytes(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let mask = hkdf_expand_like(seed, b"diffuse", BLOCK_BYTES * 2);
    let mut state = *block;
    for i in 0..BLOCK_BYTES - 1 {
        state[i] = state[i]
            .wrapping_sub(state[i + 1])
            .wrapping_sub(mask[BLOCK_BYTES + i]);
    }
    for i in (1..BLOCK_BYTES).rev() {
        state[i] = state[i].wrapping_sub(state[i - 1]).wrapping_sub(mask[i]);
    }
    state
}

fn apply_position_permutation(block: &[u8; BLOCK_BYTES], perm: &[usize]) -> [u8; BLOCK_BYTES] {
    let mut out = [0u8; BLOCK_BYTES];
    for i in 0..BLOCK_BYTES {
        out[i] = block[perm[i]];
    }
    out
}

fn invert_position_permutation(block: &[u8; BLOCK_BYTES], perm: &[usize]) -> [u8; BLOCK_BYTES] {
    let mut out = [0u8; BLOCK_BYTES];
    for (i, &source) in perm.iter().enumerate() {
        out[source] = block[i];
    }
    out
}

fn round_seed(seed: &[u8], round_index: usize) -> [u8; 32] {
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(b"round");
    data.extend_from_slice(&(round_index as u16).to_be_bytes());
    hmac_sha256(seed, &data)
}

fn encrypt_one_block(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let mut state = *block;
    for round_index in 0..ROUNDS {
        let rseed = round_seed(seed, round_index);
        state = pre_substitute(&state, &rseed);
        state = diffuse_bytes(&state, &rseed);
        let words = words_from_block(&state);
        let left = matrix_from_seed(&hmac_sha256(&rseed, b"left"));
        let right = matrix_from_seed(&hmac_sha256(&rseed, b"right"));
        let mixed = matrix_mul(&left, &matrix_mul(&words, &right));
        state = block_from_words(&mixed);
        let perm = small_permutation(&rseed, BLOCK_BYTES);
        state = apply_position_permutation(&state, &perm);
    }
    state
}

fn decrypt_one_block(block: &[u8; BLOCK_BYTES], seed: &[u8]) -> [u8; BLOCK_BYTES] {
    let mut state = *block;
    for round_index in (0..ROUNDS).rev() {
        let rseed = round_seed(seed, round_index);
        let perm = small_permutation(&rseed, BLOCK_BYTES);
        state = invert_position_permutation(&state, &perm);
        let words = words_from_block(&state);
        let left = matrix_from_seed(&hmac_sha256(&rseed, b"left"));
        let right = matrix_from_seed(&hmac_sha256(&rseed, b"right"));
        let unmixed = matrix_mul(&matrix_inv(&left), &matrix_mul(&words, &matrix_inv(&right)));
        state = block_from_words(&unmixed);
        state = undiffuse_bytes(&state, &rseed);
        state = post_unsubstitute(&state, &rseed);
    }
    state
}

fn block_seed(enc_key: &EncKey, nonce: &[u8], block_index: usize, feedback: &[u8]) -> [u8; 32] {
    let feedback_hash = Sha256::digest(feedback);
    let mut label = Vec::with_capacity(5 + nonce.len() + 8 + 32);
    label.extend_from_slice(b"block");
    label.extend_from_slice(nonce);
    label.extend_from_slice(&(block_index as u64).to_be_bytes());
    label.extend_from_slice(&feedback_hash);
    hmac_sha256(&enc_key.0, &label)
}

pub fn encrypt_blocks(padded: &[u8], enc_key: &EncKey, nonce: &[u8]) -> Result<Vec<u8>, KrcmError> {
    if padded.len() % BLOCK_BYTES != 0 {
        return Err(KrcmError::InvalidParameter);
    }
    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut feedback = nonce.to_vec();
    for (block_index, block) in padded.chunks_exact(BLOCK_BYTES).enumerate() {
        let seed = block_seed(enc_key, nonce, block_index, &feedback);
        let mut input = [0u8; BLOCK_BYTES];
        input.copy_from_slice(block);
        let encrypted = encrypt_one_block(&input, &seed);
        ciphertext.extend_from_slice(&encrypted);
        feedback.clear();
        feedback.extend_from_slice(&encrypted);
    }
    Ok(ciphertext)
}

pub fn decrypt_blocks(
    ciphertext: &[u8],
    enc_key: &EncKey,
    nonce: &[u8],
) -> Result<Vec<u8>, KrcmError> {
    if ciphertext.len() % BLOCK_BYTES != 0 {
        return Err(KrcmError::Format);
    }
    let mut padded = Vec::with_capacity(ciphertext.len());
    let mut feedback = nonce.to_vec();
    for (block_index, encrypted_block) in ciphertext.chunks_exact(BLOCK_BYTES).enumerate() {
        let seed = block_seed(enc_key, nonce, block_index, &feedback);
        let mut input = [0u8; BLOCK_BYTES];
        input.copy_from_slice(encrypted_block);
        let decrypted = decrypt_one_block(&input, &seed);
        padded.extend_from_slice(&decrypted);
        feedback.clear();
        feedback.extend_from_slice(encrypted_block);
    }
    Ok(padded)
}
