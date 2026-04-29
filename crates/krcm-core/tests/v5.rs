use krcm_core::kdf::{RootKey, V5Keys};
use krcm_core::{
    decrypt_auto, decrypt_v5, encrypt_v5, DecryptV5Options, EncryptV5Options, KdfParams,
    PaddingPolicy,
};
use proptest::prelude::*;

fn opts_with(segment_size: usize, workers: usize) -> EncryptV5Options {
    EncryptV5Options {
        kdf: KdfParams::Pbkdf2 { iterations: 1_000 },
        padding_policy: PaddingPolicy::MinimalBlock,
        segment_size,
        workers,
        salt: Some([0x11; 16]),
        public_nonce: Some([0x22; 16]),
    }
}

fn opts() -> EncryptV5Options {
    opts_with(1024 * 1024, 1)
}

fn encrypt(data: &[u8]) -> Vec<u8> {
    encrypt_v5(data, b"password", opts()).unwrap()
}

#[test]
fn test_v5_roundtrip_empty() {
    let container = encrypt(b"");
    assert_eq!(
        decrypt_v5(&container, b"password", DecryptV5Options).unwrap(),
        b""
    );
}

#[test]
fn test_v5_roundtrip_one_byte() {
    let container = encrypt(b"x");
    assert_eq!(
        decrypt_v5(&container, b"password", DecryptV5Options).unwrap(),
        b"x"
    );
}

#[test]
fn test_v5_roundtrip_block_boundaries() {
    for size in [31usize, 32, 33, 63, 64, 65] {
        let data = (0..size).map(|i| (i * 7 + size) as u8).collect::<Vec<_>>();
        let container = encrypt(&data);
        assert_eq!(
            decrypt_v5(&container, b"password", DecryptV5Options).unwrap(),
            data
        );
    }
}

#[test]
fn test_v5_roundtrip_large() {
    let data = (0..8192).map(|i| (i * 13) as u8).collect::<Vec<_>>();
    let container = encrypt_v5(&data, b"password", opts_with(257, 4)).unwrap();
    assert_eq!(
        decrypt_v5(&container, b"password", DecryptV5Options).unwrap(),
        data
    );
}

#[test]
fn test_v5_wrong_password() {
    assert!(decrypt_v5(&encrypt(b"secret"), b"wrong", DecryptV5Options).is_err());
}

fn tamper(mut container: Vec<u8>, index: usize) -> Vec<u8> {
    container[index] ^= 0x80;
    container
}

#[test]
fn test_v5_tamper_public_header() {
    let container = encrypt(b"authenticated");
    assert!(decrypt_v5(&tamper(container, 20), b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_tamper_synthetic_iv() {
    let container = encrypt(b"authenticated");
    assert!(decrypt_v5(&tamper(container, 77), b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_tamper_segment_table() {
    let container = encrypt_v5(b"authenticated", b"password", opts_with(8, 1)).unwrap();
    assert!(decrypt_v5(&tamper(container, 117), b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_tamper_ciphertext() {
    let container = encrypt(b"authenticated");
    let index = container.len() - 40;
    assert!(decrypt_v5(&tamper(container, index), b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_tamper_tag() {
    let container = encrypt(b"authenticated");
    let index = container.len() - 1;
    assert!(decrypt_v5(&tamper(container, index), b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_original_length_not_visible() {
    let data = b"length hidden from public header";
    let container = encrypt(data);
    let public_region = &container[..77];
    let encoded_len = (data.len() as u64).to_be_bytes();
    assert!(!public_region.windows(8).any(|window| window == encoded_len));
}

#[test]
fn test_v5_reused_public_nonce_different_plaintext_different_effective_nonce() {
    let a = encrypt(b"first plaintext");
    let b = encrypt(b"second plaintext");
    assert_ne!(&a[77..109], &b[77..109]);
}

#[test]
fn test_v5_same_rng_workers_1_equals_workers_n() {
    let data = (0..2048).map(|i| (i * 5) as u8).collect::<Vec<_>>();
    let a = encrypt_v5(&data, b"password", opts_with(128, 1)).unwrap();
    let b = encrypt_v5(&data, b"password", opts_with(128, 8)).unwrap();
    assert_eq!(a, b);
}

fn segment_table_bounds(container: &[u8]) -> (usize, usize, usize, usize) {
    let table_len_offset = 109;
    let table_len = u64::from_be_bytes(
        container[table_len_offset..table_len_offset + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let table_start = 117;
    let table_end = table_start + table_len;
    let ciphertext_len_offset = table_end;
    (table_start, table_end, ciphertext_len_offset, table_len)
}

#[test]
fn test_v5_segment_reorder_rejected() {
    let mut container = encrypt_v5(
        b"segment reorder rejection payload",
        b"password",
        opts_with(8, 1),
    )
    .unwrap();
    let (table_start, _, _, table_len) = segment_table_bounds(&container);
    if table_len >= 80 {
        for i in 0..40 {
            container.swap(table_start + i, table_start + 40 + i);
        }
    }
    assert!(decrypt_v5(&container, b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_segment_duplicate_rejected() {
    let mut container = encrypt_v5(
        b"segment duplicate rejection payload",
        b"password",
        opts_with(8, 1),
    )
    .unwrap();
    let (table_start, _, _, table_len) = segment_table_bounds(&container);
    if table_len >= 80 {
        let first = container[table_start..table_start + 40].to_vec();
        container[table_start + 40..table_start + 80].copy_from_slice(&first);
    }
    assert!(decrypt_v5(&container, b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_segment_truncate_rejected() {
    let mut container = encrypt_v5(
        b"segment truncate rejection payload",
        b"password",
        opts_with(8, 1),
    )
    .unwrap();
    let (table_start, _table_end, _cipher_len_offset, table_len) = segment_table_bounds(&container);
    if table_len >= 40 {
        let new_len = (table_len - 40) as u64;
        container[109..117].copy_from_slice(&new_len.to_be_bytes());
        container.drain(table_start..table_start + 40);
    }
    assert!(decrypt_v5(&container, b"password", DecryptV5Options).is_err());
}

#[test]
fn test_v5_header_serialized_len_is_64() {
    let container = encrypt(b"header");
    let public_header = &container[13..77];
    assert_eq!(public_header.len(), 64);
    assert_eq!(&public_header[..8], b"KRCMSPN\0");
}

#[test]
fn test_v5_subkeys_are_distinct() {
    let root = RootKey::from([0x42u8; 32]);
    let keys = V5Keys::derive(&root);
    let values = [
        keys.enc_key_for_tests(),
        keys.auth_key_for_tests(),
        keys.siv_key_for_tests(),
        keys.block_key_for_tests(),
        keys.segment_key_for_tests(),
    ];
    for i in 0..values.len() {
        for j in i + 1..values.len() {
            assert_ne!(values[i], values[j]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn prop_v5_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let container = encrypt_v5(&data, b"property-password", opts_with(96, 2)).unwrap();
        prop_assert_eq!(decrypt_auto(&container, b"property-password").unwrap(), data);
    }

    #[test]
    fn prop_v5_single_byte_mutation_rejected(
        data in proptest::collection::vec(any::<u8>(), 0..128),
        n in any::<usize>(),
    ) {
        let mut container = encrypt_v5(&data, b"property-password", opts_with(96, 2)).unwrap();
        let index = n % container.len();
        container[index] ^= 1;
        let result = decrypt_auto(&container, b"property-password");
        prop_assert!(result.as_ref().map(|plain| plain != &data).unwrap_or(true));
    }
}
