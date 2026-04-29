use krcm_core::kdf::derive_root_key;
use krcm_core::KdfParams;

#[test]
fn test_pbkdf2_limit() {
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Pbkdf2 { iterations: 1 }
    )
    .is_ok());
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Pbkdf2 { iterations: 0 }
    )
    .is_err());
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Pbkdf2 {
            iterations: 1_000_001
        }
    )
    .is_err());
}

#[test]
fn test_scrypt_limit_n() {
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Scrypt {
            n_log2: 16,
            r: 8,
            p: 1
        }
    )
    .is_err());
}

#[test]
fn test_scrypt_limit_r() {
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Scrypt {
            n_log2: 14,
            r: 9,
            p: 1
        }
    )
    .is_err());
}

#[test]
fn test_scrypt_limit_p() {
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Scrypt {
            n_log2: 14,
            r: 8,
            p: 3
        }
    )
    .is_err());
}

#[test]
fn test_scrypt_maxmem() {
    assert!(derive_root_key(
        b"password",
        &[0u8; 16],
        &KdfParams::Scrypt {
            n_log2: 15,
            r: 8,
            p: 2
        }
    )
    .is_ok());
}

#[test]
fn test_invalid_kdf_rejected_before_expensive_work() {
    assert!(derive_root_key(b"", &[0u8; 16], &KdfParams::Pbkdf2 { iterations: 1 }).is_err());
    assert!(derive_root_key(
        b"password",
        &[0u8; 15],
        &KdfParams::Pbkdf2 { iterations: 1 }
    )
    .is_err());
}
