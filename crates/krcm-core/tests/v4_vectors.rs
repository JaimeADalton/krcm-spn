use std::fs;
use std::path::Path;

use krcm_core::kdf::derive_keys;
use krcm_core::{decrypt_v4, encrypt_v4, EncryptV4Options};
use serde_json::Value;

const WARNING: &str = "Test vector only. Password and data are not secret.";

fn hex_to_bytes(text: &str) -> Vec<u8> {
    hex::decode(text).expect("valid hex in vector")
}

#[test]
fn test_v4_vectors_from_python() {
    let path = Path::new("../../test-vectors/v4/container_vectors.json");
    let vectors: Vec<Value> =
        serde_json::from_slice(&fs::read(path).expect("container vectors exist")).unwrap();
    assert_eq!(vectors.len(), 12);
    for vector in vectors {
        assert_eq!(vector["warning"].as_str().unwrap(), WARNING);
        let password = hex_to_bytes(vector["password_hex"].as_str().unwrap());
        let plaintext = hex_to_bytes(vector["plaintext_hex"].as_str().unwrap());
        let container = hex_to_bytes(vector["container_hex"].as_str().unwrap());
        assert_eq!(decrypt_v4(&container, &password).unwrap(), plaintext);

        let rng_outputs = vector["rng_outputs_hex"].as_array().unwrap();
        let salt: [u8; 16] = hex_to_bytes(rng_outputs[0].as_str().unwrap())
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex_to_bytes(rng_outputs[1].as_str().unwrap())
            .try_into()
            .unwrap();
        let regenerated = encrypt_v4(
            &plaintext,
            &password,
            EncryptV4Options {
                iterations: 1_000,
                salt: Some(salt),
                nonce: Some(nonce),
            },
        )
        .unwrap();
        assert_eq!(regenerated, container);
    }
}

#[test]
fn test_v4_exact_container_match_python() {
    let path = Path::new("../../test-vectors/v4/container_vectors.json");
    let vectors: Vec<Value> =
        serde_json::from_slice(&fs::read(path).expect("container vectors exist")).unwrap();
    let vector = &vectors[3];
    let password = hex_to_bytes(vector["password_hex"].as_str().unwrap());
    let plaintext = hex_to_bytes(vector["plaintext_hex"].as_str().unwrap());
    let rng_outputs = vector["rng_outputs_hex"].as_array().unwrap();
    let salt: [u8; 16] = hex_to_bytes(rng_outputs[0].as_str().unwrap())
        .try_into()
        .unwrap();
    let nonce: [u8; 16] = hex_to_bytes(rng_outputs[1].as_str().unwrap())
        .try_into()
        .unwrap();
    let regenerated = encrypt_v4(
        &plaintext,
        &password,
        EncryptV4Options {
            iterations: 1_000,
            salt: Some(salt),
            nonce: Some(nonce),
        },
    )
    .unwrap();
    assert_eq!(
        regenerated,
        hex_to_bytes(vector["container_hex"].as_str().unwrap())
    );
}

#[test]
fn test_v4_roundtrip_sizes() {
    for size in [0usize, 1, 31, 32, 33, 63, 64, 65, 127, 1024] {
        let data = (0..size).map(|i| (i * 19 + size) as u8).collect::<Vec<_>>();
        let container = encrypt_v4(
            &data,
            b"password",
            EncryptV4Options {
                iterations: 1_000,
                salt: Some([3u8; 16]),
                nonce: Some([4u8; 16]),
            },
        )
        .unwrap();
        assert_eq!(decrypt_v4(&container, b"password").unwrap(), data);
    }
}

#[test]
fn test_v4_kdf_matches_python_reference() {
    let (enc_key, auth_key) =
        derive_keys(b"kdf-password", &Vec::from_iter(0u8..16), 1_000).unwrap();
    assert_eq!(
        enc_key.expose_for_tests(),
        hex_to_bytes("bc44b29d995f5ff48cd6e231e8b2f3060062b18ed3f538e3aa7f0da01f273404")[..]
    );
    assert_eq!(
        auth_key.expose_for_tests(),
        hex_to_bytes("8d54915b8194f7a9e59daf56f972247087f5e380b7eb95a9040017975277c810")[..]
    );
}

#[test]
fn test_v4_tamper_and_wrong_password_rejected() {
    let data = b"tamper test payload";
    let password = b"correct password";
    let container = encrypt_v4(
        data,
        password,
        EncryptV4Options {
            iterations: 1_000,
            salt: Some([1u8; 16]),
            nonce: Some([2u8; 16]),
        },
    )
    .unwrap();
    assert_eq!(decrypt_v4(&container, password).unwrap(), data);
    assert!(decrypt_v4(&container, b"wrong password").is_err());

    for index in [12usize, container.len() / 2, container.len() - 1] {
        let mut tampered = container.clone();
        tampered[index] ^= 0x80;
        assert!(decrypt_v4(&tampered, password).is_err());
    }
}

#[test]
fn test_v4_wrong_password() {
    let container = encrypt_v4(
        b"payload",
        b"correct",
        EncryptV4Options {
            iterations: 1_000,
            salt: Some([1u8; 16]),
            nonce: Some([2u8; 16]),
        },
    )
    .unwrap();
    assert!(decrypt_v4(&container, b"wrong").is_err());
}

#[test]
fn test_v4_tamper_header() {
    let mut container = encrypt_v4(
        b"payload",
        b"password",
        EncryptV4Options {
            iterations: 1_000,
            salt: Some([1u8; 16]),
            nonce: Some([2u8; 16]),
        },
    )
    .unwrap();
    container[15] ^= 1;
    assert!(decrypt_v4(&container, b"password").is_err());
}

#[test]
fn test_v4_tamper_ciphertext() {
    let mut container = encrypt_v4(
        b"payload",
        b"password",
        EncryptV4Options {
            iterations: 1_000,
            salt: Some([1u8; 16]),
            nonce: Some([2u8; 16]),
        },
    )
    .unwrap();
    let index = container.len() - 40;
    container[index] ^= 1;
    assert!(decrypt_v4(&container, b"password").is_err());
}

#[test]
fn test_v4_tamper_tag() {
    let mut container = encrypt_v4(
        b"payload",
        b"password",
        EncryptV4Options {
            iterations: 1_000,
            salt: Some([1u8; 16]),
            nonce: Some([2u8; 16]),
        },
    )
    .unwrap();
    let index = container.len() - 1;
    container[index] ^= 1;
    assert!(decrypt_v4(&container, b"password").is_err());
}

#[test]
fn test_v4_header_too_large_rejected() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"AMPCRYPT");
    blob.extend_from_slice(&(4097u32).to_be_bytes());
    blob.extend_from_slice(&[0u8; 64]);
    assert!(decrypt_v4(&blob, b"password").is_err());
}

#[test]
fn test_v4_iterations_too_large() {
    let header = b"{\"block_bytes\":32,\"construction\":\"AMPC-Permutation-Matrix-v4\",\"iterations\":1000001,\"magic\":\"AMPCRYPT\",\"nonce\":\"AgICAgICAgICAgICAgICAg==\",\"original_length\":0,\"rounds\":10,\"salt\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"version\":4,\"word_bits\":64}";
    let mut blob = Vec::new();
    blob.extend_from_slice(b"AMPCRYPT");
    blob.extend_from_slice(&(header.len() as u32).to_be_bytes());
    blob.extend_from_slice(header);
    blob.extend_from_slice(&[0u8; 32]);
    assert!(decrypt_v4(&blob, b"password").is_err());
}
