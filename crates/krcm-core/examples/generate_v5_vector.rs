use std::fs;

use krcm_core::{encrypt_v5, EncryptV5Options, KdfParams, PaddingPolicy};

fn main() {
    let password = b"krcm-v5-test-password";
    let plaintext = b"hello v5";
    let container = encrypt_v5(
        plaintext,
        password,
        EncryptV5Options {
            kdf: KdfParams::Pbkdf2 { iterations: 1_000 },
            padding_policy: PaddingPolicy::MinimalBlock,
            segment_size: 64,
            workers: 4,
            salt: Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            public_nonce: Some([
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
        },
    )
    .unwrap();
    let json = format!(
        concat!(
            "{{\n",
            "  \"version\": 5,\n",
            "  \"name\": \"v5-deterministic-container\",\n",
            "  \"password_hex\": \"{}\",\n",
            "  \"plaintext_hex\": \"{}\",\n",
            "  \"salt_hex\": \"000102030405060708090a0b0c0d0e0f\",\n",
            "  \"public_nonce_hex\": \"101112131415161718191a1b1c1d1e1f\",\n",
            "  \"container_hex\": \"{}\",\n",
            "  \"warning\": \"Test vector only. Password and data are not secret.\"\n",
            "}}\n"
        ),
        hex(password),
        hex(plaintext),
        hex(&container)
    );
    fs::create_dir_all("test-vectors/v5").unwrap();
    fs::write("test-vectors/v5/container_vector.json", json).unwrap();
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}
