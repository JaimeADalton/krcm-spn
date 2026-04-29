# KRCM-SPN

KRCM-SPN is the Keyed Residue-Class Module Substitution-Permutation Network, an experimental Rust research implementation with legacy v4 container compatibility and a v5 SIV-style authenticated container.

## Security Warning

KRCM-SPN is an experimental cryptographic construction. It is not a replacement for audited, standardized schemes such as AES-GCM, ChaCha20-Poly1305, age, GnuPG, or libsodium. Do not use it to protect production data, regulated data, financial secrets, credentials, or any information whose compromise would cause harm. The project is intended for research, experimentation, implementation practice, and review.

## Project Status

The Rust implementation provides `krcm-core` and the `krcm` CLI. KRCM-SPN v4 is supported for legacy compatibility with the `AMPCRYPT` format identifier. KRCM-SPN v5 uses the `KRCMSPN\0` format identifier, a fixed public header, encrypted inner metadata, a synthetic IV, segmented block encryption, and an authenticated transcript.

## Scope

This project demonstrates a custom block transformation, authenticated container parsing, deterministic test vectors, fuzz targets, and benchmarks. It does not claim standardized security, formal proof, third-party audit, or suitability for sensitive data.

## Installation

Build the workspace with Cargo:

```bash
cargo build --release
```

The CLI binary is named `krcm`.

## CLI Usage

```bash
cargo run -p krcm-cli -- encrypt input.bin output.krcm
cargo run -p krcm-cli -- decrypt output.krcm recovered.bin
cargo run -p krcm-cli -- encrypt input.bin output.krcm --version 5 --kdf pbkdf2 --pbkdf2-iterations 200000
cargo run -p krcm-cli -- migrate legacy.ampc migrated.krcm --to-version 5
cargo run -p krcm-cli -- info output.krcm
cargo run -p krcm-cli -- self-test
```

Use `--force` to overwrite an existing output file. Without `--force`, the CLI fails before asking for a password.

## Library Usage

```rust
use krcm_core::{decrypt_auto, encrypt_v5, EncryptV5Options, KdfParams, PaddingPolicy};

let ciphertext = encrypt_v5(
    b"message",
    b"test password",
    EncryptV5Options {
        kdf: KdfParams::Pbkdf2 { iterations: 200_000 },
        padding_policy: PaddingPolicy::MinimalBlock,
        segment_size: 4 * 1024 * 1024,
        workers: 1,
        salt: None,
        public_nonce: None,
    },
)?;
let plaintext = decrypt_auto(&ciphertext, b"test password")?;
# Ok::<(), krcm_core::KrcmError>(())
```

## Build

```bash
cargo build --release
```

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
python3 -m unittest discover -s tests -v
```

Fuzz targets are under `fuzz/fuzz_targets`. Benchmarks are under `crates/krcm-core/benches`.

## Supported Formats

- v4: legacy `AMPCRYPT` authenticated container with JSON header and PBKDF2-HMAC-SHA256.
- v5: `KRCMSPN\0` authenticated container with fixed public header, encrypted inner metadata, SIV, segment table, and HMAC transcript.

## Roadmap

- Broader external review.
- Longer fuzzing campaigns with saved corpora.
- Additional interoperability vectors.
- Optional Python bindings over `krcm-core`.

## Citation

See `CITATION.cff`.

## Security Reports

See `SECURITY.md`.

## License

Licensed under `MIT OR Apache-2.0`.
