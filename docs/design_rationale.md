# Design Rationale

KRCM-SPN is an experimental cryptographic construction for research and review.

## Dependencies

- `base64` is used only to reproduce the legacy v4 JSON header exactly.
- `clap`, `rpassword`, and `tempfile` are CLI support crates. They do not implement
  cryptographic logic.
- `hmac`, `sha2`, `pbkdf2`, `scrypt`, `subtle`, and `zeroize` provide standard support
  primitives for key derivation, authentication, constant-time comparison, and secret
  cleanup.
- `serde_json` is used for strict v4 JSON header parsing.
- `rand` and `rand_core` are used for salt, nonce, and padding randomness.

The Rust core owns all container parsing, KDF, block transformation, tag generation,
and tag verification. The CLI only handles files and terminal interaction.
