# Security Considerations

KRCM-SPN is an experimental cryptographic construction. It is not a replacement for audited, standardized schemes such as AES-GCM, ChaCha20-Poly1305, age, GnuPG, or libsodium. Do not use it to protect production data, regulated data, financial secrets, credentials, or any information whose compromise would cause harm. The project is intended for research, experimentation, implementation practice, and review.

## Known Limitations

- The block transformation is custom and has no external cryptanalysis.
- The implementation has not been audited.
- v4 exposes `original_length` in the public JSON header.
- v5 hides inner metadata but remains experimental.
- Password-based encryption remains vulnerable to password guessing when weak passwords are used.

## Authentication

v4 authenticates `header || ciphertext` with HMAC-SHA256. v5 authenticates an explicit transcript containing the public header, synthetic IV, segment table, and ciphertext. Decryption must verify the tag before decrypting or returning plaintext.

## Operational Guidance

Use this project only for research, test vectors, implementation practice, and review. For real data, use a standardized and audited tool or library.
