# Specification

KRCM-SPN is an experimental authenticated container construction. It combines a custom 32-byte block transformation with password-based key derivation and HMAC authentication.

The v4 format preserves the legacy `AMPCRYPT` container. The v5 format uses `KRCMSPN\0`, a fixed 64-byte public header, encrypted inner metadata, a synthetic IV, segmented block encryption, and an authenticated transcript.

The block state is 32 bytes. It is interpreted as four big-endian `u64` words, equivalent to a 2x2 matrix over `Z/(2^64)Z`. Each round applies coordinate substitution, byte diffusion, matrix mixing, and position permutation. Ten rounds are applied. In container modes, block seeds include the public nonce, block index, and feedback from the previous ciphertext block.

Authentication is mandatory. Decryption verifies the external tag before decrypting ciphertext or returning plaintext.
