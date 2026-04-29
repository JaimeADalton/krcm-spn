# KRCM Authenticated Container Format

KRCM-SPN is experimental research software, not a production encryption format.

## v4 Legacy Container

The v4 container keeps the legacy magic bytes `AMPCRYPT` for compatibility.

```text
magic       8 bytes   AMPCRYPT
header_len 4 bytes   u32 big-endian
header      variable canonical JSON
ciphertext  variable 32-byte aligned block ciphertext
tag        32 bytes  HMAC-SHA256(header || ciphertext)
```

The v4 JSON header is serialized with sorted keys and compact separators. It carries
`magic`, `version`, `iterations`, `salt`, `nonce`, `original_length`, `block_bytes`,
`word_bits`, `rounds`, and `construction`.

## v5 Public Header

The v5 public header is exactly 64 bytes. Multi-byte integer fields are big-endian.

```text
offset size field
0      8    magic               KRCMSPN\0
8      1    container_version   5
9      1    header_version      1
10     1    kdf_id              1=PBKDF2, 2=scrypt
11     1    flags               reserved, zero
12     4    pbkdf2_iterations   u32be
16     1    scrypt_n_log2       u8
17     4    scrypt_r            u32be
21     4    scrypt_p            u32be
25     1    segment_size_log2   u8
26     1    pad_policy          0=minimal, 1=random blocks
27     5    reserved            all zero
32     16   salt
48     16   public_nonce
```

Any non-zero reserved byte is a format error. `public_header_len` in the outer v5
container must be 64.

## v5 Inner Plaintext

The inner plaintext is encrypted and authenticated before release.

```text
offset size field
0      8    inner_magic       KRCMIN5\0
8      1    inner_version     1
9      1    flags             zero
10     2    reserved          zero
12     8    original_length   u64be
20     8    payload_length    u64be
28     32   payload_sha256
60     2    algorithm_id      u16be
62     2    block_bytes       u16be
64     2    rounds            u16be
66     10   reserved2         zero
76     var  payload
...    var  random padding
```

`payload_sha256` is computed over the first `payload_length` bytes of payload data.

## v5 Segment Table

Each segment entry is exactly 40 bytes:

```text
segment_index      u64be
plain_offset       u64be
plain_length       u64be
ciphertext_offset  u64be
ciphertext_length  u64be
```

Entries are sorted by `segment_index`, starting at zero without gaps. The table length
must be a multiple of 40 bytes.

## v5 Authentication Transcript

All transcript lengths are `u64` big-endian.

```text
u64be(len("KRCM-v5-TAG")) || "KRCM-v5-TAG" ||
u64be(len(public_header)) || public_header ||
u64be(len(synthetic_iv))  || synthetic_iv ||
u64be(len(segment_table)) || segment_table ||
u64be(len(ciphertext))    || ciphertext
```

The tag is `HMAC-SHA256(auth_key, transcript)` and must be checked in constant time
before deriving or using the effective nonce for decryption.

## v5 Outer Container

```text
magic              8 bytes   KRCMSPN\0
container_version  1 byte    5
public_header_len  4 bytes   u32be, always 64
public_header      64 bytes
synthetic_iv       32 bytes
segment_table_len  8 bytes   u64be
segment_table      variable
ciphertext_len     8 bytes   u64be
ciphertext         variable
tag                32 bytes
```
