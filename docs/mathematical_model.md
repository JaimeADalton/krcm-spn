# Mathematical Model

The block state is represented as `b in (Z/2^8Z)^32`. Packing the state as four big-endian 64-bit words identifies it with a 2x2 matrix over `Z/(2^64)Z`.

For round `r`, the transformation is:

```text
T_r = P_r o L_r o D_r o S_r
```

- `S_r`: coordinate substitution dependent on round seed.
- `D_r`: reversible modular triangular byte diffusion.
- `L_r`: left and right multiplication by invertible 2x2 matrices modulo `2^64`.
- `P_r`: state-coordinate permutation.

The container mode applies 10 rounds per block. The block seed is derived from the encryption key, nonce, block index, and feedback hash. Feedback is the previous ciphertext block, with the nonce used for the first block.
