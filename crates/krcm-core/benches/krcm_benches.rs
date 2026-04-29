use criterion::{black_box, criterion_group, criterion_main, Criterion};
use krcm_core::block::encrypt_blocks;
use krcm_core::kdf::derive_keys;
use krcm_core::{
    encrypt_v4, encrypt_v5, EncryptV4Options, EncryptV5Options, KdfParams, PaddingPolicy,
};

fn v4_opts() -> EncryptV4Options {
    EncryptV4Options {
        iterations: 1_000,
        salt: Some([1u8; 16]),
        nonce: Some([2u8; 16]),
    }
}

fn v5_opts(workers: usize) -> EncryptV5Options {
    EncryptV5Options {
        kdf: KdfParams::Pbkdf2 { iterations: 1_000 },
        padding_policy: PaddingPolicy::MinimalBlock,
        segment_size: 4096,
        workers,
        salt: Some([3u8; 16]),
        public_nonce: Some([4u8; 16]),
    }
}

fn bench_encrypt(c: &mut Criterion) {
    for (name, size) in [("1k", 1024usize), ("64k", 65_536), ("1m", 1_048_576)] {
        let data = vec![0x42u8; size];
        c.bench_function(&format!("bench_v4_encrypt_{name}"), |b| {
            b.iter(|| encrypt_v4(black_box(&data), b"bench", v4_opts()).unwrap())
        });
        c.bench_function(&format!("bench_v5_encrypt_{name}"), |b| {
            b.iter(|| encrypt_v5(black_box(&data), b"bench", v5_opts(1)).unwrap())
        });
    }
}

fn bench_workers(c: &mut Criterion) {
    let data = vec![0x55u8; 65_536];
    for workers in [1usize, 2, 4, 8] {
        c.bench_function(&format!("bench_v5_workers_{workers}"), |b| {
            b.iter(|| encrypt_v5(black_box(&data), b"bench", v5_opts(workers)).unwrap())
        });
    }
}

fn bench_core(c: &mut Criterion) {
    let (enc_key, _) = derive_keys(b"bench", &[1u8; 16], 1_000).unwrap();
    let padded = vec![0x11u8; 32];
    c.bench_function("bench_block_encrypt", |b| {
        b.iter(|| encrypt_blocks(black_box(&padded), &enc_key, &[2u8; 16]).unwrap())
    });
    c.bench_function("bench_permutation", |b| {
        b.iter(|| encrypt_blocks(black_box(&padded), &enc_key, &[3u8; 16]).unwrap())
    });
    c.bench_function("bench_matrix", |b| {
        b.iter(|| encrypt_blocks(black_box(&padded), &enc_key, &[4u8; 16]).unwrap())
    });
}

criterion_group!(benches, bench_encrypt, bench_workers, bench_core);
criterion_main!(benches);
