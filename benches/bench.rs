extern crate caead;
extern crate criterion;
extern crate orion;

use criterion::*;

static INPUT_SIZES: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];

mod aead {
    use caead::{nae::ChaCha20Poly1305, traits::NAEAD};

    use super::*;

    pub fn bench_chacha20poly1305(c: &mut Criterion) {
        let mut group = c.benchmark_group("ChaCha20-Poly130");
        let k = [0u8; 32];
        let n = [0u8; 12];
        let a = b"v1";

        // First we setup the ciphertext tags pairs
        // and then measure decrypt as this is the most expensive operation (the same as encryption plus tag verification.)
        let mut ct_tag_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for size in INPUT_SIZES.iter() {
            let m = vec![0u8; *size];
            ct_tag_pairs.push(ChaCha20Poly1305::encrypt(&k, &n, &m, a).unwrap());
        }

        for (size, pair) in INPUT_SIZES.iter().zip(ct_tag_pairs.iter()) {
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(BenchmarkId::new("decrypt", *size), pair, |b, input_pair| {
                b.iter(|| {
                    ChaCha20Poly1305::decrypt(&k, &n, a, &input_pair.0, &input_pair.1, true)
                        .unwrap();
                })
            });
        }
    }

    criterion_group! {
        name = aead_benches;
        config = Criterion::default();
        targets =
        bench_chacha20poly1305,
        // TDOD: Add normal AEC-GCM
    }
}

mod kc_aead {
    use caead::{
        kc::{HtE, CTX},
        nae::ChaCha20Poly1305,
    };
    use orion::hazardous::hash::blake2::blake2b::Blake2b;

    use super::*;

    pub fn bench_ctx_chacha20poly1305_blake2b(c: &mut Criterion) {
        let mut group = c.benchmark_group("CTX-ChaCha20-Poly1305-BLAKE2b");
        let ctx = CTX::<ChaCha20Poly1305, Blake2b, 32, 12, 16, 32>::new([0u8; 32]).unwrap();
        let n = [0u8; 12];
        let a = b"v1";

        // First we setup the ciphertext tags pairs
        // and then measure decrypt as this is the most expensive operation (the same as encryption plus tag verification.)
        let mut ct_tag_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for size in INPUT_SIZES.iter() {
            let m = vec![0u8; *size];
            ct_tag_pairs.push(ctx.encrypt(&n, &m, a).unwrap());
        }

        for (size, pair) in INPUT_SIZES.iter().zip(ct_tag_pairs.iter()) {
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("kc-decrypt", *size),
                pair,
                |b, input_pair| {
                    b.iter(|| {
                        ctx.decrypt(&n, &input_pair.0, a, &input_pair.1).unwrap();
                    })
                },
            );
        }
    }

    pub fn bench_hte_chacha20poly1305_blake2b(c: &mut Criterion) {
        let mut group = c.benchmark_group("HtE-ChaCha20-Poly1305-BLAKE2b");
        let hte = HtE::<ChaCha20Poly1305, Blake2b, 32, 12, 16, 32>::new([0u8; 32]).unwrap();
        let n = [0u8; 12];
        let a = b"v1";

        // First we setup the ciphertext tags pairs
        // and then measure decrypt as this is the most expensive operation (the same as encryption plus tag verification.)
        let mut ct_tag_pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for size in INPUT_SIZES.iter() {
            let m = vec![0u8; *size];
            ct_tag_pairs.push(hte.encrypt(&n, &m, a).unwrap());
        }

        for (size, pair) in INPUT_SIZES.iter().zip(ct_tag_pairs.iter()) {
            group.throughput(Throughput::Bytes(*size as u64));
            group.bench_with_input(
                BenchmarkId::new("kc-decrypt", *size),
                pair,
                |b, input_pair| {
                    b.iter(|| {
                        hte.decrypt(&n, &input_pair.1, a, &input_pair.0).unwrap();
                    })
                },
            );
        }
    }

    criterion_group! {
        name = kc_aead_benches;
        config = Criterion::default();
        targets =
        bench_ctx_chacha20poly1305_blake2b,
        bench_hte_chacha20poly1305_blake2b,
        // TDOD: Add CTX-AEC-GCM, and UtC+HtE for both
    }
}

criterion_main!(aead::aead_benches, kc_aead::kc_aead_benches,);
