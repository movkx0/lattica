use super::super::tests::{runtime, upload, value};
use super::*;
use crate::{
    config::{MyCompress, MyHash, Val, ValMmcs},
    cuda_compute::Randoms,
};
use p3_commit::{BatchOpening, BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use p3_merkle_tree::MerkleCap;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

type Cpu<F> = ExtensionMmcs<Val, F, ValMmcs>;
fn rng(seed: u8) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    rng.set_word_pos((1 << 36) - 1);
    rng
}
fn oracle<F: ExtensionField<Val>>(seed: u8, cap: usize) -> Cpu<F> {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    Cpu::new(ValMmcs::new(
        MyHash::new(p.clone()),
        MyCompress::new(p),
        cap,
        rng(seed),
    ))
}
fn digests(raw: &[u64]) -> Vec<[Val; 4]> {
    raw.chunks_exact(4)
        .map(|c| std::array::from_fn(|i| Val::from_u64(c[i])))
        .collect()
}
fn opening<F: ExtensionField<Val>>(
    data: &FriLayerOpenings,
    query: usize,
) -> BatchOpening<F, Cpu<F>> {
    let values = data.values[query * data.width..(query + 1) * data.width]
        .chunks_exact(F::DIMENSION)
        .map(|v| F::from_basis_coefficients_fn(|j| Val::from_u64(v[j])))
        .collect();
    let salts = vec![data.salts[query * 4..(query + 1) * 4]
        .iter()
        .map(|&v| Val::from_u64(v))
        .collect()];
    let path = digests(&data.paths[query * data.path_len * 4..(query + 1) * data.path_len * 4]);
    BatchOpening::new(vec![values], (salts, path))
}

fn compare<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(16 << 20, 8 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for (log, arity) in [(8, 1), (10, 2), (9, 4)] {
        let values: Vec<F> = (0..1 << log).map(value).collect();
        let original = upload(&runtime, extension, log, 7, &values);
        let vector = fri.rescale(&original).unwrap();
        for cap_height in [0, 6] {
            let random = randoms.import(rng(33)).unwrap();
            let before = runtime.snapshot();
            let layer = fri
                .commit_layer(&commitments, &vector, arity, &random, cap_height)
                .unwrap();
            let after = runtime.snapshot();
            assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
            // Capture and replay each report only their public sampler status.
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 16);
            let cpu = oracle::<F>(33, cap_height);
            let (expected_cap, expected_data) =
                cpu.commit_matrix(RowMajorMatrix::new(values.clone(), 1 << arity));
            let cap = MerkleCap::new(digests(&layer.cap(64 << 10).unwrap()));
            assert_eq!(cap, expected_cap);
            let height = 1usize << (log as usize - arity);
            for count in [1, 5, 33, 256] {
                let indices: Vec<_> = (0..count)
                    .map(|i| [height - 1, 0, 13, height - 1][i % 4])
                    .collect();
                let before = runtime.snapshot();
                let result = layer.open(&fri, &commitments, &indices, 2 << 20).unwrap();
                assert_eq!(result.queries, count);
                assert_eq!(
                    runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                    ((result.values.len() + result.salts.len() + result.paths.len()) * 8 + 8)
                        as u64
                );
                assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
                for (q, &index) in indices.iter().enumerate() {
                    let actual = opening::<F>(&result, q);
                    assert_eq!(
                        postcard::to_allocvec(&actual).unwrap(),
                        postcard::to_allocvec(&cpu.open_batch(index, &expected_data)).unwrap()
                    );
                    cpu.verify_batch(
                        &cap,
                        &[Dimensions {
                            height,
                            width: 1 << arity,
                        }],
                        index,
                        BatchOpeningRef::from(&actual),
                    )
                    .unwrap();
                    if cap_height == 0 && q == 0 {
                        let (mut values, proof) = actual.unpack();
                        values[0][0] += F::ONE;
                        assert!(cpu
                            .verify_batch(
                                &cap,
                                &[Dimensions {
                                    height,
                                    width: 1 << arity
                                }],
                                index,
                                BatchOpeningRef::new(&values, &proof)
                            )
                            .is_err());
                    }
                }
            }
            drop(layer);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
        }
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_quadratic_commitments_and_queries_match_upstream_wire_format() {
    compare::<crate::config::Challenge>(Extension::Quadratic);
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_cubic_commitments_and_queries_match_upstream_wire_format() {
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

fn pressure(runtime: &Runtime) -> Vec<Buffer> {
    let mut buffers = Vec::new();
    while runtime.snapshot().live_bytes + 8 <= 1 << 20 {
        let bytes = ((1 << 20) - runtime.snapshot().live_bytes).min(1 << 19);
        buffers.push(runtime.allocate(bytes / 8).unwrap());
    }
    buffers
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_layer_admission_preserves_salts_and_retired_families_reject_reads() {
    let runtime = runtime(1 << 20, 1 << 19);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let values: Vec<crate::config::Challenge> = (0..256).map(value).collect();
    let input = upload(&runtime, Extension::Quadratic, 8, 7, &values);
    let vector = fri.rescale(&input).unwrap();
    let random = randoms.import(rng(33)).unwrap();
    let held = pressure(&runtime);
    let before = runtime.snapshot();
    assert!(fri
        .commit_layer(&commitments, &vector, 2, &random, 0)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(held);
    let mut cpu_rng = rng(33);
    let samples = random.sample_fields(7).unwrap();
    let actual = samples.read_for_test(56).unwrap();
    let expected: Vec<_> = (0..7)
        .map(|_| cpu_rng.random::<Val>().as_canonical_u64())
        .collect();
    assert_eq!(actual.as_slice(), &expected);
    drop(samples);
    let layer = fri
        .commit_layer(&commitments, &vector, 2, &random, 0)
        .unwrap();
    let before = runtime.snapshot();
    assert!(layer.cap(31).is_err());
    for indices in [vec![], vec![64], vec![0; 4097]] {
        assert!(layer.open(&fri, &commitments, &indices, 1 << 20).is_err());
    }
    assert!(layer.open(&fri, &commitments, &[0; 256], 64 << 10).is_err());
    assert_eq!(runtime.snapshot(), before);
    let held = pressure(&runtime);
    let before = runtime.snapshot();
    assert!(layer.open(&fri, &commitments, &[0, 63], 1 << 20).is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(held);
    layer
        .open(&fri, &commitments, &[63, 0, 63], 1 << 20)
        .unwrap();
    random.retire();
    let before = runtime.snapshot();
    assert!(layer.cap(32).is_err());
    assert!(layer
        .open(&fri, &commitments, &[63, 0, 63], 1 << 20)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_query_failures_and_unwinds_retire_salt_families() {
    let runtime = runtime(1 << 20, 1 << 19);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let values: Vec<crate::config::Challenge> = (0..256).map(value).collect();
    let input = upload(&runtime, Extension::Quadratic, 8, 7, &values);
    let vector = fri.rescale(&input).unwrap();
    for fault in [Fault::AfterGather, Fault::PanicAfterGather] {
        let random = randoms.import(rng(33)).unwrap();
        let layer = fri
            .commit_layer(&commitments, &vector, 2, &random, 0)
            .unwrap();
        let before = runtime.snapshot();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            layer.open_impl(&fri, &commitments, &[0, 63, 0], 1 << 20, fault)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(runtime.snapshot().downloaded_bytes > before.downloaded_bytes);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert!(random.check_live().is_err());
        assert!(layer.cap(32).is_err());
    }
}
