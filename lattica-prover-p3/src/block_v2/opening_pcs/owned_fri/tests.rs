use super::*;
use crate::block_v2::gpu_hash::{
    self,
    device::{Extension, MatrixSpec, RowOrder},
};
use crate::config::{MyCompress, MyHash, ValMmcs};
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
#[ignore = "requires OpenCL GPU, GPU_HASH=1 and a <=3 GiB zero-swap service"]
fn resident_fri_matches_upstream_at_multiple_heights_without_layer_transfers() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    let baseline = gpu_hash::report("before FRI fixtures").unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    for heights in [
        vec![16usize],
        vec![32, 16],
        vec![2048, 128, 16],
        vec![65536, 4096, 256],
    ] {
        let perm = default_goldilocks_poseidon2_8();
        let base = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([83; 32]),
        );
        let input_mmcs = CandidateMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([83; 32]),
        );
        let gpu = profile::fri(ChallengeMmcs::new(input_mmcs.clone()));
        let cpu = profile::fri(ExtensionMmcs::<Val, Challenge, _>::new(base));
        let values: Vec<Vec<Challenge>> = heights
            .iter()
            .enumerate()
            .map(|(which, height)| {
                let mut coeffs = vec![Challenge::ZERO; *height];
                for (i, c) in coeffs
                    .iter_mut()
                    .take(*height >> profile::LOG_BLOWUP)
                    .enumerate()
                {
                    *c = challenge(&[i as u64 + 7, which as u64 + 13, (i % 2) as u64]);
                }
                let mut values = <Radix2DFTSmallBatch<Val> as TwoAdicSubgroupDft<Val>>::dft_algebra(
                    &Radix2DFTSmallBatch::default(),
                    coeffs,
                );
                reverse_slice_index_bits(&mut values);
                values
            })
            .collect();
        let inputs: Vec<_> = values
            .iter()
            .map(|v| {
                let spec = MatrixSpec::new(
                    v.len().ilog2(),
                    1,
                    Extension::Cubic,
                    RowOrder::BitReversed,
                    1,
                )
                .unwrap();
                session
                    .upload(spec, &v.iter().copied().flat_map(words).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect();
        // Failure must occur before advancing the exact FRI salt stream.
        assert!(gpu
            .mmcs
            .inner()
            .commit_fri_device(&session, &inputs[0], 0)
            .is_err());
        assert!(DeviceSession::new()
            .unwrap()
            .fri_leaves(&inputs[0])
            .is_err());
        assert!(session.gather_rows(&inputs[0], &[], 8).is_err());
        assert!(session.gather_rows(&inputs[0], &[heights[0]], 24).is_err());
        assert!(session.gather_rows(&inputs[0], &[0], 23).is_err());
        assert!(session
            .gather_rows(&inputs[0], &vec![0; 4097], usize::MAX)
            .is_err());
        if heights[0] >= 2048 {
            let budget: usize = std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")
                .unwrap()
                .parse()
                .unwrap();
            let live = gpu_hash::report("before FRI admission failure")
                .unwrap()
                .managed_live_bytes;
            let words = (budget - live - 4096) / 8;
            let filler_spec =
                MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1).unwrap();
            let filler = session.upload(filler_spec, &vec![0; words]).unwrap();
            assert!(gpu
                .mmcs
                .inner()
                .commit_fri_device(&session, &inputs[0], HOST_SALT_ALLOWANCE)
                .is_err());
            drop(filler);
        }
        let before = session.stats();
        let mut actual_challenger = Challenger::new(perm.clone());
        let mut reference_challenger = Challenger::new(perm);
        let log_height = heights[0].ilog2() as usize;
        let (expected, actual) = pool.install(|| {
            let folding: TwoAdicFriFoldingForMmcs<Val, CandidateMmcs> =
                TwoAdicFriFolding(PhantomData);
            let expected = prover::prove_fri(
                &folding,
                &cpu,
                values,
                &mut reference_challenger,
                log_height,
                &[],
                &input_mmcs,
                |_| {},
                |_, _, _| None,
            );
            let actual = prove(
                &session,
                &input_mmcs,
                &gpu,
                inputs,
                &mut actual_challenger,
                log_height,
                &[],
                64 << 20,
            )
            .unwrap();
            (expected, actual)
        });
        assert_eq!(
            postcard::to_allocvec(&expected).unwrap(),
            postcard::to_allocvec(&actual).unwrap()
        );
        let a: Challenge = actual_challenger.sample_algebra_element();
        let b: Challenge = reference_challenger.sample_algebra_element();
        assert_eq!(a, b);
        let rounds = log_height - profile::LOG_BLOWUP;
        let after = session.stats();
        assert_eq!(after.cubic_folds - before.cubic_folds, rounds as u64);
        assert_eq!(after.fri_mixes - before.fri_mixes, heights.len() as u64 - 1);
        let gathered = 24 + rounds * profile::NUM_QUERIES * 80;
        let caps: usize = (0..rounds)
            .map(|r| (heights[0] >> (r + 1)).min(1 << profile::CAP_HEIGHT) * 32)
            .sum();
        let paths: usize = (0..rounds)
            .map(|r| {
                (log_height - r - 1).saturating_sub(profile::CAP_HEIGHT) * 32 * profile::NUM_QUERIES
            })
            .sum();
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            (gathered + caps + paths) as u64
        );
        let salts = (heights[0] - (1 << profile::LOG_BLOWUP)) * 32;
        let indices = (1 + rounds * 2 * profile::NUM_QUERIES) * 8;
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            (salts + indices) as u64
        );
        let freed = gpu_hash::report("after FRI fixture").unwrap();
        assert_eq!(
            freed.device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
        assert_eq!(freed.device_matrices, baseline.device_matrices);
    }
}
