use super::*;
use crate::{
    block_v2::{
        profile::{Challenge, Config},
        quotient_program::Program,
    },
    config::{MyCompress, MyHash},
    cuda_compute::{
        Commitments, Limits, QuotientInputs, Quotients, Runtime, Specialization, Transcripts,
    },
    gpu_matrix::{MatrixSpec, RowOrder},
};
use p3_air::symbolic::AirLayout;
use p3_batch_stark::BatchTranscript;
use p3_challenger::{CanObserve, CanSample};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_lookup::{Kind, LogUpGadget};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 4 << 20,
            max_allocation_bytes: 2 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn cpu() -> BatchTranscript<Config> {
    BatchTranscript::new(CandidateChallenger::new(
        p3_goldilocks::default_goldilocks_poseidon2_8(),
    ))
}
fn lookup(kind: Kind, width: usize) -> Lookup<Val> {
    Lookup {
        kind,
        elements: vec![vec![Val::ONE.into(); width]],
        multiplicities: vec![Val::ONE.into()],
        count_weight: 1,
        column: 0,
    }
}
fn read(buffer: &Buffer) -> Vec<u64> {
    let mut output = vec![0; buffer.len()];
    buffer.read(0, &mut output).unwrap();
    output
}
fn words(value: Challenge) -> Vec<u64> {
    let coefficients: &[Val] = value.as_basis_coefficients_slice();
    coefficients
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

#[test]
fn cuda_lookup_metadata_matches_encounter_order_and_rejects_excess_before_allocating() {
    let rows = [
        vec![lookup(Kind::Global("a".into()), 1), lookup(Kind::Local, 2)],
        vec![],
        vec![
            lookup(Kind::Global("a".into()), 7),
            lookup(Kind::Global("b".into()), 0),
            lookup(Kind::Local, 1),
        ],
    ];
    let refs: Vec<_> = rows.iter().map(Vec::as_slice).collect();
    assert_eq!(
        lookup_layout::bus_layout(&refs).unwrap(),
        (vec![vec![0, 1], vec![], vec![0, 2, 3]], 7, 4)
    );
    assert!(lookup_layout::bus_layout(&vec![&[][..]; 4097]).is_err());
    let excess = vec![lookup(Kind::Local, 1); 4097];
    assert!(lookup_layout::bus_layout(&[&excess]).is_err());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_lookup_challenges_match_upstream_without_host_field_transfers() {
    let runtime = runtime();
    let scalars = Scalars::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    for rows in [
        vec![
            vec![lookup(Kind::Global("a".into()), 1), lookup(Kind::Local, 4)],
            vec![],
            vec![
                lookup(Kind::Global("a".into()), 7),
                lookup(Kind::Global("b".into()), 0),
                lookup(Kind::Local, 0),
            ],
        ],
        vec![vec![], vec![]],
        vec![vec![lookup(Kind::Local, 0)]],
        vec![vec![lookup(Kind::Global("shared".into()), 1); 4096]],
    ] {
        let refs: Vec<_> = rows.iter().map(Vec::as_slice).collect();
        let mut actual = CandidateChallenger::new_cuda(&transcripts).unwrap();
        let mut reference = cpu();
        for pending in 0..5 {
            let input: Vec<_> = (0..pending).map(|i| Val::new(i + 17)).collect();
            actual.observe_slice(&input);
            reference.challenger.observe_slice(&input);
            let expected = reference.sample_perm_challenges(&refs, &LogUpGadget::new());
            let before = runtime.snapshot();
            let result = actual.cuda_lookup_challenges(&scalars, &refs).unwrap();
            let after = runtime.snapshot();
            assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
            let count: usize = refs.iter().map(|r| r.len()).sum();
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                (count * 8) as u64,
                "only public IDs are uploaded"
            );
            let values = result.values.as_ref().map(read).unwrap_or_default();
            if count == 0 {
                assert_eq!(after, before);
            }
            for (range, expected) in result.instances.iter().zip(expected) {
                assert_eq!(
                    &values[range.clone()],
                    expected.into_iter().flat_map(words).collect::<Vec<_>>()
                );
            }
            let expected: Challenge = reference.challenger.sample();
            let observed: Challenge = actual.sample();
            assert_eq!(
                observed, expected,
                "lookup adapter preserves the following transcript sample"
            );
        }
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_lookup_rejection_retires_snapshots_before_sampling() {
    let runtime = runtime();
    let scalars = Scalars::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    let mut actual = CandidateChallenger::new_cuda(&transcripts).unwrap();
    let related = actual.clone();
    let before = runtime.snapshot();
    assert!(actual
        .cuda_lookup_challenges(&scalars, &vec![&[][..]; 4097])
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(related.begin_attempt().is_err());
    let mut fresh = CandidateChallenger::new_cuda(&transcripts).unwrap();
    let mut filler = Vec::new();
    while runtime.snapshot().live_bytes < 4 << 20 {
        let remaining = ((4 << 20) - runtime.snapshot().live_bytes) / 8;
        filler.push(runtime.allocate(remaining.min((2 << 20) / 8)).unwrap());
    }
    let before = runtime.snapshot();
    assert!(fresh
        .cuda_lookup_challenges(&scalars, &[&[lookup(Kind::Local, 1)]])
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(fresh.begin_attempt().is_err());
    drop(filler);
    let mut independent = CandidateChallenger::new_cuda(&transcripts).unwrap();
    assert!(independent
        .cuda_lookup_challenges(&scalars, &[&[]])
        .unwrap()
        .values
        .is_none());
}

#[test]
#[ignore = "requires CUDA and NVRTC; native stage chain, not complete CUDA proving"]
fn cuda_lookup_scalars_feed_quotient_and_commitment_without_challenge_readback() {
    let runtime = runtime();
    let scalars = Scalars::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    let evaluator = Quotients::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let program = Program {
        extension: Extension::Cubic,
        instructions: vec![
            1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 12, 0, 0, 1, 0, 4, 1, 3, 0, 0, 14, 0, 0, 1, 0, 17, 0, 0,
            0, 0, 17, 0, 1, 1, 0,
        ],
        registers: 2,
        constraints: 2,
        layout: AirLayout {
            main_width: 1,
            num_permutation_challenges: 2,
            ..AirLayout::default()
        },
        row_words: 2,
        parameter_words: 6,
    };
    let prepared = evaluator
        .prepare(Arc::new(program), Specialization::Prefer)
        .unwrap();
    let main_values: Vec<_> = (0..16).map(|i| i * 17 + 7).collect();
    let main = runtime
        .upload_matrix(
            MatrixSpec::new(4, 1, Extension::Base, RowOrder::Natural, 7).unwrap(),
            &main_values,
        )
        .unwrap();
    let mut actual = CandidateChallenger::new_cuda(&transcripts).unwrap();
    let mut reference = cpu();
    actual.observe_slice(&[Val::new(19), Val::new(23)]);
    reference
        .challenger
        .observe_slice(&[Val::new(19), Val::new(23)]);
    let rows = [lookup(Kind::Local, 2)];
    let expected = reference.sample_perm_challenges(&[&rows[..]], &LogUpGadget::new());
    let expected_alpha: Challenge = reference.challenger.sample();
    let before = runtime.snapshot();
    let parameters = actual.cuda_lookup_challenges(&scalars, &[&rows]).unwrap();
    let Backend::Cuda(transcript) = &mut actual.inner else {
        unreachable!()
    };
    let alpha = transcript.sample_resident(3).unwrap();
    let quotient = evaluator
        .evaluate(
            &prepared,
            3,
            QuotientInputs {
                main: Some(&main),
                preprocessed: None,
                permutation: None,
            },
            &alpha,
            parameters.values.as_ref(),
        )
        .unwrap();
    let tree = commitments.commit(&[&quotient], 0).unwrap();
    let after = runtime.snapshot();
    assert_eq!(
        after.uploaded_bytes - before.uploaded_bytes,
        8,
        "only one public bus ID"
    );
    assert_eq!(
        after.downloaded_bytes - before.downloaded_bytes,
        8,
        "only quotient domain validity"
    );
    let prefix = expected[0][0];
    let beta = expected[0][1];
    let root = Val::two_adic_generator(4);
    let expected: Vec<Challenge> = main_values
        .iter()
        .enumerate()
        .map(|(i, &m)| {
            let x = Val::new(7) * root.exp_u64(i as u64);
            let z = x.exp_power_of_2(3) - Val::ONE;
            ((Challenge::from(Val::new(m)) + prefix) * beta * expected_alpha + beta)
                / Challenge::from(z)
        })
        .collect();
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(permutation.clone());
    let compress = MyCompress::new(permutation);
    let mut layer: Vec<[Val; 4]> = expected
        .iter()
        .map(|v| hash.hash_iter(v.as_basis_coefficients_slice().iter().copied()))
        .collect();
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|p| compress.compress([p[0], p[1]]))
            .collect();
    }
    let expected_cap: Vec<_> = layer[0]
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect();
    assert_eq!(tree.cap(32).unwrap(), expected_cap);
    assert_eq!(
        quotient.read(16 * 3 * 8).unwrap(),
        expected.into_iter().flat_map(words).collect::<Vec<_>>()
    );
}
