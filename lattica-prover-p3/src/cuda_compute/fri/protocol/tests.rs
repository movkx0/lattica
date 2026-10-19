use super::*;
use crate::{
    config::{self, Challenger, Dft, MyCompress, MyHash, MyPcs},
    cuda_compute::{Hiding, HidingInput, Openings, Randoms, Transcripts},
};
use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Mmcs, Pcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{coset::TwoAdicMultiplicativeCoset as Domain, PrimeField64};
use p3_fri::{CommitmentWithOpeningPoints, TwoAdicFriFolding, TwoAdicFriFoldingForMmcs};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

type CpuData = <ValMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
type Claims<F> = CommitmentWithOpeningPoints<F, <ValMmcs as Mmcs<Val>>::Commitment, Domain<Val>>;
type CpuFri<F> = p3_fri::FriParameters<ExtensionMmcs<Val, F, ValMmcs>>;

fn rng(seed: u8) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    rng.set_word_pos((1 << 36) - 1);
    rng
}
fn mmcs(seed: u8, cap: usize) -> ValMmcs {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    ValMmcs::new(MyHash::new(p.clone()), MyCompress::new(p), cap, rng(seed))
}
fn parameters<F: FriField>(cap: usize) -> CpuFri<F> {
    p3_fri::FriParameters {
        log_blowup: config::LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 4,
        num_queries: config::NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: config::QUERY_POW_BITS,
        mmcs: ExtensionMmcs::new(mmcs(201, cap)),
    }
}

struct Fixture<F: FriField> {
    originals: Vec<HiddenCommitment>,
    inputs: Vec<FriVector>,
    families: Vec<DeviceRandom>,
    transcript: Transcript,
    verifier: Challenger,
    prover: Challenger,
    claims: Vec<Claims<F>>,
    cpu_data: Vec<CpuData>,
    cpu_reductions: Vec<Vec<F>>,
    points: Vec<F>,
}

fn fixture<F: FriField>(
    runtime: &Runtime,
    fri: &Fri,
    cap: usize,
    batches: &[Vec<(u32, usize)>],
) -> Fixture<F> {
    let hiding = Hiding::new(runtime).unwrap();
    let commitments = Commitments::new(runtime).unwrap();
    let openings = Openings::new(runtime).unwrap();
    let transforms = Transforms::new(runtime).unwrap();
    let randoms = Randoms::new(runtime).unwrap();
    let transcripts = Transcripts::new(runtime).unwrap();
    let mut transcript = transcripts.start().unwrap();
    let mut cpu = Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8());
    let mut originals = Vec::new();
    let mut cpu_data = Vec::new();
    let mut caps = Vec::new();
    let mut families = Vec::new();
    for (batch, shapes) in batches.iter().enumerate() {
        let hiding_seed = 31 + batch as u8;
        let salt_seed = 71 + batch as u8;
        let private = randoms.import(rng(hiding_seed)).unwrap();
        let salts = randoms.import(rng(salt_seed)).unwrap();
        let mut prepared = Vec::new();
        let mut cpu_inputs = Vec::new();
        for &(log, width) in shapes {
            let spec = MatrixSpec::new(log, width, Extension::Base, RowOrder::Natural, 1).unwrap();
            let raw: Vec<_> = (0..spec.words())
                .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15))
                .collect();
            let trace = runtime.upload_matrix(spec, &raw).unwrap();
            prepared.push(
                hiding
                    .prepare_trace(&trace, &private, log + 1 + config::LOG_BLOWUP as u32, 2)
                    .unwrap(),
            );
            cpu_inputs.push((
                Domain::new(Val::ONE, (log + 1) as usize).unwrap(),
                RowMajorMatrix::new(raw.into_iter().map(Val::from_u64).collect(), width),
            ));
        }
        let references: Vec<_> = prepared.iter().map(HidingInput::Trace).collect();
        let data = hiding
            .commit_batch(&commitments, &references, &salts, cap)
            .unwrap();
        let raw_cap = data.cap(1 << 20).unwrap();
        let input_mmcs = mmcs(salt_seed, cap);
        let pcs = MyPcs::new(
            Dft::default(),
            input_mmcs.clone(),
            config::production_fri(config::ChallengeMmcs::new(input_mmcs)),
            config::NUM_RANDOM_CODEWORDS,
            rng(hiding_seed),
        );
        let (cpu_cap, cpu_prover) =
            <MyPcs as Pcs<config::Challenge, Challenger>>::commit(&pcs, cpu_inputs);
        assert_eq!(MerkleCap::new(digests(&raw_cap).unwrap()), cpu_cap);
        for chunk in raw_cap.chunks(crate::transcript_limits::BATCH_WORDS) {
            transcript.observe(chunk).unwrap();
        }
        cpu.observe(cpu_cap.clone());
        caps.push(cpu_cap);
        cpu_data.push(cpu_prover);
        originals.push(data);
        families.extend([private, salts]);
    }
    let points = transcript.sample_resident(2 * F::DIMENSION).unwrap();
    let cpu_points: Vec<F> = (0..2).map(|_| cpu.sample_algebra_element()).collect();
    let mut claims = Vec::new();
    for (batch, data) in originals.iter().enumerate() {
        let mut matrices = Vec::new();
        let cpu_mmcs = mmcs(0, cap);
        let cpu_matrices = cpu_mmcs.get_matrices(&cpu_data[batch]);
        for (matrix, spec) in data.specs().enumerate() {
            let raw = data
                .with_opening(
                    &openings,
                    matrix,
                    F::EXTENSION,
                    FieldSpan {
                        buffer: &points,
                        first: 0,
                    },
                    2,
                    |o| o.values(1 << 20),
                )
                .unwrap();
            let values = fields::<F>(&raw).unwrap();
            // Independent coefficients from the CPU hidden commitment. No
            // native prefix or original full codeword is downloaded here.
            let prefix_log = spec.log_rows as usize - config::LOG_BLOWUP;
            let width = spec.columns;
            let mut prefix = Vec::new();
            for row in 0usize..1 << prefix_log {
                let physical = row.reverse_bits() >> (usize::BITS as usize - prefix_log);
                prefix.extend_from_slice(
                    &cpu_matrices[matrix].values[physical * width..(physical + 1) * width],
                );
            }
            let coefficients = Dft::default()
                .coset_idft_batch(RowMajorMatrix::new(prefix, width), Val::from_u64(7));
            for (point, &z) in cpu_points.iter().enumerate() {
                for col in 0..width {
                    let expected = (0..1 << prefix_log).rev().fold(F::ZERO, |v, row| {
                        v * z + coefficients.values[row * width + col]
                    });
                    assert_eq!(values[point * width + col], expected);
                }
            }
            for chunk in raw.chunks(crate::transcript_limits::BATCH_WORDS) {
                transcript.observe(chunk).unwrap();
            }
            cpu.observe_algebra_slice(&values);
            matrices.push((
                Domain::new(Val::ONE, prefix_log).unwrap(),
                cpu_points
                    .iter()
                    .enumerate()
                    .map(|(p, &z)| (z, values[p * width..(p + 1) * width].to_vec()))
                    .collect(),
            ));
        }
        claims.push((caps[batch].clone(), matrices));
    }
    let verifier = cpu.clone();
    let _: F = cpu.sample_algebra_element();
    let alpha = transcript.sample_resident(F::DIMENSION).unwrap();
    let mut accumulators = BTreeMap::new();
    for data in &originals {
        for (matrix, spec) in data.specs().enumerate() {
            let accumulator = accumulators.remove(&spec.log_rows).unwrap_or_else(|| {
                openings
                    .accumulator(
                        spec.log_rows,
                        7,
                        F::EXTENSION,
                        FieldSpan {
                            buffer: &alpha,
                            first: 0,
                        },
                        0,
                    )
                    .unwrap()
            });
            let accumulator = data
                .with_opening(
                    &openings,
                    matrix,
                    F::EXTENSION,
                    FieldSpan {
                        buffer: &points,
                        first: 0,
                    },
                    2,
                    |o| accumulator.append(&transforms, o),
                )
                .unwrap();
            accumulators.insert(spec.log_rows, accumulator);
        }
    }
    let mut inputs = Vec::new();
    let mut cpu_reductions = Vec::new();
    for (_, accumulator) in accumulators.into_iter().rev() {
        let matrix = accumulator.finish().unwrap();
        cpu_reductions.push(fields(&matrix.read(4 << 20).unwrap()).unwrap());
        inputs.push(fri.rescale(&matrix).unwrap());
    }
    Fixture {
        originals,
        inputs,
        families,
        transcript,
        verifier,
        prover: cpu,
        claims,
        cpu_data,
        cpu_reductions,
        points: cpu_points,
    }
}

fn compare<F: FriField>(
    params: CpuFri<F>,
    cap: usize,
    batches: &[Vec<(u32, usize)>],
    exact_wire: bool,
) {
    let runtime = super::super::tests::runtime(64 << 20, 16 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let salts = randoms.import(rng(201)).unwrap();
    let mut f = fixture::<F>(&runtime, &fri, cap, batches);
    let global_log = f.inputs[0].log_rows();
    let originals: Vec<_> = f.originals.iter().collect();
    let native_params = FriParameters::from_upstream(&params, cap);
    let before = runtime.snapshot();
    let proof = fri
        .prove::<F>(
            &commitments,
            native_params,
            f.inputs,
            &originals,
            &salts,
            &mut f.transcript,
            64 << 20,
        )
        .unwrap();
    let downloaded = runtime.snapshot().downloaded_bytes - before.downloaded_bytes;
    assert!(
        downloaded < 1 << 20,
        "unexpected polynomial readback: {downloaded}"
    );
    let input_mmcs = mmcs(0, cap);
    let folding: TwoAdicFriFoldingForMmcs<Val, ValMmcs> =
        TwoAdicFriFolding(core::marker::PhantomData);
    let mut verifier = f.verifier.clone();
    p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut verifier,
        &f.claims,
        &input_mmcs,
    )
    .unwrap();
    let cpu_after: Vec<_> = (0..4)
        .map(|_| {
            let v: Val = verifier.sample();
            v.as_canonical_u64()
        })
        .collect();
    assert_eq!(f.transcript.sample_fields(4).unwrap(), cpu_after);
    if exact_wire {
        let data: Vec<_> = f
            .cpu_data
            .iter()
            .zip(&f.originals)
            .map(|(d, o)| (d, vec![f.points.clone(); o.specs().len()]))
            .collect();
        let expected = p3_fri::prover::prove_fri(
            &folding,
            &params,
            f.cpu_reductions,
            &mut f.prover,
            global_log as usize,
            &data,
            &input_mmcs,
        );
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
    }
    let verify = |bad: &NativeFriProof<F>| {
        p3_fri::verifier::verify_fri(
            &folding,
            &params,
            bad,
            &mut f.verifier.clone(),
            &f.claims,
            &input_mmcs,
        )
    };
    let mut bad = proof.clone();
    bad.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.query_proofs[0].input_proof[0].opening_proof.0[0][0] += Val::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.query_proofs[0].commit_phase_openings[0].sibling_values[0] += F::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.query_proofs[0].commit_phase_openings[0].log_arity = 0;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.final_poly[0] += F::ONE;
    assert!(verify(&bad).is_err());
    let mut bad_claims = f.claims.clone();
    bad_claims[0].1[0].1[0].1[0] += F::ONE;
    assert!(p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut f.verifier.clone(),
        &bad_claims,
        &input_mmcs
    )
    .is_err());
    for family in f.families {
        family.check_live().unwrap();
    }
    salts.check_live().unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_quadratic_production_proofs_pass_independent_cpu_verification() {
    compare::<config::Challenge>(
        parameters(6),
        6,
        &[vec![(9, 2), (3, 1)], vec![(5, 3), (2, 2), (3, 2)]],
        false,
    );
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_cubic_production_proofs_pass_independent_cpu_verification() {
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(
        crate::block_v2::profile::fri(ExtensionMmcs::new(mmcs(201, 6))),
        6,
        &[vec![(9, 2), (3, 1)], vec![(5, 3), (2, 2), (3, 2)]],
        false,
    );
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_protocol_wire_format_and_final_polynomials_match_upstream() {
    for arity in 1..=4 {
        let mut params = parameters::<config::Challenge>(0);
        params.max_log_arity = arity;
        params.query_proof_of_work_bits = 0;
        params.log_final_poly_len = 3;
        compare(params, 0, &[vec![(6, 2), (4, 1)]], true);
    }
    let mut params = parameters::<p3_field::extension::CubicTrinomialExtensionField<Val>>(6);
    params.query_proof_of_work_bits = 0;
    params.log_final_poly_len = 2;
    compare(params, 6, &[vec![(4, 3)], vec![(2, 1)]], true);
    let mut params = parameters::<config::Challenge>(6);
    params.commit_proof_of_work_bits = 4;
    compare(params, 6, &[vec![(3, 2)]], false);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_protocol_admission_and_failure_retire_all_participants() {
    let runtime = super::super::tests::runtime(16 << 20, 8 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let params = FriParameters::from_upstream(&parameters::<config::Challenge>(6), 6);
    let mut f = fixture::<config::Challenge>(&runtime, &fri, 6, &[vec![(2, 1)]]);
    let salts = randoms.import(rng(201)).unwrap();
    let originals: Vec<_> = f.originals.iter().collect();
    let transcript_before = f.transcript.snapshot().unwrap();
    let before = runtime.snapshot();
    assert!(fri
        .prove::<config::Challenge>(
            &commitments,
            params,
            f.inputs,
            &originals,
            &salts,
            &mut f.transcript,
            0
        )
        .is_err());
    assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
    assert_eq!(f.transcript.sample_fields(4).unwrap(), {
        let mut t = transcript_before;
        t.sample_fields(4).unwrap()
    });
    for family in &f.families {
        family.check_live().unwrap();
    }
    salts.check_live().unwrap();
    for fault in [
        Fault::AfterFirstCap,
        Fault::PanicAfterFirstCap,
        Fault::BeforeQueries,
    ] {
        let mut f = fixture::<config::Challenge>(&runtime, &fri, 6, &[vec![(2, 1)]]);
        let salts = randoms.import(rng(201)).unwrap();
        let originals: Vec<_> = f.originals.iter().collect();
        let alias = f.transcript.snapshot().unwrap();
        let baseline = runtime.snapshot();
        let input_bytes: usize = f.inputs.iter().map(|v| v.matrix.spec.bytes()).sum();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fri.prove_impl::<config::Challenge>(
                &commitments,
                params,
                f.inputs,
                &originals,
                &salts,
                &mut f.transcript,
                64 << 20,
                fault,
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(
            runtime.snapshot().live_bytes,
            baseline.live_bytes - input_bytes
        );
        assert!(salts.check_live().is_err());
        assert!(f.transcript.check_live().is_err());
        assert!(alias.check_live().is_err());
        for family in f.families {
            assert!(family.check_live().is_err());
        }
        assert!(f.originals[0].cap(1 << 20).is_err());
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_protocol_rejects_invalid_parameters_and_unauthenticated_heights_before_work() {
    let runtime = super::super::tests::runtime(16 << 20, 8 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let mut f = fixture::<config::Challenge>(&runtime, &fri, 6, &[vec![(3, 1)], vec![(2, 1)]]);
    let originals: Vec<_> = f.originals.iter().collect();
    let salts = randoms.import(rng(201)).unwrap();
    let params = FriParameters::from_upstream(&parameters::<config::Challenge>(6), 6);
    let copies = || {
        f.inputs
            .iter()
            .map(|v| fri.rescale(&v.matrix).unwrap())
            .collect::<Vec<_>>()
    };
    let before = runtime.snapshot();
    for bad in [
        FriParameters {
            num_queries: 0,
            ..params
        },
        FriParameters {
            num_queries: 257,
            ..params
        },
        FriParameters {
            max_log_arity: 0,
            ..params
        },
        FriParameters {
            max_log_arity: 5,
            ..params
        },
        FriParameters {
            log_blowup: usize::MAX,
            ..params
        },
        FriParameters {
            log_final_poly_len: 17,
            ..params
        },
        FriParameters {
            cap_height: 26,
            ..params
        },
        FriParameters {
            query_proof_of_work_bits: 21,
            ..params
        },
        FriParameters {
            commit_proof_of_work_bits: 21,
            ..params
        },
    ] {
        assert!(fri
            .prove::<config::Challenge>(
                &commitments,
                bad,
                copies(),
                &originals,
                &salts,
                &mut f.transcript,
                64 << 20
            )
            .is_err());
    }
    assert!(fri
        .prove::<config::Challenge>(
            &commitments,
            params,
            copies(),
            &[],
            &salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert!(fri
        .prove::<config::Challenge>(
            &commitments,
            params,
            copies(),
            &originals[..1],
            &salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert!(fri
        .prove::<config::Challenge>(
            &commitments,
            params,
            copies().into_iter().take(1).collect(),
            &originals,
            &salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());

    assert!(fri
        .prove::<p3_field::extension::CubicTrinomialExtensionField<Val>>(
            &commitments,
            params,
            copies(),
            &originals,
            &salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    f.transcript.check_live().unwrap();
    salts.check_live().unwrap();
    for family in f.families {
        family.check_live().unwrap();
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_zero_input_without_fold_layers_preserves_duplicate_queries() {
    type F = config::Challenge;
    let runtime = super::super::tests::runtime(8 << 20, 4 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let hiding = Hiding::new(&runtime).unwrap();
    let openings = Openings::new(&runtime).unwrap();
    let transforms = Transforms::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    let mut transcript = transcripts.start().unwrap();
    let mut cpu = Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8());
    let original_salts = randoms.import(rng(71)).unwrap();
    let fri_salts = randoms.import(rng(201)).unwrap();
    let trace = runtime
        .upload_matrix(
            MatrixSpec::new(0, 2, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &[0, 0],
        )
        .unwrap();
    let prepared = hiding.prepare_preprocessing(&trace, 4, 2).unwrap();
    let data = hiding
        .commit_batch(
            &commitments,
            &[HidingInput::Trace(&prepared)],
            &original_salts,
            6,
        )
        .unwrap();
    let cap = data.cap(1 << 20).unwrap();
    transcript.observe(&cap).unwrap();
    let cap = MerkleCap::new(digests(&cap).unwrap());
    cpu.observe(cap.clone());
    let point = transcript.sample_resident(2).unwrap();
    let z: F = cpu.sample_algebra_element();
    let claimed = [F::ZERO, F::ZERO];
    transcript.observe(&[0, 0, 0, 0]).unwrap();
    cpu.observe_algebra_slice(&claimed);
    let mut verifier = cpu;
    let alpha = transcript.sample_resident(2).unwrap();
    let accumulator = openings
        .accumulator(
            4,
            7,
            Extension::Quadratic,
            FieldSpan {
                buffer: &alpha,
                first: 0,
            },
            0,
        )
        .unwrap();
    let reduced = data
        .with_opening(
            &openings,
            0,
            Extension::Quadratic,
            FieldSpan {
                buffer: &point,
                first: 0,
            },
            1,
            |o| accumulator.append(&transforms, o),
        )
        .unwrap()
        .finish()
        .unwrap();
    let params = parameters::<F>(6);
    let proof = fri
        .prove::<F>(
            &commitments,
            FriParameters::from_upstream(&params, 6),
            vec![fri.rescale(&reduced).unwrap()],
            &[&data],
            &fri_salts,
            &mut transcript,
            4 << 20,
        )
        .unwrap();
    assert!(proof.commit_phase_commits.is_empty());
    assert!(proof.commit_pow_witnesses.is_empty());
    assert_eq!(proof.final_poly, [F::ZERO]);
    assert!(proof
        .query_proofs
        .iter()
        .all(|p| p.commit_phase_openings.is_empty()));
    let distinct: std::collections::BTreeSet<_> = proof
        .query_proofs
        .iter()
        .map(|q| postcard::to_allocvec(&q.input_proof).unwrap())
        .collect();
    assert!(distinct.len() <= 16 && distinct.len() < proof.query_proofs.len());
    let claims = [(
        cap,
        vec![(
            Domain::new(Val::ONE, 0).unwrap(),
            vec![(z, claimed.to_vec())],
        )],
    )];
    let folding: TwoAdicFriFoldingForMmcs<Val, ValMmcs> =
        TwoAdicFriFolding(core::marker::PhantomData);
    p3_fri::verifier::verify_fri(
        &folding,
        &params,
        &proof,
        &mut verifier,
        &claims,
        &mmcs(0, 6),
    )
    .unwrap();
    let cpu_after: Vec<_> = (0..4)
        .map(|_| {
            let v: Val = verifier.sample();
            v.as_canonical_u64()
        })
        .collect();
    assert_eq!(transcript.sample_fields(4).unwrap(), cpu_after);
}
