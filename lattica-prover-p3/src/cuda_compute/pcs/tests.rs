use super::*;
use crate::{
    config::{self, Challenger, Dft, MyCompress, MyHash, ValMmcs},
    cuda_compute::{Buffer, Hiding, HidingInput, Limits, Matrix, Randoms, Transcripts},
};
use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{ExtensionMmcs, Mmcs, PolynomialSpace};
use p3_field::{coset::TwoAdicMultiplicativeCoset as Domain, PrimeField64, TwoAdicField};
use p3_fri::HidingFriPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type Cpu<F> = HidingFriPcs<Val, Dft, ValMmcs, ExtensionMmcs<Val, F, ValMmcs>, ChaCha20Rng>;
type CpuData = <ValMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 32 << 20,
            max_allocation_bytes: 8 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn rng(seed: u8) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    rng.set_word_pos((1 << 36) - 1);
    rng
}
fn mmcs() -> ValMmcs {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    ValMmcs::new(MyHash::new(p.clone()), MyCompress::new(p), 6, rng(71))
}
fn parameters<F: FriField>(
    zero_pow: bool,
) -> p3_fri::FriParameters<ExtensionMmcs<Val, F, ValMmcs>> {
    let mut p = if F::EXTENSION == Extension::Cubic {
        FriParameters::from_upstream(&crate::block_v2::profile::fri(()), 6)
    } else {
        FriParameters::from_upstream(
            &config::production_fri(config::ChallengeMmcs::new(mmcs())),
            6,
        )
    };
    if zero_pow {
        p.query_proof_of_work_bits = 0;
    }
    p3_fri::FriParameters {
        log_blowup: p.log_blowup,
        log_final_poly_len: p.log_final_poly_len,
        max_log_arity: p.max_log_arity,
        num_queries: p.num_queries,
        commit_proof_of_work_bits: p.commit_proof_of_work_bits,
        query_proof_of_work_bits: p.query_proof_of_work_bits,
        mmcs: ExtensionMmcs::new(mmcs()),
    }
}
fn upload(
    runtime: &Runtime,
    log: u32,
    width: usize,
    extension: Extension,
    shift: u64,
) -> (Matrix, RowMajorMatrix<Val>) {
    let spec = MatrixSpec::new(log, width, extension, RowOrder::Natural, shift).unwrap();
    let raw: Vec<_> = (0..spec.words())
        .map(|i| {
            if i % 7 == 0 {
                u64::MAX
            } else {
                (i * 173 + 11) as u64
            }
        })
        .collect();
    let matrix = RowMajorMatrix::new(
        raw.iter().copied().map(Val::from_u64).collect(),
        width * extension.degree(),
    );
    (runtime.upload_matrix(spec, &raw).unwrap(), matrix)
}

struct Fixture<F: FriField + TwoAdicField> {
    params: FriParameters,
    cpu: Cpu<F>,
    cpu_data: Vec<CpuData>,
    caps: Vec<<ValMmcs as Mmcs<Val>>::Commitment>,
    originals: Vec<HiddenCommitment>,
    families: Vec<DeviceRandom>,
    fri_salts: DeviceRandom,
    transcript: Transcript,
    challenger: Challenger,
    points: Buffer,
    point_layouts: Vec<Vec<(usize, usize)>>,
    cpu_points: Vec<Vec<Vec<F>>>,
}

fn fixture<F: FriField + TwoAdicField>(
    runtime: &Runtime,
    public_preprocessing: bool,
    zero_pow: bool,
) -> Fixture<F> {
    let hiding = Hiding::new(runtime).unwrap();
    let commitments = Commitments::new(runtime).unwrap();
    let randoms = Randoms::new(runtime).unwrap();
    let transcripts = Transcripts::new(runtime).unwrap();
    let mut transcript = transcripts.start().unwrap();
    let mut challenger = Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8());
    let private = randoms.import(rng(31)).unwrap();
    let input_salts = randoms.import(rng(71)).unwrap();
    // Upstream CPU MMCS Clone snapshots its RNG. Input and FRI streams start
    // identically and then advance independently; retain that construction.
    let fri_salts = randoms.import(rng(71)).unwrap();
    let cpu_params = parameters::<F>(zero_pow);
    let params = FriParameters::from_upstream(&cpu_params, 6);
    let cpu = Cpu::<F>::new(
        Dft::default(),
        mmcs(),
        cpu_params,
        config::NUM_RANDOM_CODEWORDS,
        rng(31),
    );
    let mut originals = Vec::new();
    let mut cpu_data = Vec::new();
    let mut caps = Vec::new();
    for batch in 0..4 {
        let (native, cap, expected) = if batch == 0 {
            let mut prepared = Vec::new();
            let mut domains = Vec::new();
            for log in [3, 5] {
                prepared.push(
                    hiding
                        .prepare_randomization(log, 1, F::EXTENSION, &private, log + 4, 2)
                        .unwrap(),
                );
                domains.push(Domain::new(Val::ONE, log as usize).unwrap());
            }
            let inputs: Vec<_> = prepared.iter().map(HidingInput::Randomization).collect();
            let native = hiding
                .commit_batch(&commitments, &inputs, &input_salts, 6)
                .unwrap();
            let (cap, data) =
                <Cpu<F> as Pcs<F, Challenger>>::get_opt_randomization_poly_commitment(
                    &cpu, domains,
                )
                .unwrap();
            (native, cap, data)
        } else if batch == 2 {
            let (quotient, cpu_quotient) = upload(runtime, 5, 1, F::EXTENSION, 13);
            let prepared = hiding
                .prepare_quotient(&quotient, 4, &private, 8, 2)
                .unwrap();
            let native = hiding
                .commit_batch(
                    &commitments,
                    &[HidingInput::Quotient(&prepared)],
                    &input_salts,
                    6,
                )
                .unwrap();
            let domain = Domain::new(Val::from_u64(13), 5).unwrap();
            let ldes = <Cpu<F> as Pcs<F, Challenger>>::get_quotient_ldes(
                &cpu,
                domain
                    .split_domains(4)
                    .into_iter()
                    .zip(domain.split_evals(4, cpu_quotient)),
                4,
            );
            let (cap, data) = <Cpu<F> as Pcs<F, Challenger>>::commit_ldes(&cpu, ldes);
            (native, cap, data)
        } else {
            let shapes = match batch {
                1 => vec![(3, 3, F::EXTENSION)],
                _ => vec![(2, 2, Extension::Base)],
            };
            let mut prepared = Vec::new();
            let mut cpu_inputs = Vec::new();
            for (log, width, extension) in shapes {
                let (trace, cpu_trace) = upload(runtime, log, width, extension, 1);
                prepared.push(if public_preprocessing && batch == PREPROCESSED_ROUND {
                    hiding.prepare_preprocessing(&trace, log + 5, 2).unwrap()
                } else {
                    hiding.prepare_trace(&trace, &private, log + 5, 2).unwrap()
                });
                cpu_inputs.push((Domain::new(Val::ONE, log as usize + 1).unwrap(), cpu_trace));
            }
            let refs: Vec<_> = prepared.iter().map(HidingInput::Trace).collect();
            let native = hiding
                .commit_batch(&commitments, &refs, &input_salts, 6)
                .unwrap();
            let (cap, data) = if public_preprocessing && batch == PREPROCESSED_ROUND {
                <Cpu<F> as Pcs<F, Challenger>>::commit_preprocessing(&cpu, cpu_inputs)
            } else {
                <Cpu<F> as Pcs<F, Challenger>>::commit(&cpu, cpu_inputs)
            };
            (native, cap, data)
        };
        let raw = native.cap(1 << 20).unwrap();
        let digests: Vec<[Val; 4]> = raw
            .chunks_exact(4)
            .map(|w| std::array::from_fn(|i| Val::from_u64(w[i])))
            .collect();
        assert_eq!(MerkleCap::new(digests), cap);
        transcript.observe(&raw).unwrap();
        challenger.observe(cap.clone());
        originals.push(native);
        cpu_data.push(expected);
        caps.push(cap);
    }
    let sampled = transcript.sample_resident(2 * F::DIMENSION).unwrap();
    let a: F = challenger.sample_algebra_element();
    let b: F = challenger.sample_algebra_element();
    let points = runtime.allocate(3 * F::DIMENSION + 4).unwrap();
    points.copy_from(2, &sampled, 0, 2 * F::DIMENSION).unwrap();
    points
        .copy_from(2 + 2 * F::DIMENSION, &sampled, 0, F::DIMENSION)
        .unwrap();
    let all = [a, b, a];
    let mut point_layouts = Vec::new();
    let mut cpu_points = Vec::new();
    for (batch, original) in originals.iter().enumerate() {
        let mut layout = Vec::new();
        let mut coordinates = Vec::new();
        for matrix in 0..original.specs().len() {
            let (first, count) = match (batch + matrix) % 3 {
                0 => (0, 3),
                1 => (1, 2),
                _ => (1, 1),
            };
            layout.push((2 + first * F::DIMENSION, count));
            coordinates.push(all[first..first + count].to_vec());
        }
        point_layouts.push(layout);
        cpu_points.push(coordinates);
    }
    Fixture {
        params,
        cpu,
        cpu_data,
        caps,
        originals,
        families: vec![private, input_salts],
        fri_salts,
        transcript,
        challenger,
        points,
        point_layouts,
        cpu_points,
    }
}

fn point_requests<'a>(
    buffer: &'a Buffer,
    layouts: &[Vec<(usize, usize)>],
) -> Vec<Vec<OpeningPoints<'a>>> {
    layouts
        .iter()
        .map(|ms| {
            ms.iter()
                .map(|&(first, count)| OpeningPoints {
                    values: FieldSpan { buffer, first },
                    count,
                })
                .collect()
        })
        .collect()
}
fn rounds<'a>(
    originals: &'a [HiddenCommitment],
    points: &'a [Vec<OpeningPoints<'a>>],
) -> Vec<OpeningRound<'a>> {
    originals
        .iter()
        .zip(points)
        .map(|(commitment, points)| OpeningRound { commitment, points })
        .collect()
}

fn compare<F: FriField + TwoAdicField>(public_preprocessing: bool, zero_pow: bool) {
    let runtime = runtime();
    let engine = PcsOpenings::new(&runtime).unwrap();
    let mut f = fixture::<F>(&runtime, public_preprocessing, zero_pow);
    let points = point_requests(&f.points, &f.point_layouts);
    let rounds = rounds(&f.originals, &points);
    let plan = engine
        .plan::<F>(f.params, &rounds, public_preprocessing, 64 << 20)
        .unwrap();
    let before = runtime.snapshot();
    assert!(engine
        .open::<F>(
            f.params,
            &rounds,
            public_preprocessing,
            &f.fri_salts,
            &mut f.transcript,
            plan.host_peak - 1
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    f.transcript.check_live().unwrap();
    let (values, proof) = engine
        .open::<F>(
            f.params,
            &rounds,
            public_preprocessing,
            &f.fri_salts,
            &mut f.transcript,
            plan.host_peak,
        )
        .unwrap();
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    let cpu_rounds = f
        .cpu_data
        .iter()
        .zip(&f.cpu_points)
        .map(|(d, p)| (d, p.clone()))
        .collect();
    let (expected_values, expected_proof) = <Cpu<F> as Pcs<F, Challenger>>::open_with_preprocessing(
        &f.cpu,
        cpu_rounds,
        &mut f.challenger.clone(),
        public_preprocessing,
    );
    assert_eq!(values, expected_values);
    assert_eq!(proof.0, expected_proof.0);
    if zero_pow {
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected_proof).unwrap()
        );
    }
    let mut claims = Vec::new();
    for (batch, original) in f.originals.iter().enumerate() {
        let mut mats = Vec::new();
        for (matrix, spec) in original.specs().enumerate() {
            let domain =
                Domain::new(Val::ONE, spec.log_rows as usize - f.params.log_blowup).unwrap();
            let opening = f.cpu_points[batch][matrix]
                .iter()
                .copied()
                .zip(values[batch][matrix].iter().cloned())
                .collect();
            mats.push((domain, opening));
        }
        claims.push((f.caps[batch].clone(), mats));
    }
    let mut verifier = f.challenger.clone();
    <Cpu<F> as Pcs<F, Challenger>>::verify(&f.cpu, claims.clone(), &proof, &mut verifier).unwrap();
    let expected_after: Vec<_> = (0..4)
        .map(|_| {
            let v: Val = verifier.sample();
            v.as_canonical_u64()
        })
        .collect();
    assert_eq!(f.transcript.sample_fields(4).unwrap(), expected_after);
    let mut bad = proof.clone();
    bad.0[0][0][0][0] += F::ONE;
    assert!(<Cpu<F> as Pcs<F, Challenger>>::verify(
        &f.cpu,
        claims.clone(),
        &bad,
        &mut f.challenger.clone()
    )
    .is_err());
    let mut bad = proof.clone();
    bad.0[0][0][0].pop();
    assert!(<Cpu<F> as Pcs<F, Challenger>>::verify(
        &f.cpu,
        claims.clone(),
        &bad,
        &mut f.challenger.clone()
    )
    .is_err());
    let mut bad = proof.clone();
    bad.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
    assert!(<Cpu<F> as Pcs<F, Challenger>>::verify(
        &f.cpu,
        claims.clone(),
        &bad,
        &mut f.challenger.clone()
    )
    .is_err());
    let mut bad_claims = claims;
    bad_claims[0].1[0].1[0].1[0] += F::ONE;
    assert!(<Cpu<F> as Pcs<F, Challenger>>::verify(
        &f.cpu,
        bad_claims,
        &proof,
        &mut f.challenger.clone()
    )
    .is_err());
    for family in f.families {
        family.check_live().unwrap();
    }
    f.fri_salts.check_live().unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_quadratic_hiding_pcs_openings_pass_unchanged_cpu_verifier() {
    compare::<config::Challenge>(true, false);
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_cubic_hiding_pcs_openings_pass_unchanged_cpu_verifier() {
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(true, false);
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hiding_pcs_masking_and_wire_encoding_match_upstream() {
    for public in [false, true] {
        compare::<config::Challenge>(public, true);
        compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(public, true);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_pcs_failed_attempts_retire_every_input_salt_and_transcript_family() {
    let runtime = runtime();
    let engine = PcsOpenings::new(&runtime).unwrap();
    for fault in [
        Fault::AfterObservation,
        Fault::PanicAfterObservation,
        Fault::AfterReduction,
    ] {
        let mut f = fixture::<config::Challenge>(&runtime, true, true);
        let points = point_requests(&f.points, &f.point_layouts);
        let rounds = rounds(&f.originals, &points);
        let alias = f.transcript.snapshot().unwrap();
        let before = runtime.snapshot();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.open_impl::<config::Challenge>(
                f.params,
                &rounds,
                true,
                &f.fri_salts,
                &mut f.transcript,
                64 << 20,
                fault,
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert!(runtime.snapshot().completed_commands > before.completed_commands);
        assert!(alias.check_live().is_err());
        assert!(f.transcript.check_live().is_err());
        assert!(f.fri_salts.check_live().is_err());
        for family in f.families {
            assert!(family.check_live().is_err());
        }
        for data in f.originals {
            assert!(data.cap(1 << 20).is_err());
        }
    }
    let mut f = fixture::<config::Challenge>(&runtime, true, true);
    // A validly shaped point on the evaluation coset must fail on CUDA.
    f.points.write(2, &[7, 0]).unwrap();
    let points = point_requests(&f.points, &f.point_layouts);
    let rounds = rounds(&f.originals, &points);
    let before = runtime.snapshot();
    assert!(engine
        .open::<config::Challenge>(
            f.params,
            &rounds,
            true,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert!(f.transcript.check_live().is_err());
    assert!(f.fri_salts.check_live().is_err());
    for family in f.families {
        assert!(family.check_live().is_err());
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_pcs_admission_checks_hiding_shapes_points_and_retained_device_peaks() {
    let runtime = runtime();
    let engine = PcsOpenings::new(&runtime).unwrap();
    let mut f = fixture::<config::Challenge>(&runtime, true, true);
    let points = point_requests(&f.points, &f.point_layouts);
    let rounds = rounds(&f.originals, &points);
    let before = runtime.snapshot();
    assert!(engine
        .open::<config::Challenge>(
            f.params,
            &rounds,
            false,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert!(engine
        .open::<config::Challenge>(
            f.params,
            &[],
            true,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert!(engine
        .open::<config::Challenge>(
            FriParameters {
                log_blowup: usize::MAX,
                ..f.params
            },
            &rounds,
            true,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    for count in [0, 33] {
        let mut invalid = point_requests(&f.points, &f.point_layouts);
        invalid[0][0].count = count;
        let rounds = self::rounds(&f.originals, &invalid);
        assert!(engine
            .open::<config::Challenge>(
                f.params,
                &rounds,
                true,
                &f.fri_salts,
                &mut f.transcript,
                64 << 20
            )
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let mut invalid = point_requests(&f.points, &f.point_layouts);
    invalid[0][0].values.first = usize::MAX;
    assert!(engine
        .open::<config::Challenge>(
            f.params,
            &self::rounds(&f.originals, &invalid),
            true,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut pressure = Vec::new();
    while runtime.snapshot().live_bytes + 1024 < 32 << 20 {
        let bytes = ((32 << 20) - runtime.snapshot().live_bytes - 1024).min(8 << 20);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(engine
        .open::<config::Challenge>(
            f.params,
            &rounds,
            true,
            &f.fri_salts,
            &mut f.transcript,
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    f.transcript.check_live().unwrap();
    f.fri_salts.check_live().unwrap();
    for family in f.families {
        family.check_live().unwrap();
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_retained_openings_preserve_values_and_reject_consumers_after_retirement() {
    let runtime = runtime();
    let engine = PcsOpenings::new(&runtime).unwrap();
    for panic in [false, true] {
        let f = fixture::<config::Challenge>(&runtime, true, true);
        let points = point_requests(&f.points, &f.point_layouts);
        let p = points[0][0];
        let opening = f.originals[0]
            .retain_opening(&engine.openings, 0, Extension::Quadratic, p.values, p.count)
            .unwrap();
        let alias = f.originals[0]
            .retain_opening(&engine.openings, 0, Extension::Quadratic, p.values, p.count)
            .unwrap();
        let values = opening.with(|o| o.values(1 << 20)).unwrap();
        f.points.write(0, &vec![0; f.points.len()]).unwrap();
        assert_eq!(opening.with(|o| o.values(1 << 20)).unwrap(), values);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            opening.with::<()>(|_| {
                if panic {
                    panic!("injected retained opening consumer unwind");
                }
                Err("injected retained opening consumer failure".into())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let before = runtime.snapshot();
        assert!(alias.with(|o| o.values(1 << 20)).is_err());
        assert_eq!(runtime.snapshot(), before);
        for family in &f.families {
            assert!(family.check_live().is_err());
        }
    }
}
