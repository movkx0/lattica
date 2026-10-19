use super::*;
use crate::cuda_compute::{Limits, Randoms};
use p3_air::{AirBuilder, BaseAir, WindowAccess};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use rand::SeedableRng;

#[derive(Clone, Copy)]
struct ArithmeticAir {
    periodic: bool,
    next: bool,
}

impl BaseAir<Val> for ArithmeticAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        usize::from(self.periodic)
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        if self.periodic {
            vec![(1..=4).map(Val::from_u64).collect()]
        } else {
            Vec::new()
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.next {
            vec![0]
        } else {
            Vec::new()
        }
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ArithmeticAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        b.assert_eq(row[0] * row[1], row[2]);
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(row[2], public);
        if self.periodic {
            let periodic = b.periodic_values()[0];
            b.assert_eq(row[1], periodic);
        }
        if self.next {
            b.when_transition()
                .assert_eq(main.next_slice()[0], row[0] + Val::ONE);
        }
    }
}
impl Source for ArithmeticAir {
    fn count(&self) -> usize {
        self.num_periodic_columns()
    }
    fn len(&self, index: usize) -> Option<usize> {
        (self.periodic && index == 0).then_some(4)
    }
    fn fill(
        &self,
        index: usize,
        output: &mut [Val],
    ) -> std::result::Result<(), crate::block_v2::machine::verifier::CompileError> {
        if self.len(index) != Some(output.len()) {
            return Err(crate::block_v2::machine::verifier::CompileError::Shape(
                "test periodic source",
            ));
        }
        for (i, v) in output.iter_mut().enumerate() {
            *v = Val::from_usize(i + 1);
        }
        Ok(())
    }
}

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 256 << 20,
            max_allocation_bytes: 64 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn rng(seed: u8) -> ChaCha20Rng {
    let mut r = ChaCha20Rng::from_seed([seed; 32]);
    r.set_word_pos((1 << 36) - 1);
    r
}
fn mmcs() -> ValMmcs {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    ValMmcs::new(
        config::MyHash::new(p.clone()),
        config::MyCompress::new(p),
        6,
        rng(71),
    )
}
fn cpu<F: StarkField>(zero_pow: bool) -> NativeStarkConfig<F> {
    let p = parameters::<F>();
    let fri = p3_fri::FriParameters {
        log_blowup: p.log_blowup,
        log_final_poly_len: p.log_final_poly_len,
        max_log_arity: p.max_log_arity,
        num_queries: p.num_queries,
        commit_proof_of_work_bits: p.commit_proof_of_work_bits,
        query_proof_of_work_bits: if zero_pow {
            0
        } else {
            p.query_proof_of_work_bits
        },
        mmcs: ExtensionMmcs::new(mmcs()),
    };
    NativeStarkConfig::new(
        EncodingPcs::new(Dft::default(), mmcs(), fri, 4, rng(31)),
        Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8()),
    )
}
fn trace(air: ArithmeticAir, log: u32) -> RowMajorMatrix<Val> {
    let values = (0..1usize << log)
        .flat_map(|row| {
            let left = Val::from_usize(row + 2);
            let right = Val::from_usize(if air.periodic { row % 4 + 1 } else { row + 5 });
            [left, right, left * right]
        })
        .collect();
    RowMajorMatrix::new(values, 3)
}

fn compare<F: StarkField>(air: ArithmeticAir, zero_pow: bool, mode: Specialization) {
    let runtime = runtime();
    let engine = Starks::new(&runtime).unwrap();
    let prepared = engine.prepare::<F, _>(&air, 5, 256 << 20, mode).unwrap();
    let cpu_trace = trace(air, 5);
    let public = [cpu_trace.values[2]];
    let raw: Vec<_> = cpu_trace
        .values
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect();
    let matrix = runtime
        .upload_matrix(
            MatrixSpec::new(5, 3, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &raw,
        )
        .unwrap();
    let public_device = runtime.allocate(1).unwrap();
    public_device
        .write(0, &[public[0].as_canonical_u64()])
        .unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let masks = randoms.import(rng(31)).unwrap();
    let salts = randoms.import(rng(71)).unwrap();
    let fri = randoms.import(rng(71)).unwrap();
    let randomness = StarkRandomness {
        masks: &masks,
        commitments: &salts,
        fri: &fri,
    };
    let before = runtime.snapshot();
    let proof = if zero_pow {
        let mut p = parameters::<F>();
        p.query_proof_of_work_bits = 0;
        engine.prove_impl(
            &prepared,
            &matrix,
            Some(&public_device),
            randomness,
            64 << 20,
            p,
            prove::Fault::None,
        )
    } else {
        engine.prove(
            &prepared,
            &matrix,
            Some(&public_device),
            randomness,
            64 << 20,
        )
    }
    .unwrap();
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    let cpu = cpu::<F>(zero_pow);
    let before_verify = runtime.snapshot();
    p3_uni_stark::verify(&cpu, &air, &proof, &public).unwrap();
    assert!(p3_uni_stark::verify(&cpu, &air, &proof, &[public[0] + Val::ONE]).is_err());
    assert_eq!(
        runtime.snapshot(),
        before_verify,
        "independent verifier must not execute CUDA"
    );
    let encoded = postcard::to_allocvec(&proof).unwrap();
    let mut altered: NativeStarkProof<F> = postcard::from_bytes(&encoded).unwrap();
    altered.opened_values.trace_local[0] += F::ONE;
    assert!(p3_uni_stark::verify(&cpu, &air, &altered, &public).is_err());
    let mut altered: NativeStarkProof<F> = postcard::from_bytes(&encoded).unwrap();
    altered.degree_bits += 1;
    assert!(p3_uni_stark::verify(&cpu, &air, &altered, &public).is_err());
    if zero_pow {
        let expected = p3_uni_stark::prove(&cpu, &air, cpu_trace, &public);
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
    }
    for family in [masks, salts, fri] {
        family.check_live().unwrap();
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_quadratic_stark_proof_passes_unchanged_cpu_verifier() {
    compare::<config::Challenge>(
        ArithmeticAir {
            periodic: true,
            next: true,
        },
        false,
        Specialization::Prefer,
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_cubic_stark_proof_passes_unchanged_cpu_verifier() {
    compare::<crate::block_v2::profile::Challenge>(
        ArithmeticAir {
            periodic: true,
            next: true,
        },
        false,
        Specialization::Prefer,
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_stark_wire_encoding_matches_upstream_with_periodic_and_next_row_modes() {
    for (periodic, next) in [(false, false), (false, true), (true, true)] {
        let air = ArithmeticAir { periodic, next };
        compare::<config::Challenge>(air, true, Specialization::Generic);
        compare::<crate::block_v2::profile::Challenge>(air, true, Specialization::Prefer);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_stark_errors_and_unwinds_retire_all_randomness_and_release_intermediates() {
    let runtime = runtime();
    let engine = Starks::new(&runtime).unwrap();
    let air = ArithmeticAir {
        periodic: true,
        next: true,
    };
    let prepared = engine
        .prepare::<config::Challenge, _>(&air, 5, 256 << 20, Specialization::Prefer)
        .unwrap();
    let cpu_trace = trace(air, 5);
    let raw: Vec<_> = cpu_trace
        .values
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect();
    let matrix = runtime
        .upload_matrix(
            MatrixSpec::new(5, 3, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &raw,
        )
        .unwrap();
    let public = runtime.allocate(1).unwrap();
    public.write(0, &[2]).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for fault in [
        prove::Fault::None, // Real late PCS host-admission failure.
        prove::Fault::AfterTrace,
        prove::Fault::AfterQuotient,
        prove::Fault::PanicAfterQuotient,
        prove::Fault::AfterPcs,
    ] {
        let masks = randoms.import(rng(31)).unwrap();
        let salts = randoms.import(rng(71)).unwrap();
        let fri = randoms.import(rng(71)).unwrap();
        let streams = StarkRandomness {
            masks: &masks,
            commitments: &salts,
            fri: &fri,
        };
        let before = runtime.snapshot();
        let mut params = parameters::<config::Challenge>();
        params.query_proof_of_work_bits = 0;
        let allowance = if matches!(fault, prove::Fault::None) {
            HOST_METADATA + 6 * (1 << config::CAP_HEIGHT) * 4 * 8 + 1
        } else {
            64 << 20
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.prove_impl(
                &prepared,
                &matrix,
                Some(&public),
                streams,
                allowance,
                params,
                fault,
            )
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        let after = runtime.snapshot();
        assert_eq!(after.live_bytes, before.live_bytes);
        assert_eq!(after.allocations, before.allocations);
        assert_eq!(after.pending_commands, 0);
        assert!(after.completed_commands > before.completed_commands);
        for family in [&masks, &salts, &fri] {
            assert!(family.check_live().is_err());
        }
        assert!(engine
            .prove(&prepared, &matrix, Some(&public), streams, 64 << 20)
            .is_err());
        assert_eq!(runtime.snapshot(), after);
    }
    // The reusable public program remains valid after attempt-local failures.
    let masks = randoms.import(rng(31)).unwrap();
    let salts = randoms.import(rng(71)).unwrap();
    let fri = randoms.import(rng(71)).unwrap();
    let proof = engine
        .prove(
            &prepared,
            &matrix,
            Some(&public),
            StarkRandomness {
                masks: &masks,
                commitments: &salts,
                fri: &fri,
            },
            64 << 20,
        )
        .unwrap();
    p3_uni_stark::verify(
        &cpu::<config::Challenge>(false),
        &air,
        &proof,
        &[Val::from_u64(2)],
    )
    .unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_stark_admission_preserves_inputs_and_invalid_witness_cannot_verify() {
    let runtime = runtime();
    let engine = Starks::new(&runtime).unwrap();
    let air = ArithmeticAir {
        periodic: false,
        next: false,
    };
    let before = runtime.snapshot();
    assert!(engine
        .prepare::<config::Challenge, _>(&air, 5, 192 << 20, Specialization::Generic)
        .is_ok());
    for (log, allowance) in [(0, 256 << 20), (21, 256 << 20), (5, (192 << 20) - 1)] {
        assert!(engine
            .prepare::<config::Challenge, _>(&air, log, allowance, Specialization::Generic)
            .is_err());
    }
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    let prepared = engine
        .prepare::<config::Challenge, _>(&air, 5, 256 << 20, Specialization::Generic)
        .unwrap();
    let cpu_trace = trace(air, 5);
    let raw: Vec<_> = cpu_trace
        .values
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect();
    let matrix = runtime
        .upload_matrix(
            MatrixSpec::new(5, 3, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &raw,
        )
        .unwrap();
    let public = runtime.allocate(1).unwrap();
    public.write(0, &[10]).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let masks = randoms.import(rng(31)).unwrap();
    let salts = randoms.import(rng(71)).unwrap();
    let fri = randoms.import(rng(71)).unwrap();
    let streams = StarkRandomness {
        masks: &masks,
        commitments: &salts,
        fri: &fri,
    };
    let before = runtime.snapshot();
    assert!(engine
        .prove(&prepared, &matrix, None, streams, 64 << 20)
        .is_err());
    assert!(engine
        .prove(&prepared, &matrix, Some(&public), streams, 1)
        .is_err());
    let wrong = Matrix {
        spec: MatrixSpec::new(5, 3, Extension::Base, RowOrder::Natural, 7).unwrap(),
        buffer: matrix.buffer.clone(),
    };
    assert!(engine
        .prove(&prepared, &wrong, Some(&public), streams, 64 << 20)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    for family in [&masks, &salts, &fri] {
        family.check_live().unwrap();
    }
    // Corrupt a private witness cell while keeping shape and public inputs.
    matrix.buffer.write(2, &[11]).unwrap();
    let before = runtime.snapshot();
    let proof = engine.prove(&prepared, &matrix, Some(&public), streams, 64 << 20);
    if let Ok(proof) = proof {
        assert!(p3_uni_stark::verify(
            &cpu::<config::Challenge>(false),
            &air,
            &proof,
            &[Val::from_u64(10)]
        )
        .is_err());
    } else {
        for family in [&masks, &salts, &fri] {
            assert!(family.check_live().is_err());
        }
    }
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_periodic_preflight_uses_borrowed_sources_and_rejects_changed_geometry() {
    use std::cell::Cell;
    struct Provider {
        calls: Cell<usize>,
        drift: bool,
        len: usize,
    }
    impl Source for Provider {
        fn count(&self) -> usize {
            1
        }
        fn len(&self, _: usize) -> Option<usize> {
            let old = self.calls.get();
            self.calls.set(old + 1);
            Some(if self.drift && old > 0 {
                self.len * 2
            } else {
                self.len
            })
        }
        fn fill(
            &self,
            _: usize,
            out: &mut [Val],
        ) -> std::result::Result<(), crate::block_v2::machine::verifier::CompileError> {
            assert!(!self.drift);
            out.fill(Val::ONE);
            Ok(())
        }
    }
    let runtime = runtime();
    let engine = Starks::new(&runtime).unwrap();
    let before = runtime.snapshot();
    for (len, drift, bytes) in [(3, false, 1 << 20), (4, false, 1), (4, true, 1 << 20)] {
        let provider = Provider {
            calls: Cell::new(0),
            drift,
            len,
        };
        assert!(engine.prepare_periodic(&provider, 5, bytes).is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let provider = Provider {
        calls: Cell::new(0),
        drift: false,
        len: 4,
    };
    let prefix = engine
        .prepare_periodic(&provider, 5, 1 << 20)
        .unwrap()
        .unwrap();
    assert_eq!(prefix.read(256).unwrap(), vec![1; 32]);
}

fn wallet<A>(air: A, cpu_trace: RowMajorMatrix<Val>, publics: Vec<Val>)
where
    A: Air<symbolic::Builder>
        + Source
        + Air<p3_air::symbolic::SymbolicAirBuilder<Val>>
        + for<'a> Air<
            p3_uni_stark::VerifierConstraintFolder<'a, NativeStarkConfig<config::Challenge>>,
        >,
{
    let runtime = runtime();
    let engine = Starks::new(&runtime).unwrap();
    let log_rows = cpu_trace.height().ilog2();
    let prepared = engine
        .prepare::<config::Challenge, _>(&air, log_rows, 256 << 20, Specialization::Prefer)
        .unwrap();
    let words: Vec<_> = cpu_trace
        .values
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect();
    let trace = runtime
        .upload_matrix(
            MatrixSpec::new(
                log_rows,
                cpu_trace.width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )
            .unwrap(),
            &words,
        )
        .unwrap();
    let public = runtime.allocate(publics.len()).unwrap();
    public
        .write(
            0,
            &publics
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let masks = randoms.import(rng(31)).unwrap();
    let salts = randoms.import(rng(71)).unwrap();
    let fri = randoms.import(rng(71)).unwrap();
    let before = runtime.snapshot();
    // CPU witness construction is an oracle input in this test. The measured
    // device operation starts with the uploaded trace and public values.
    let proof = engine
        .prove(
            &prepared,
            &trace,
            Some(&public),
            StarkRandomness {
                masks: &masks,
                commitments: &salts,
                fri: &fri,
            },
            64 << 20,
        )
        .unwrap();
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    let before_verify = runtime.snapshot();
    p3_uni_stark::verify(&crate::config::make_config(), &air, &proof, &publics).unwrap();
    let mut wrong = publics.clone();
    wrong[0] += Val::ONE;
    assert!(p3_uni_stark::verify(&crate::config::make_config(), &air, &proof, &wrong).is_err());
    assert_eq!(runtime.snapshot(), before_verify);
}

#[test]
#[ignore = "requires CUDA; serial bounded service; CPU witness oracle input"]
fn cuda_joinsplit_stark_from_resident_trace_passes_production_cpu_verifier() {
    let witness = crate::joinsplit_air::demo_witness();
    wallet(
        crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::build_trace(&witness),
        crate::joinsplit_air::public_values(&witness),
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service; CPU witness oracle input"]
fn cuda_htlc_stark_from_resident_trace_passes_production_cpu_verifier() {
    let witness = crate::htlc_air::demo_witness();
    wallet(
        crate::htlc_air::HtlcAir,
        crate::htlc_air::build_trace(&witness),
        crate::htlc_air::public_values(&witness),
    );
}

#[test]
#[ignore = "requires pinned NVRTC but no device"]
fn cuda_stark_periodic_source_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
