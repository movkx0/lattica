use super::{check_binding_and_policy, WitnessOwner};
use crate::block_v2::machine::{ExecutionError, ProgramBuilder};
use crate::proving::{Policy, Request};
use std::{cell::RefCell, sync::Arc};

struct Owner<'a> {
    events: &'a RefCell<Vec<&'static str>>,
    name: &'static str,
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.events.borrow_mut().push(self.name);
    }
}

#[test]
fn consuming_trace_retires_instructions_before_returning_the_owned_matrix() {
    let events = RefCell::new(Vec::new());
    let instructions = Owner {
        events: &events,
        name: "instruction_drop",
    };
    let trace = WitnessOwner::Consumed(instructions)
        .trace_and_retire(|_| {
            assert!(events.borrow().is_empty());
            let _fence = Owner {
                events: &events,
                name: "trace_fence",
            };
            Ok::<_, ExecutionError>(Owner {
                events: &events,
                name: "owned_trace_drop",
            })
        })
        .unwrap();
    assert_eq!(*events.borrow(), ["trace_fence", "instruction_drop"]);
    // The trace has independent ownership after instructions are gone.
    drop(trace);
    assert_eq!(
        *events.borrow(),
        ["trace_fence", "instruction_drop", "owned_trace_drop"]
    );
}

#[test]
fn reusable_trace_preserves_instruction_owner_until_registration_retires() {
    let events = RefCell::new(Vec::new());
    let instructions = Owner {
        events: &events,
        name: "instruction_drop",
    };
    WitnessOwner::Retained(&instructions)
        .trace_and_retire(|_| Ok::<_, ExecutionError>(()))
        .unwrap();
    assert!(events.borrow().is_empty());
    let failure = WitnessOwner::Retained(&instructions)
        .trace_and_retire(|_| Err::<(), _>(ExecutionError::GpuFailure));
    assert_eq!(failure, Err(ExecutionError::GpuFailure));
    assert!(events.borrow().is_empty());
    drop(instructions);
    assert_eq!(*events.borrow(), ["instruction_drop"]);
}

#[test]
fn trace_failure_cleans_inner_guards_before_consumed_instructions() {
    let events = RefCell::new(Vec::new());
    let instructions = Owner {
        events: &events,
        name: "instruction_drop",
    };
    let failure = WitnessOwner::Consumed(instructions).trace_and_retire(|_| {
        let _scratch = Owner {
            events: &events,
            name: "scratch_scrub_drain",
        };
        let _fence = Owner {
            events: &events,
            name: "trace_fence_drain",
        };
        Err::<(), _>(ExecutionError::GpuFailure)
    });
    assert_eq!(failure, Err(ExecutionError::GpuFailure));
    assert_eq!(
        *events.borrow(),
        [
            "trace_fence_drain",
            "scratch_scrub_drain",
            "instruction_drop"
        ]
    );
}

#[test]
fn trace_unwind_cleans_inner_guards_before_consumed_instructions() {
    let events = RefCell::new(Vec::new());
    let instructions = Owner {
        events: &events,
        name: "instruction_drop",
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), ExecutionError> =
            WitnessOwner::Consumed(instructions).trace_and_retire(|_| {
                let _scratch = Owner {
                    events: &events,
                    name: "scratch_scrub_drain",
                };
                let _fence = Owner {
                    events: &events,
                    name: "trace_fence_drain",
                };
                panic!("injected trace failure");
            });
    }));
    assert!(result.is_err());
    assert_eq!(
        *events.borrow(),
        [
            "trace_fence_drain",
            "scratch_scrub_drain",
            "instruction_drop"
        ]
    );
}

#[test]
fn consuming_admission_requires_the_same_immutable_program_owner_and_gpu_policy() {
    let program = Arc::new(ProgramBuilder::new(1).unwrap().finish(Some(8)).unwrap());
    let same_program = Arc::clone(&program);
    let equal_geometry = Arc::new(ProgramBuilder::new(1).unwrap().finish(Some(8)).unwrap());
    let strict = Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    };
    check_binding_and_policy(&program, &same_program, strict).unwrap();
    assert_eq!(
        check_binding_and_policy(&program, &equal_geometry, strict),
        Err(ExecutionError::ProvingPolicy)
    );
    for policy in [Policy::Compatible, Policy::CpuRequired] {
        assert_eq!(
            check_binding_and_policy(
                &program,
                &same_program,
                Request {
                    policy,
                    emit_report: false,
                }
            ),
            Err(ExecutionError::ProvingPolicy)
        );
    }
}

mod gpu {
    use super::*;
    use crate::block_v2::{
        gpu_hash,
        machine::{
            backend::RegisteredProgram, MachineAir, Program, RegisteredGpuLimits,
            RegisteredGpuMemoryPlan,
        },
        profile, quotient_pcs,
    };
    use crate::config::Val;
    use crate::proving::{Backend, CoverageScope, Report};
    use p3_field::PrimeCharacteristicRing;

    // The borrowed comparison uses the existing registered-test allowance; a
    // one-shot admission never authorizes the reusable registration lifetime.
    const BASELINE_HOST_BYTES: u64 = (64 << 20)
        + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
        + 2 * crate::block_v2::machine::symbolic::HOST_BYTES
        + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES
        + gpu_hash::ENGINE_RETAINED_HOST_BYTES;

    fn program() -> Arc<Program> {
        let mut b = ProgramBuilder::new(4).unwrap();
        let x = b.input();
        let y = b.input();
        let seventeen = b.constant(Val::from_u64(17));
        let twenty_three = b.constant(Val::from_u64(23));
        let expressions = [
            b.add(x, y),
            b.mul(x, y),
            b.add(x, seventeen),
            b.add(y, twenty_three),
        ];
        for (index, expression) in expressions.into_iter().enumerate() {
            let public = b.public(index).unwrap();
            b.assert_equal(public, expression);
        }
        Arc::new(b.finish(Some(64)).unwrap())
    }

    fn values(x: u64, y: u64) -> ([Val; 4], Vec<Val>) {
        (
            [x + y, x * y, x + 17, y + 23].map(Val::from_u64),
            vec![Val::from_u64(x), Val::from_u64(y)],
        )
    }

    fn strict() -> Request {
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        }
    }

    fn initialize() {
        let fusion = quotient_pcs::initialize_research_from_env().unwrap();
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
        assert!(quotient_pcs::gpu_witness_enabled());
        assert!(quotient_pcs::gpu_randomness_enabled());
        assert!(quotient_pcs::gpu_transcript_enabled());
        gpu_hash::initialize_from_env().unwrap();
        assert!(gpu_hash::initialize_resident_from_env().unwrap());
    }

    fn receipt(report: &Report, scope: CoverageScope) {
        assert_eq!(report.policy, Policy::GpuRequired);
        assert_eq!(report.capabilities.scope(), scope);
        assert!(report.succeeded && report.stage_coverage_complete);
        assert!(!report.completion_rejected);
        assert_eq!(report.observation_errors, 0);
        assert!(report.components.is_empty());
        for stage in report.capabilities.stages() {
            assert_eq!(stage.backend, Backend::OpenCl);
            let observed: Vec<_> = report
                .observations
                .iter()
                .filter(|observation| observation.stage == stage.stage)
                .collect();
            assert_eq!(observed.len(), 1);
            let observation = observed[0];
            assert_eq!(observation.backend, Backend::OpenCl);
            assert!(observation.calls > 0 && observation.device_calls > 0);
            assert_eq!(observation.calls, observation.completed_calls);
        }
    }

    fn close() {
        gpu_hash::drain().unwrap();
        let terminal = gpu_hash::report("small consuming regression before close").unwrap();
        assert_eq!(terminal.device_matrix_live_bytes, 0);
        assert_eq!(terminal.device_matrices, 0);
        assert!(terminal.managed_peak_bytes <= 8 << 30);
        // shutdown checks every allocation and the exclusive job lease after
        // draining; its existing terminal receipt reports managed_live_bytes=0.
        gpu_hash::shutdown().unwrap();
        assert!(gpu_hash::report("small consuming regression closed").is_none());
    }

    struct Verified {
        id: [u64; 4],
        preprocessing: p3_symmetric::MerkleCap<Val, [Val; 4]>,
        main: p3_symmetric::MerkleCap<Val, [Val; 4]>,
    }

    fn prove_and_verify(
        program: &Arc<Program>,
        public: &[Val; 4],
        witness: &Vec<Val>,
        limits: RegisteredGpuLimits,
        consuming: bool,
    ) -> Verified {
        let _shutdown = gpu_hash::TestShutdownGuard;
        let admission = consuming.then(|| {
            RegisteredGpuMemoryPlan::new(program, public, witness, limits)
                .unwrap()
                .admit()
                .expect("complete one-shot admission; no test bypass")
        });
        initialize();
        let budget = admission
            .as_ref()
            .map_or(BASELINE_HOST_BYTES, |token| token.host_budget_bytes());
        let (registered, setup) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            MachineAir::from_shared_program(Arc::clone(program)),
            budget,
            strict(),
            None,
        )
        .unwrap();
        receipt(&setup, CoverageScope::Preprocessing);
        assert!(!registered.identity_hint_hit());
        let id = registered.id();
        let preprocessing = registered.preprocessing_cap().clone();
        let (proof, proving) = if let Some(token) = &admission {
            registered
                .into_prove_with_request_and_report(token, strict())
                .unwrap()
        } else {
            let completed = registered
                .prove_with_request_and_report(public, witness, strict())
                .unwrap();
            assert!(registered.prepared.gpu_witness.is_some());
            drop(registered);
            completed
        };
        receipt(&proving, CoverageScope::RegisteredProof);
        let main = proof.commitments.main.clone();
        // Only these small summaries survive into another GPU lifecycle.
        assert!(preprocessing.root_capacity() * 32 + main.root_capacity() * 32 < 16 << 10);
        drop(setup);
        drop(proving);
        drop(admission);
        close();

        // Rebuild the full independent upstream CPU PCS and preprocessing only
        // after GPU retirement. GPU-specific verifier adapters supply no trust.
        use crate::config::{Challenger, Dft, MyCompress, MyHash, ValMmcs};
        use p3_commit::ExtensionMmcs;
        use p3_fri::HidingFriPcs;
        use p3_goldilocks::default_goldilocks_poseidon2_8;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        type Ext = ExtensionMmcs<Val, profile::Challenge, ValMmcs>;
        type CpuPcs = HidingFriPcs<Val, Dft, ValMmcs, Ext, ChaCha20Rng>;
        type CpuConfig = p3_uni_stark::StarkConfig<CpuPcs, profile::Challenge, Challenger>;
        let perm = default_goldilocks_poseidon2_8();
        let base = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([0; 32]),
        );
        let pcs = CpuPcs::new(
            Default::default(),
            base.clone(),
            profile::fri(Ext::new(base)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
        );
        let reference = CpuConfig::new(pcs, Challenger::new(perm));
        let air = MachineAir::from_shared_program(Arc::clone(program));
        let data = p3_batch_stark::ProverData::from_airs_and_degrees(
            &reference,
            core::slice::from_ref(&air),
            &[program.height().ilog2() as usize + 1],
        );
        assert_eq!(
            data.common.preprocessed.as_ref().unwrap().commitment,
            preprocessing
        );
        let encoded = postcard::to_allocvec(&proof).unwrap();
        drop(proof);
        let mut proof: p3_batch_stark::BatchProof<CpuConfig> =
            postcard::from_bytes(&encoded).unwrap();
        drop(encoded);
        let verify = |proof: &p3_batch_stark::BatchProof<CpuConfig>, publics: &[Val]| {
            p3_batch_stark::verify_batch(
                &reference,
                core::slice::from_ref(&air),
                proof,
                &[publics.to_vec()],
                &data.common,
            )
        };
        verify(&proof, public).unwrap();
        let mut wrong = *public;
        wrong[0] += Val::ONE;
        assert!(verify(&proof, &wrong).is_err());
        let original = proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0];
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += profile::Challenge::ONE;
        assert!(verify(&proof, public).is_err());
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] = original;
        verify(&proof, public).unwrap();
        assert!(gpu_hash::report("CPU verification did not open GPU").is_none());
        Verified {
            id,
            preprocessing,
            main,
        }
    }

    #[test]
    #[ignore = "requires release wide AIR, complete admitted OpenCL profile, and serialized GPU slot"]
    fn small_consuming_registration_matches_reusable_and_closes_before_cpu_verification() {
        assert!(cfg!(all(
            not(debug_assertions),
            target_arch = "x86_64",
            feature = "block-v2-wide-lanes"
        )));
        let program = program();
        let (public, witness) = values(3, 5);
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, 1 << 20).unwrap();
        {
            let _shutdown = gpu_hash::TestShutdownGuard;
            let token = RegisteredGpuMemoryPlan::new(&program, &public, &witness, limits)
                .unwrap()
                .admit()
                .expect("complete one-shot admission; no test bypass");
            initialize();
            let different_owner = Arc::new(program.as_ref().clone());
            let registered = RegisteredProgram::new_with_request(
                MachineAir::from_shared_program(different_owner),
                token.host_budget_bytes(),
                strict(),
            )
            .unwrap();
            let before = gpu_hash::report("small consuming mismatch before dispatch").unwrap();
            assert!(matches!(
                registered.into_prove_with_request_and_report(&token, strict()),
                Err(ExecutionError::ProvingPolicy)
            ));
            let after = gpu_hash::report("small consuming mismatch rejected").unwrap();
            assert_eq!(before.allocations, after.allocations);
            assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
            assert_eq!(before.commits, after.commits);
            close();
        }
        {
            let _shutdown = gpu_hash::TestShutdownGuard;
            let mut invalid_witness = witness.clone();
            invalid_witness[0] += Val::ONE;
            let token = RegisteredGpuMemoryPlan::new(&program, &public, &invalid_witness, limits)
                .unwrap()
                .admit()
                .expect("complete one-shot admission; no test bypass");
            initialize();
            let registered = RegisteredProgram::new_with_request(
                MachineAir::from_shared_program(Arc::clone(&program)),
                token.host_budget_bytes(),
                strict(),
            )
            .unwrap();
            assert!(matches!(
                registered.into_prove_with_request_and_report(&token, strict()),
                Err(ExecutionError::Unsatisfied)
            ));
            close();
        }
        let reusable = prove_and_verify(&program, &public, &witness, limits, false);
        let consumed = prove_and_verify(&program, &public, &witness, limits, true);
        assert_eq!(reusable.id, consumed.id);
        assert_eq!(reusable.preprocessing, consumed.preprocessing);
        assert_ne!(
            reusable.main, consumed.main,
            "fresh hiding randomness must not replay"
        );
        let (other_public, other_witness) = values(7, 11);
        let other = prove_and_verify(&program, &other_public, &other_witness, limits, true);
        assert_eq!(other.id, consumed.id);
        assert_eq!(other.preprocessing, consumed.preprocessing);
        eprintln!("small_consuming_registration cases=5 fresh_proofs=3 independent_cpu_verified=3 mutation_rejections=6 contexts_closed=5 same_public_program=true reused_proofs=0");
    }
}
