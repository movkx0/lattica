use super::*;
use crate::block_v2::{gpu_hash, quotient_pcs};
use p3_field::PrimeCharacteristicRing;

const HOST_BUDGET: u64 = (64 << 20)
    + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
    // Setup reserves symbolic scratch outside the PCS partition; proving
    // also requires that partition to admit its quotient compiler workspace.
    + 2 * crate::block_v2::machine::symbolic::HOST_BYTES
    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES
    + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES;

fn initialize() {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(quotient_pcs::gpu_witness_enabled());
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
}

#[test]
#[ignore = "requires OpenCL GPU, owned preprocessing and a <=3 GiB zero-swap service"]
fn cached_pcs_metadata_rejects_spare_cap_storage_and_preserves_device_state() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let mut registered = RegisteredProgram::new_with_request(
        air(),
        HOST_BUDGET,
        crate::proving::Request::compatible(),
    )
    .unwrap();
    let rows = registered.prepared.air.program().height();
    let device_salts = quotient_pcs::gpu_randomness_enabled();
    let limit = gpu_hash::cache_metadata::bound(rows as u64, device_salts).unwrap();
    super::cache_storage::admit_prepared(&registered.prepared).unwrap();
    let mut roots = Vec::with_capacity(limit as usize / core::mem::size_of::<[Val; 4]>() + 1);
    roots.extend_from_slice(registered.preprocessing_cap().roots());
    let original = std::mem::replace(
        &mut registered
            .prepared
            .data
            .common
            .preprocessed
            .as_mut()
            .unwrap()
            .commitment,
        p3_symmetric::MerkleCap::new(roots),
    );
    assert_eq!(registered.preprocessing_cap().roots(), original.roots());
    let before = gpu_hash::report("cached PCS before metadata rejection").unwrap();
    assert!(super::cache_storage::admit_prepared(&registered.prepared)
        .unwrap_err()
        .contains("metadata exceeds allowance"));
    assert!(super::cache_storage::admit_data(&registered.prepared.data, rows, 1).is_err());
    registered
        .prepared
        .data
        .common
        .preprocessed
        .as_mut()
        .unwrap()
        .commitment = original;
    super::cache_storage::admit_prepared(&registered.prepared).unwrap();
    let after = gpu_hash::report("cached PCS after metadata restoration").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    assert_eq!(before.managed_live_bytes, after.managed_live_bytes);
    eprintln!("cached_pcs_gpu_rejection device_salts={device_salts} spare_cap_rejected=true restored=true device_allocation_unchanged=true upload_unchanged=true");
}

fn air() -> MachineAir {
    let mut b = super::super::ProgramBuilder::new(64).unwrap();
    for i in 0..64 {
        let public = b.public(i).unwrap();
        let witness = b.input();
        b.assert_equal(public, witness);
    }
    MachineAir::new(b.finish(Some(64)).unwrap())
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_WITNESS=1, device-only PCS and <=3 GiB zero-swap service"]
fn registered_device_preprocessing_uses_host_staging_bound_not_host_lde_payload() {
    use super::super::{analysis, gpu_backend::resources::Bounds, ProgramBuilder};
    let make_air = || {
        let mut builder = ProgramBuilder::new(1).unwrap();
        let public = builder.public(0).unwrap();
        let private = builder.input();
        builder.assert_equal(public, private);
        MachineAir::new(builder.finish(Some(16384)).unwrap())
    };
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let air = make_air();
    let analysis = analysis::analyze(&air).unwrap();
    let allowance = Bounds::for_program_with_device_salts(
        air.program(),
        quotient_pcs::gpu_randomness_enabled(),
    )
    .unwrap()
    .reservation(1)
    .unwrap()
    .host_bytes;
    eprintln!("cached_pcs_admission_geometry rows=16384 host_bytes={allowance} cpu_compact_bytes={} cpu_full_bytes={}", analysis.compact_retained_lde_lower_bound().unwrap(), analysis.retained_lde_bytes);
    assert!(analysis
        .check_ram_lower_bound_with_budget(allowance)
        .is_err());
    assert!(analysis
        .check_compact_ram_lower_bound_with_budget(allowance)
        .is_err());
    let before = gpu_hash::report("device registration before host rejection").unwrap();
    let error = RegisteredProgram::new_with_request(
        make_air(),
        allowance - 1,
        crate::proving::Request::compatible(),
    )
    .err()
    .unwrap();
    assert!(format!("{error:?}").contains("host allowance"), "{error:?}");
    let after = gpu_hash::report("device registration after host rejection").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    let registered =
        RegisteredProgram::new_with_request(air, allowance, crate::proving::Request::compatible())
            .unwrap();
    assert!(registered.prepared.gpu_witness.is_some());
    assert_eq!(registered.analysis().height, 16384);
    assert!(registered
        .prepared
        .data
        .prover_only
        .preprocessed_prover_data
        .is_some());
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_WITNESS=1, device-only PCS and <=3 GiB zero-swap service"]
fn registered_gpu_witness_keeps_cpu_registry_identity_and_proves_in_fresh_sessions() {
    registered_proofs(false, false, false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_RANDOMNESS=1 and a <=3 GiB zero-swap service"]
fn registered_gpu_randomness_preserves_identity_and_proves_in_fresh_sessions() {
    registered_proofs(true, false, false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_TRANSCRIPT=1 and a <=3 GiB zero-swap service"]
fn registered_gpu_transcript_preserves_identity_and_proves_in_fresh_sessions() {
    registered_proofs(true, true, false);
}

#[test]
#[ignore = "requires all owned OpenCL proving stages and <=3 GiB zero-swap service"]
fn registered_gpu_required_scope_proves_or_rejects_debug_audits_before_work() {
    registered_proofs(true, true, true);
}

fn registered_proofs(randomness: bool, transcript: bool, strict: bool) {
    use crate::config::{Challenger, Dft, MyCompress, MyHash, ValMmcs};
    use p3_commit::ExtensionMmcs;
    use p3_fri::HidingFriPcs;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    initialize();
    assert_eq!(quotient_pcs::gpu_randomness_enabled(), randomness);
    assert_eq!(quotient_pcs::gpu_transcript_enabled(), transcript);
    let _shutdown = gpu_hash::TestShutdownGuard;
    if !randomness {
        let input_air = air();
        let before = gpu_hash::report("partial setup before GPU policy rejection").unwrap();
        let request = crate::proving::Request {
            policy: crate::proving::Policy::GpuRequired,
            emit_report: true,
        };
        assert!(matches!(
            RegisteredProgram::new_with_request(input_air, HOST_BUDGET, request),
            Err(super::super::analysis::AdmissionError::ProvingPolicy(
                crate::proving::Error::Unsupported { gaps, .. }
            )) if gaps.iter().any(|gap| gap.stage == crate::proving::Stage::Randomness
                && gap.backend == crate::proving::Backend::Cpu)
        ));
        let after = gpu_hash::report("partial setup after GPU policy rejection").unwrap();
        assert_eq!(after.allocations, before.allocations);
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    }
    let capabilities = profile::proving_capabilities(true);
    let scoped = profile::registered_proof_capabilities();
    assert_eq!(
        scoped.scope(),
        crate::proving::CoverageScope::RegisteredProof
    );
    assert!(!scoped
        .stages()
        .iter()
        .any(|s| s.stage == crate::proving::Stage::PublicValues));
    if transcript {
        if cfg!(debug_assertions) {
            let crate::proving::Error::Unsupported { gaps, .. } = scoped
                .admit(crate::proving::Policy::GpuRequired)
                .unwrap_err()
            else {
                panic!("debug audit gap")
            };
            assert_eq!(
                gaps,
                vec![crate::proving::StageCapability {
                    stage: crate::proving::Stage::ConstraintAudit,
                    backend: crate::proving::Backend::Cpu
                }]
            );
        } else {
            scoped.admit(crate::proving::Policy::GpuRequired).unwrap();
        }
    }

    for (stage, backend) in [
        (
            crate::proving::Stage::WitnessTrace,
            crate::proving::Backend::OpenCl,
        ),
        (
            crate::proving::Stage::Preprocessing,
            crate::proving::Backend::Mixed,
        ),
        (
            crate::proving::Stage::Transcript,
            if transcript {
                crate::proving::Backend::OpenCl
            } else {
                crate::proving::Backend::Cpu
            },
        ),
        (
            crate::proving::Stage::Grinding,
            if transcript {
                crate::proving::Backend::OpenCl
            } else {
                crate::proving::Backend::Cpu
            },
        ),
        (
            crate::proving::Stage::Scalar,
            if transcript {
                crate::proving::Backend::OpenCl
            } else {
                crate::proving::Backend::Mixed
            },
        ),
    ] {
        assert!(capabilities
            .stages()
            .iter()
            .any(|entry| entry.stage == stage && entry.backend == backend));
    }
    for budget in [64 << 20, 128 << 20, super::super::symbolic::HOST_BYTES - 1] {
        let before =
            gpu_hash::report("registered witness before compiler budget rejection").unwrap();
        assert!(matches!(
            RegisteredProgram::new_with_memory_budget(air(), budget),
            Err(super::super::analysis::AdmissionError::Gpu(reason))
                if reason.contains("source/compiler/staging")
        ));
        let after = gpu_hash::report("registered witness after compiler budget rejection").unwrap();
        assert_eq!(before.allocations, after.allocations);
        assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    }
    let request = if strict {
        crate::proving::Request {
            policy: crate::proving::Policy::GpuRequired,
            emit_report: true,
        }
    } else {
        crate::proving::Request::from_env().unwrap()
    };
    let mut registered = RegisteredProgram::new_with_request(air(), HOST_BUDGET, request).unwrap();
    assert!(registered.prepared.gpu_witness.is_some());
    {
        use p3_uni_stark::StarkGenericConfig;
        assert!(!profile::preprocessing_config()
            .initialise_challenger()
            .is_gpu());
        assert!(!profile::make_config().initialise_challenger().is_gpu());
    }

    type Ext = ExtensionMmcs<Val, profile::Challenge, ValMmcs>;
    type CpuPcs = HidingFriPcs<Val, Dft, ValMmcs, Ext, ChaCha20Rng>;
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
    let reference = p3_uni_stark::StarkConfig::<CpuPcs, profile::Challenge, Challenger>::new(
        pcs,
        Challenger::new(perm),
    );
    let data = ProverData::from_airs_and_degrees(
        &reference,
        core::slice::from_ref(registered.air()),
        &[7],
    );
    let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
    assert_eq!(registered.preprocessing_cap(), cap);
    let common = common_from_cap(registered.air(), cap.clone()).unwrap();
    assert_eq!(
        registered.id(),
        program_identity(registered.air(), &common, registered.analysis())
    );
    let verifier = registered.verifier();
    let baseline = gpu_hash::report("registered witness public baseline").unwrap();
    let public: Vec<_> = (17..81).map(Val::from_u64).collect();
    let mut rejected_policies = vec![crate::proving::Policy::CpuRequired];
    if !transcript || cfg!(debug_assertions) {
        rejected_policies.push(crate::proving::Policy::GpuRequired);
    }
    for policy in rejected_policies {
        let request = crate::proving::Request {
            policy,
            emit_report: false,
        };
        assert!(matches!(
            registered.prove_with_request(&public, &public, request),
            Err(ExecutionError::ProvingPolicy)
        ));
    }
    assert!(matches!(
        registered.prove(&[], &public),
        Err(ExecutionError::PublicInputCount)
    ));
    assert!(matches!(
        registered.prove(&public, &[]),
        Err(ExecutionError::WitnessCount)
    ));
    let rejected = gpu_hash::report("registered witness count policy rejection").unwrap();
    assert_eq!(rejected.uploaded_bytes, baseline.uploaded_bytes);
    assert_eq!(rejected.allocations, baseline.allocations);
    if strict && cfg!(debug_assertions) {
        // Admission includes the known CPU constraint audit and rejects before
        // trace allocation/private draws; setup is independently GPU-complete.
        assert!(matches!(
            registered.prove_with_request(&public, &public, request),
            Err(ExecutionError::ProvingPolicy)
        ));
        let rejected = gpu_hash::report("strict debug audit admission").unwrap();
        assert_eq!(rejected.allocations, baseline.allocations);
        assert_eq!(rejected.uploaded_bytes, baseline.uploaded_bytes);
        drop(registered);
        gpu_hash::shutdown().unwrap();
        return;
    }
    if strict {
        let prepared = registered.prepared.gpu_witness.take();
        assert!(matches!(
            registered.prove_with_request(&public, &public, request),
            Err(ExecutionError::GpuFailure)
        ));
        let rejected = gpu_hash::report("strict missing preprocessing provenance").unwrap();
        assert_eq!(rejected.allocations, baseline.allocations);
        assert_eq!(rejected.uploaded_bytes, baseline.uploaded_bytes);
        registered.prepared.gpu_witness = prepared;
    }
    let mut wrong = public.clone();
    wrong[63] += Val::ONE;
    assert!(matches!(
        registered.prove_with_request(&public, &wrong, request),
        Err(ExecutionError::Unsatisfied)
    ));
    let rejected = gpu_hash::report("registered witness invalid assignment released").unwrap();
    assert_eq!(
        rejected.device_matrix_live_bytes,
        baseline.device_matrix_live_bytes
    );
    let mut proofs = Vec::new();
    for offset in [17, 117, 217] {
        let public: Vec<_> = (offset..offset + 64).map(Val::from_u64).collect();
        let proof = registered
            .prove_with_request(&public, &public, request)
            .unwrap();
        verifier.verify(&proof, &public).unwrap();
        proofs.push((postcard::to_allocvec(&proof).unwrap(), public));
        let after = gpu_hash::report("registered GPU witness proof complete").unwrap();
        assert_eq!(
            after.device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
        assert_eq!(after.device_matrices, baseline.device_matrices);
        assert_eq!(after.lde_host_output_bytes, baseline.lde_host_output_bytes);
        assert_eq!(
            after.lde_host_reordered_bytes,
            baseline.lde_host_reordered_bytes
        );
    }
    let cpu_air = registered.air().clone();
    drop(registered);
    gpu_hash::shutdown().unwrap();
    for (encoded, public) in proofs {
        let proof = postcard::from_bytes(&encoded).unwrap();
        verify_batch(
            &reference,
            core::slice::from_ref(&cpu_air),
            &proof,
            &[public.clone()],
            &data.common,
        )
        .unwrap();
        let mut wrong = public;
        wrong[63] += Val::ONE;
        assert!(verify_batch(
            &reference,
            core::slice::from_ref(&cpu_air),
            &proof,
            &[wrong],
            &data.common
        )
        .is_err());
    }
}

struct AssignmentFile {
    path: std::path::PathBuf,
    previous: Option<std::ffi::OsString>,
}
impl Drop for AssignmentFile {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("LATTICA_V2_WORKER_BUDGET", value),
            None => std::env::remove_var("LATTICA_V2_WORKER_BUDGET"),
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_WITNESS=1 and <=3 GiB zero-swap service"]
fn registered_witness_worker_bounds_reject_before_any_device_upload() {
    registered_worker_bounds(false, false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_RANDOMNESS=1 and a <=3 GiB zero-swap service"]
fn registered_randomness_worker_bounds_reject_before_any_device_upload() {
    registered_worker_bounds(true, false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_TRANSCRIPT=1 and a <=3 GiB zero-swap service"]
fn registered_transcript_worker_bounds_reject_before_initialization_or_private_draws() {
    registered_worker_bounds(true, true);
}

fn registered_worker_bounds(randomness: bool, transcript: bool) {
    use super::super::gpu_backend::resources::Bounds;
    let _shutdown = gpu_hash::TestShutdownGuard;
    let original = air();
    let b = Bounds::for_program(original.program()).unwrap();
    let mut valid = serde_json::json!({
        "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
        "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
        "witness_bounds":b,"witness_reservation":b.reservation(1).unwrap(),
        "owned_quotient_reservation":{"managed_bytes":67108864},
        "gpu":{"version":1,"managed_bytes":268435456,"max_allocation_bytes":67108864},
        "host":{"worker_bytes":HOST_BUDGET}
    });
    if randomness {
        let random = crate::block_v2::randomness::resources::Bounds {
            rows: b.rows,
            main_columns: b.main_columns,
            preprocessing_columns: b.preprocessing_columns,
            lookup_columns: 4096,
            quotient_rows: b.rows * 16,
            quotient_chunks: 16,
        };
        valid["gpu_randomness"] = true.into();
        valid["randomness_bounds"] = serde_json::to_value(random).unwrap();
        valid["randomness_reservation"] =
            serde_json::to_value(random.reservation(1).unwrap()).unwrap();
    }
    if transcript {
        use crate::block_v2::challenger::resources;
        valid["gpu_transcript"] = true.into();
        valid["transcript_bounds"] = serde_json::to_value(resources::BOUNDS).unwrap();
        valid["transcript_reservation"] = serde_json::to_value(resources::reservation()).unwrap();
    }
    let path = std::env::temp_dir().join(format!(
        "lattica-witness-assignment-{}.json",
        std::process::id()
    ));
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let assignment = AssignmentFile {
        path,
        previous: std::env::var_os("LATTICA_V2_WORKER_BUDGET"),
    };
    std::env::set_var("LATTICA_V2_WORKER_BUDGET", &assignment.path);
    let mut bad = valid.clone();
    if transcript {
        bad["transcript_reservation"]["managed_bytes"] = 1.into();
    } else {
        bad["gpu_witness"] = false.into();
    }
    std::fs::write(&assignment.path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    assert!(quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).is_err());
    assert!(!quotient_pcs::gpu_witness_enabled());
    assert!(!quotient_pcs::gpu_transcript_enabled());
    assert!(!gpu_hash::is_enabled());
    // Rejection leaves both selection and context initialization untouched.
    std::fs::write(&assignment.path, serde_json::to_vec(&valid).unwrap()).unwrap();
    initialize();
    let baseline = gpu_hash::report("registered witness before bad worker bounds").unwrap();
    for case in 0..4 {
        let mut bad = valid.clone();
        match case {
            0 => {
                bad["gpu_witness"] = false.into();
            }
            1 => {
                bad["witness_reservation"]["managed_bytes"] = 1.into();
            }
            2 => {
                let mut bounds = b.clone();
                bounds.metadata_bytes = 192;
                bad["witness_bounds"] = serde_json::to_value(&bounds).unwrap();
                bad["witness_reservation"] =
                    serde_json::to_value(bounds.reservation(1).unwrap()).unwrap();
            }
            _ => {
                bad["witness_bounds"]["extra"] = 1.into();
            }
        }
        std::fs::write(&assignment.path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(matches!(
            RegisteredProgram::new_with_memory_budget(original.clone(), HOST_BUDGET),
            Err(super::super::analysis::AdmissionError::Gpu(_))
        ));
        let after = gpu_hash::report("registered witness rejected worker bounds").unwrap();
        assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
        assert_eq!(after.allocations, baseline.allocations);
    }
    std::fs::write(&assignment.path, serde_json::to_vec(&valid).unwrap()).unwrap();
    if randomness {
        for case in 0..3 {
            let mut bad = valid.clone();
            match case {
                0 => bad["gpu_randomness"] = false.into(),
                1 => bad["randomness_reservation"]["managed_bytes"] = 1.into(),
                _ => bad["randomness_bounds"]["rows"] = 1.into(),
            }
            std::fs::write(&assignment.path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(matches!(
                RegisteredProgram::new_with_memory_budget(original.clone(), HOST_BUDGET),
                Err(super::super::analysis::AdmissionError::Gpu(_))
            ));
            let after =
                gpu_hash::report("registered randomness rejected before key imports").unwrap();
            assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
            assert_eq!(after.allocations, baseline.allocations);
        }
        std::fs::write(&assignment.path, serde_json::to_vec(&valid).unwrap()).unwrap();
    }
    let registered =
        RegisteredProgram::new_with_memory_budget(original.clone(), HOST_BUDGET).unwrap();
    assert!(registered.prepared.gpu_witness.is_some());
    if transcript {
        let public: Vec<_> = (1..=64).map(Val::from_u64).collect();
        let baseline =
            gpu_hash::report("registered transcript before rejected assignments").unwrap();
        for case in 0..4 {
            let mut bad = valid.clone();
            match case {
                0 => bad["gpu_transcript"] = false.into(),
                1 => bad["transcript_reservation"]["managed_bytes"] = 1.into(),
                2 => bad["transcript_bounds"]["live_states"] = 3.into(),
                _ => bad["transcript_bounds"]["extra"] = 1.into(),
            }
            std::fs::write(&assignment.path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(matches!(
                RegisteredProgram::new_with_memory_budget(original.clone(), HOST_BUDGET),
                Err(super::super::analysis::AdmissionError::Gpu(_))
            ));
            assert!(matches!(
                registered.prove(&public, &public),
                Err(ExecutionError::GpuFailure)
            ));
            let after =
                gpu_hash::report("registered transcript rejected before state creation").unwrap();
            assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
            assert_eq!(after.allocations, baseline.allocations);
        }
        std::fs::write(&assignment.path, serde_json::to_vec(&valid).unwrap()).unwrap();
    }
    if randomness {
        let public: Vec<_> = (1..=64).map(Val::from_u64).collect();
        let proof = registered.prove(&public, &public).unwrap();
        registered.verifier().verify(&proof, &public).unwrap();
    }
}
