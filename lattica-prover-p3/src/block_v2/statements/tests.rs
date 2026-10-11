use super::*;
use crate::block_v2::machine::programs;
use crate::proving::Policy;
use p3_field::PrimeCharacteristicRing;

#[cfg(all(feature = "gpu", feature = "stream", target_os = "linux"))]
#[path = "native_public_tests.rs"]
mod native_public;

fn context() -> Context {
    Context {
        profile_id: [0x31; 32],
        chain_id: [0x92; 32],
    }
}

fn conformance(hash: &mut Derivation<'_>) -> Result<(), Error> {
    let context = context();
    let mut entries = Vec::new();
    for i in 0..64u64 {
        let kind = Kind::from_code(1 + (i % 3) as u8)?;
        let words = [i, commitment::MODULUS - 1, 0, i + 1, 0];
        let entry = Entry {
            kind,
            statement_digest: commitment::statement_digest(kind as u8, &words)?,
        };
        assert_eq!(
            hash.leaf(context, kind, &words.map(Val::from_u64))?,
            commitment::leaf(context, entry)?
        );
        entries.push(entry);
    }
    for count in [1, 2, 3, 17, 63, 64] {
        assert_eq!(
            commitment::root_with_hash(context, &entries[..count], &mut |d, f| hash.hash(d, f))?,
            commitment::root(context, &entries[..count])?
        );
    }
    let leaf = commitment::leaf(context, entries[0])?;
    for level in 0..=commitment::DEPTH {
        let empty = hash.empty(context, level)?;
        assert_eq!(empty, commitment::empty_subtree(context, level)?);
        for modes in [3, 5, 6, 12] {
            let public = programs::statement(empty, programs::EMPTY);
            assert_eq!(hash.summary(&public, modes)?, empty);
            let mut wrong = public;
            wrong[programs::ROOT] += Val::ONE;
            assert_eq!(
                hash.summary(&wrong, modes).unwrap_err().to_string(),
                commitment::CommitmentError::InvalidEmptyRoot.to_string()
            );
        }
    }
    for modes in [6, 12] {
        let public = programs::statement(leaf, programs::WRAPPER);
        let root = hash.finalize(&public, modes, modes)?;
        assert_eq!(root.level, commitment::DEPTH);
        assert_eq!(root.count, 1);
        assert_eq!(root.root, commitment::root(context, &entries[..1])?);
        assert!(hash
            .finalize(&programs::statement(root, programs::MERGE), modes, modes)
            .is_err());
        assert!(hash
            .finalize(&programs::statement(leaf, modes), modes, modes)
            .is_err());
    }
    let other = commitment::leaf(
        Context {
            chain_id: [9; 32],
            ..context
        },
        entries[1],
    )?;
    assert_eq!(
        hash.merge(leaf, other).unwrap_err().to_string(),
        "child contexts differ"
    );
    let empty = hash.empty(context, 0)?;
    assert_eq!(
        hash.merge(empty, leaf).unwrap_err().to_string(),
        "nonempty right subtree requires a full left subtree"
    );
    let pair = hash.merge(leaf, commitment::leaf(context, entries[1])?)?;
    assert_ne!(
        pair.root,
        hash.merge(commitment::leaf(context, entries[1])?, leaf)?
            .root
    );
    let padded = hash.merge(leaf, empty)?;
    assert_eq!(padded.count, 1);
    assert_eq!(padded, commitment::merge_nodes(leaf, empty)?);
    let mut public = programs::statement(leaf, programs::WRAPPER);
    for (index, value, error) in [
        (0, 1u64 << 32, "noncanonical context limb"),
        (programs::MODE, 0, "node metadata range"),
        (programs::LEVEL, 7, "node metadata range"),
        (programs::COUNT, 2, "node metadata range"),
    ] {
        let old = public[index];
        public[index] = Val::from_u64(value);
        assert_eq!(hash.summary(&public, 3).unwrap_err().to_string(), error);
        assert_eq!(recursive::summary(&public).unwrap_err().to_string(), error);
        public[index] = old;
    }
    Ok(())
}

#[test]
fn cpu_statements_preserve_reference_roots_errors_and_partial_reports() {
    let (result, report) = derive_reported(
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        conformance,
    )
    .unwrap();
    result.unwrap();
    assert!(report.succeeded);
    assert!(report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].backend, Backend::Cpu);
    assert_eq!(report.observations[0].stage, Stage::PublicValues);
    assert!(report.observations[0].completed_calls > 0);
    assert_eq!(report.observations[0].device_ns, 0);
}

#[test]
fn incomplete_gpu_policy_rejects_before_statement_derivation() {
    assert!(derive_reported(
        Request {
            policy: Policy::GpuRequired,
            emit_report: false
        },
        |_| -> Result<(), Error> { panic!("rejected before hashing") }
    )
    .is_err());
}

fn summary_only_reports(backend: Backend) {
    let policy = if backend == Backend::Cpu {
        Policy::CpuRequired
    } else {
        Policy::GpuRequired
    };
    for modes in [3, 5, 6, 12] {
        for level in 0..=commitment::DEPTH {
            for count in [1, 1 << level] {
                for mode in [1, modes] {
                    let node = NodeSummary {
                        context: Context {
                            profile_id: [0xff; 32],
                            chain_id: [0; 32],
                        },
                        level,
                        count,
                        root: [0, 1, commitment::MODULUS - 1, 9],
                    };
                    let public = programs::statement(node, mode);
                    let (result, report) = derive_reported(
                        Request {
                            policy,
                            emit_report: false,
                        },
                        |hash| hash.summary(&public, modes),
                    )
                    .unwrap();
                    assert_eq!(result.unwrap(), node);
                    assert_eq!(recursive::decode_summary(&public, modes).unwrap(), node);
                    assert!(report.succeeded && report.stage_coverage_complete);
                    assert_eq!(report.observations.len(), 1);
                    let observation = &report.observations[0];
                    assert_eq!(observation.stage, Stage::PublicValues);
                    assert_eq!(observation.backend, backend);
                    assert_eq!(observation.calls, 1);
                    assert_eq!(observation.completed_calls, 1);
                    assert_eq!(observation.device_ns > 0, backend == Backend::OpenCl);
                }
            }
        }
    }
    let node = NodeSummary {
        context: context(),
        level: 6,
        count: 64,
        root: [1; 4],
    };
    let valid = programs::statement(node, 12);
    for (index, value, error) in [
        (0, 1 << 32, "noncanonical context limb"),
        (15, commitment::MODULUS - 1, "noncanonical context limb"),
        (programs::MODE, 0, "node metadata range"),
        (programs::MODE, 13, "node metadata range"),
        (programs::LEVEL, 7, "node metadata range"),
        (
            programs::LEVEL,
            commitment::MODULUS - 1,
            "node metadata range",
        ),
        (programs::COUNT, 65, "node metadata range"),
    ] {
        let mut public = valid;
        public[index] = Val::from_u64(value);
        let (result, report) = derive_reported(
            Request {
                policy,
                emit_report: false,
            },
            |hash| hash.summary(&public, 12),
        )
        .unwrap();
        assert_eq!(result.unwrap_err().to_string(), error);
        assert_eq!(
            recursive::decode_summary(&public, 12)
                .unwrap_err()
                .to_string(),
            error
        );
        assert!(!report.succeeded && !report.stage_coverage_complete);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].completed_calls, 1);
        assert_eq!(report.observations[0].backend, backend);
    }
}

#[test]
fn cpu_nonempty_summary_alone_has_complete_statement_coverage() {
    summary_only_reports(Backend::Cpu);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_nonempty_summary_alone_has_complete_statement_coverage() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    initialize();
    summary_only_reports(Backend::OpenCl);
}

#[test]
fn callback_validation_precedes_hashing_and_empty_hash_failures_propagate() {
    use commitment::CommitmentError as C;
    let mut reject = |_: u64, _: &[u64]| -> Result<Digest, C> { panic!("no hashing allowed") };
    assert_eq!(
        commitment::statement_digest_with_hash(0, &[u64::MAX], &mut reject),
        Err(C::InvalidKind)
    );
    assert_eq!(
        commitment::statement_digest_with_hash(1, &[u64::MAX], &mut reject),
        Err(C::NonCanonicalField)
    );
    assert_eq!(
        commitment::empty_subtree_with_hash(context(), 7, &mut reject),
        Err(C::InvalidLevel)
    );
    let empty = commitment::empty_subtree(context(), 2).unwrap();
    assert_eq!(
        commitment::validate_summary_with_hash(
            NodeSummary {
                count: 5,
                root: [u64::MAX; 4],
                ..empty
            },
            &mut reject
        ),
        Err(C::InvalidCount)
    );
    assert_eq!(
        commitment::validate_summary_with_hash(
            NodeSummary {
                root: [u64::MAX; 4],
                ..empty
            },
            &mut reject
        ),
        Err(C::NonCanonicalField)
    );
    let mut domains = Vec::new();
    let mut fail = |domain: u64, fields: &[u64]| -> Result<Digest, Error> {
        domains.push(domain);
        if domains.len() == 2 {
            return Err("injected hash failure".into());
        }
        Ok(commitment::hash_fields(domain, fields)?)
    };
    assert_eq!(
        commitment::validate_summary_with_hash(empty, &mut fail)
            .unwrap_err()
            .to_string(),
        "injected hash failure"
    );
    assert_eq!(domains, [commitment::EMPTY, commitment::NODE]);
    assert_eq!(
        commitment::validate_summary_with_hash(empty, &mut commitment::hash_fields),
        Ok(())
    );
}

#[cfg(feature = "gpu")]
pub(super) fn initialize() {
    use crate::block_v2::{gpu_hash, quotient_pcs};
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(quotient_pcs::gpu_witness_enabled());
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_statements_match_cpu_roots_and_report_only_completed_work() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let (result, report) = derive_reported(Request::compatible(), conformance).unwrap();
    result.unwrap();
    assert!(report.succeeded);
    assert!(report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let o = &report.observations[0];
    assert_eq!(o.backend, Backend::OpenCl);
    assert_eq!(o.stage, Stage::PublicValues);
    assert_eq!(o.calls, o.completed_calls);
    assert!(o.completed_calls > 0 && o.device_ns > 0);
    assert_eq!(o.inclusive_ns, 0);
    let (result, report) = derive_reported(Request::compatible(), |hash| -> Result<(), Error> {
        hash.empty(context(), 2)?;
        Err("injected derivation failure".into())
    })
    .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected derivation failure"
    );
    assert!(!report.succeeded && !report.stage_coverage_complete);
    assert_eq!(report.observations[0].completed_calls, 3);
    assert!(report.observations[0].device_ns > 0);
    let (result, report) =
        derive_reported(Request::compatible(), |hash| hash.empty(context(), 2)).unwrap();
    assert_eq!(
        result.unwrap(),
        commitment::empty_subtree(context(), 2).unwrap()
    );
    assert_eq!(report.observations[0].completed_calls, 3);
    let (result, report) = derive_reported(
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        |hash| hash.empty(context(), 2),
    )
    .unwrap();
    assert_eq!(
        result.unwrap(),
        commitment::empty_subtree(context(), 2).unwrap()
    );
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(
        report.capabilities.scope(),
        crate::proving::CoverageScope::Statement
    );
    let baseline = gpu_hash::report("statements before policy rejection").unwrap();
    for policy in [Policy::CpuRequired] {
        assert!(derive_reported(
            Request {
                policy,
                emit_report: false
            },
            |_| -> Result<(), Error> { panic!("must not enter rejected derivation") }
        )
        .is_err());
    }
    let after = gpu_hash::report("statements after policy rejection").unwrap();
    assert_eq!(after.allocations, baseline.allocations);
    assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
}

#[cfg(feature = "gpu")]
fn empty_key<const N: usize>(height: usize) -> programs::Caps<N> {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
    let mut caps = core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    let compiled = programs::empty(height, &caps).unwrap();
    let registered = RegisteredProgram::new_with_memory_budget(
        MachineAir::new(compiled.program.pad_to(height).unwrap()),
        1 << 30,
    )
    .unwrap();
    caps[1] = registered.preprocessing_cap().roots().to_vec();
    caps
}

#[cfg(feature = "gpu")]
struct RestorePolicy(Option<std::ffi::OsString>);
#[cfg(feature = "gpu")]
impl Drop for RestorePolicy {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => std::env::set_var("LATTICA_PROVING_POLICY", value),
            None => std::env::remove_var("LATTICA_PROVING_POLICY"),
        }
    }
}

#[cfg(feature = "gpu")]
fn recursive_gpu_policy<T>(prove: impl FnOnce() -> Result<T, Error>) -> Option<RestorePolicy> {
    use crate::block_v2::gpu_hash;
    let restore = RestorePolicy(std::env::var_os("LATTICA_PROVING_POLICY"));
    std::env::set_var("LATTICA_PROVING_POLICY", "gpu-required");
    if !cfg!(debug_assertions) {
        return Some(restore);
    }
    let before = gpu_hash::report("whole debug request before rejection").unwrap();
    let error = match prove() {
        Ok(_) => panic!("debug CPU audits must reject GPU-required requests"),
        Err(error) => error,
    };
    assert!(matches!(
        error.downcast_ref::<crate::proving::Error>(),
        Some(crate::proving::Error::Unsupported {
            policy: Policy::GpuRequired,
            ..
        })
    ));
    let after = gpu_hash::report("whole debug request after rejection").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    eprintln!("whole_gpu_request_rejected_before_component_work");
    None
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_untyped_empty_proofs_use_statements_and_verify_after_shutdown() {
    use crate::block_v2::{codec, gpu_hash};
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let height = 2048;
    let registry = recursive::Registry {
        height,
        caps: empty_key(height),
    };
    let pin = registry.id().unwrap();
    let mut session = recursive::ProverSession::new(registry.clone(), pin).unwrap();
    let _policy = recursive_gpu_policy(|| session.empty(context().chain_id, 0));
    let mut encoded = Vec::new();
    for level in [0, 5] {
        let proof = session.empty(context().chain_id, level).unwrap();
        let reference = commitment::empty_subtree(
            Context {
                profile_id: pin,
                ..context()
            },
            level,
        )
        .unwrap();
        assert_eq!(
            proof.public,
            programs::statement(reference, programs::EMPTY)
        );
        encoded.push(codec::encode_node(&proof).unwrap());
    }
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 1 }
    );
    drop(session);
    gpu_hash::shutdown().unwrap();
    for bytes in encoded {
        let mut proof = codec::decode_node(&bytes).unwrap();
        registry.verify(pin, &proof, &proof.public).unwrap();
        let mut wrong = proof.public;
        wrong[programs::ROOT] += Val::ONE;
        assert!(registry.verify(pin, &proof, &wrong).is_err());
        // A nonzero in-range count passes summary structure checks. Keep the
        // expected statement equal to the altered artifact so rejection comes
        // from proof verification, not the expected-statement comparison.
        proof.public[programs::COUNT] = Val::ONE;
        recursive::summary(&proof.public).unwrap();
        assert!(registry.verify(pin, &proof, &proof.public).is_err());
    }
}

#[cfg(feature = "gpu")]
fn typed_empty_proofs<const N: usize>() {
    use crate::block_v2::{codec, gpu_hash, typed_recursive};
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let height = 2048;
    let registry = typed_recursive::Registry::<N> {
        height,
        caps: empty_key(height),
    };
    let pin = registry.id().unwrap();
    let mut session = typed_recursive::Session::new(registry.clone(), pin, 1 << 30).unwrap();
    let _policy = recursive_gpu_policy(|| session.empty(context().chain_id, 0));
    let mut encoded = Vec::new();
    for level in [0, 5] {
        let proof = session.empty(context().chain_id, level).unwrap();
        let reference = commitment::empty_subtree(
            Context {
                profile_id: pin,
                ..context()
            },
            level,
        )
        .unwrap();
        assert_eq!(
            proof.public,
            programs::statement(reference, programs::EMPTY)
        );
        encoded.push(codec::encode_node(&proof).unwrap());
    }
    assert_eq!(
        session.stats(),
        recursive::CacheStats { setups: 1, hits: 1 }
    );
    drop(session);
    gpu_hash::shutdown().unwrap();
    for bytes in encoded {
        let mut proof = codec::decode_node(&bytes).unwrap();
        registry.verify(pin, &proof, &proof.public).unwrap();
        let mut wrong = proof.public;
        wrong[programs::COUNT] += Val::ONE;
        assert!(registry.verify(pin, &proof, &wrong).is_err());
        proof.public[programs::COUNT] = Val::ONE;
        recursive::summary_with_modes(&proof.public, N as u64).unwrap();
        assert!(registry.verify(pin, &proof, &proof.public).is_err());
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_five_key_empty_proofs_use_statements_and_verify_after_shutdown() {
    typed_empty_proofs::<5>();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_six_key_empty_proofs_use_statements_and_verify_after_shutdown() {
    typed_empty_proofs::<6>();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_twelve_key_empty_proofs_use_statements_and_verify_after_shutdown() {
    typed_empty_proofs::<12>();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires selected OpenCL witness backend and <=3 GiB zero-swap service"]
fn gpu_statement_worker_admission_precedes_hashing_and_preserves_host_summary() {
    use crate::block_v2::{gpu_hash, machine::gpu_backend::resources::Bounds};
    let _shutdown = gpu_hash::TestShutdownGuard;
    initialize();
    let b = Bounds {
        rows: 16,
        main_columns: 98,
        preprocessing_columns: 200,
        metadata_bytes: 65536,
        compiler_host_bytes: 262144,
        compiler_retained_host_bytes: 0,
        pcs_retained_host_bytes: 0,
        program_host_bytes: 1048576,
        program_retained_host_bytes: 0,
        wires: 4096,
        input_values: 64,
    };
    let valid = serde_json::json!({
        "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
        "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
        "witness_bounds":b,"witness_reservation":b.reservation(1).unwrap(),
        "owned_quotient_reservation":{"managed_bytes":67108864},
        "gpu":{"version":1,"managed_bytes":268435456,"max_allocation_bytes":67108864},
        "host":{"worker_bytes":1073741824}
    });
    struct Assignment(std::path::PathBuf, Option<std::ffi::OsString>);
    impl Drop for Assignment {
        fn drop(&mut self) {
            if let Some(value) = &self.1 {
                std::env::set_var("LATTICA_V2_WORKER_BUDGET", value);
            } else {
                std::env::remove_var("LATTICA_V2_WORKER_BUDGET");
            }
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "lattica-statement-budget-{}.json",
        std::process::id()
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let assignment = Assignment(path, std::env::var_os("LATTICA_V2_WORKER_BUDGET"));
    std::env::set_var("LATTICA_V2_WORKER_BUDGET", &assignment.0);
    let public = programs::statement(
        commitment::empty_subtree(context(), 2).unwrap(),
        programs::EMPTY,
    );
    let baseline = gpu_hash::report("statement worker before admission").unwrap();
    for case in 0..4 {
        let mut bad = valid.clone();
        match case {
            0 => bad["gpu_witness"] = false.into(),
            1 => bad["witness_reservation"]["managed_bytes"] = 1.into(),
            2 => bad["witness_bounds"]["extra"] = 1.into(),
            _ => bad["gpu"]["max_allocation_bytes"] = 1024.into(),
        }
        std::fs::write(&assignment.0, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(
            derive(|_| -> Result<(), Error> { panic!("must reject before derivation") }).is_err()
        );
        // CPU host acceptance does not consult GPU flags or a worker assignment.
        assert!(compile(2048, 3, |_| -> Result<(), Error> {
            panic!("must reject before registry compilation")
        })
        .is_err());
        recursive::summary(&public).unwrap();
        let caps: programs::Caps =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        programs::profile_id(2048, &caps).unwrap();
        let after = gpu_hash::report("statement worker rejected").unwrap();
        assert_eq!(after.allocations, baseline.allocations);
        assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
    }
    std::fs::write(&assignment.0, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert_eq!(
        derive(|hash| hash.summary(&public, 3)).unwrap(),
        recursive::summary(&public).unwrap()
    );
}
