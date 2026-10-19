//! Full-size registered interface qualification against an independently approved
//! public cap. The controller must supply approved-cap.postcard from a successful
//! CPU preprocessing audit, never from this attempt's generated commitment.
use super::*;
use crate::cuda_compute::RegisteredKey;

#[test]
#[ignore = "large registered recursion; independently approved cap and bounded serial CUDA service"]
fn cuda_recursive_registered_wallet_produces_authenticated_outer_proof() {
    let path = directory().join("approved-cap.postcard");
    assert!(
        std::fs::metadata(path).unwrap().len() <= (super::super::CAP_BYTES / 8 * 10 + 16) as u64
    );
    let approved: Cap = read("approved-cap.postcard");
    let started = Instant::now();
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: MANAGED,
            max_allocation_bytes: ALLOCATION,
            ..Limits::default()
        },
    )
    .unwrap();
    let (proof, public) = inner(&runtime);
    assert_eq!(runtime.snapshot().modules, 0);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    write("inner.postcard", &proof);
    write("public.postcard", &public);
    let (air, witness) = compile(&proof, public.len());
    let public: Vec<_> = public.iter().map(PrimeField64::as_canonical_u64).collect();
    let witness: Vec<_> = witness.iter().map(PrimeField64::as_canonical_u64).collect();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    for stage in Stage::ARITHMETIC {
        capabilities.set(stage, Backend::Cuda);
    }
    let run = Run::request(
        "cuda_recursive_registered_wallet_verifier",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
        &[
            ("preprocessing", CoverageScope::Preprocessing),
            ("proof", CoverageScope::RegisteredProof),
        ],
    )
    .unwrap();
    let before = runtime.snapshot();
    let calls = crate::proving::cpu_witness_oracle_calls();
    let preparation = Instant::now();
    let (prepared, setup_report) = engine
        .prepare_registered_in_run(
            &air,
            RegisteredKey {
                profile: Profile::BlockV2Cubic,
                height: 262_144,
                public_values: ContextJoinSplitAir.num_public_values(),
                witness_values: 88_371,
                cap: approved.roots(),
            },
            run.child(
                "preprocessing",
                "cuda_registered_preprocessing",
                BatchStarks::preprocessing_capabilities(),
            )
            .unwrap(),
            HOST,
            Specialization::Prefer,
        )
        .unwrap();
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_PREPARED {}",
        serde_json::json!({"seconds": preparation.elapsed().as_secs_f64(), "snapshot": runtime.snapshot()})
    );
    eprintln!(
        "LATTICA_CUDA_REGISTERED_PREPARATION_REPORT {}",
        serde_json::to_string(&setup_report).unwrap()
    );
    assert!(setup_report.stage_coverage_complete && setup_report.succeeded);
    let cap = prepared.preprocessing_cap().unwrap();
    assert_eq!(cap, approved);
    let proving = Instant::now();
    let output = prepared
        .prove_in_run(
            MachineInputs {
                public: &public,
                witness: &witness,
            },
            run.child(
                "proof",
                "cuda_registered_proof",
                prepared.proof_capabilities(),
            )
            .unwrap(),
            HOST,
        )
        .unwrap();
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_PROVED {}",
        serde_json::json!({"seconds": proving.elapsed().as_secs_f64(), "snapshot": runtime.snapshot()})
    );
    eprintln!(
        "LATTICA_CUDA_REGISTERED_PROOF_REPORT {}",
        serde_json::to_string(&output.report).unwrap()
    );
    assert!(output.report.stage_coverage_complete && output.report.succeeded);
    let outer = output.proof;
    drop(prepared);
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), calls);
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete && report.succeeded);
    assert_eq!(report.observations.len(), 16);
    assert_eq!(report.components.len(), 2);
    assert!(report
        .components
        .iter()
        .all(|c| c.succeeded && c.stage_coverage_complete && !c.cached));
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    assert_eq!(
        runtime.snapshot().public_program_bytes,
        before.public_program_bytes
    );
    write("outer.postcard", &outer);
    write("candidate-cap.postcard", &cap);
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_PRODUCER {}",
        serde_json::json!({
            "seconds": started.elapsed().as_secs_f64(), "report": report,
            "snapshot": runtime.snapshot(), "identity": runtime.identity(),
            "managed_bytes": MANAGED, "max_allocation_bytes": ALLOCATION,
            "host_allowance": HOST, "approved_cap_matched": true, "independent_cpu_audit_pending": true,
        })
    );
}
