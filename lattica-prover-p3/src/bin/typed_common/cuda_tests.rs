use super::*;
use serde_json::json;

fn assignment() -> Value {
    json!({"backend":"cuda", "workload_kind":WORKLOAD, "typed_ram_admission":"owned",
        "qualification_capacity_test":true, "host":{"worker_bytes":3u64 << 30},
        "pool_job_limit":4, "startup_guard":"/tmp/cuda-cli-startup"})
}

#[test]
fn cli_requires_explicit_cuda_workload_and_a_fenced_bounded_service() {
    let valid = assignment();
    assert_eq!(validate_owned_assignment(&valid, 3 << 30).is_ok(), PAIRED);
    assert!(validate_owned_assignment(&valid, 4 << 30).is_err());
    for (pointer, value) in [
        ("/backend", Value::Null),
        ("/backend", json!("opencl")),
        (
            "/workload_kind",
            json!("typed-paired-owned-depth-six-bootstrap-v1"),
        ),
        ("/typed_ram_admission", json!("compact")),
        ("/qualification_capacity_test", json!(1)),
        ("/pool_job_limit", json!(0)),
        ("/pool_job_limit", json!(16385)),
        ("/pool_job_limit", json!(true)),
        ("/startup_guard", json!("relative")),
        ("/startup_guard", Value::Null),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_owned_assignment(&changed, 3 << 30).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn cli_rejects_legacy_commands_and_active_opencl_tuning() {
    let args = |verb: &str| {
        vec![
            "probe",
            verb,
            "/fixture",
            "/expected",
            "/launches",
            "3221225472",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    };
    assert_eq!(
        command(&args("serve-shared-process-gpu")).is_ok(),
        PAIRED && cfg!(feature = "stream")
    );
    for verb in [
        "register-gpu",
        "prove-gpu",
        "serve-process-gpu",
        "prove-process-gpu",
    ] {
        assert!(command(&args(verb)).is_err());
    }
    for key in [
        "LATTICA_V2_GPU_HASH",
        "LATTICA_V2_GPU_WITNESS",
        "LATTICA_V2_QUOTIENT_FUSION",
    ] {
        assert!(environment_setting(key, "1").is_err());
        assert!(environment_setting(key, "0").is_ok());
    }
    assert!(environment_setting("LATTICA_V2_GPU_CONTEXT_BYTES", "4294967296").is_ok());
    assert!(environment_setting("LATTICA_V2_GPU_MANAGED_BYTES", "7516192768").is_ok());
}

#[test]
fn cuda_telemetry_requires_completed_work_and_all_owners_retired() {
    let empty = CudaSnapshot::default();
    assert!(validate_work(&empty, 0, 4).is_ok());
    assert!(validate_work(&empty, 1, 4).is_err());
    let complete = CudaSnapshot {
        peak_bytes: 8,
        completed_commands: 1,
        uploaded_bytes: 8,
        downloaded_bytes: 8,
        ..empty
    };
    assert!(validate_work(&complete, 4, 4).is_ok());
    assert!(validate_work(&complete, 5, 4).is_err());
    for changed in [
        CudaSnapshot {
            live_bytes: 8,
            ..complete
        },
        CudaSnapshot {
            allocations: 1,
            ..complete
        },
        CudaSnapshot {
            modules: 1,
            ..complete
        },
        CudaSnapshot {
            pending_commands: 1,
            ..complete
        },
        CudaSnapshot {
            public_program_bytes: 8,
            ..complete
        },
        CudaSnapshot {
            public_programs: 1,
            ..complete
        },
    ] {
        assert!(validate_work(&changed, 4, 4).is_err());
    }
}
