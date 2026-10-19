use super::*;
use serde_json::{json, Value};

#[cfg(feature = "block-v2-host")]
#[path = "native_worker_cuda_integration_tests.rs"]
mod integration;

fn assignment() -> Value {
    json!({
        "backend": "cuda",
        "cuda": {"version": 1, "program_host_bytes": 1u64 << 30,
                 "wires": 1 << 24, "input_values": 1 << 20},
        "gpu": {"uuid": "GPU-01234567-89ab-cdef-0123-456789abcdef",
                "managed_bytes": 7u64 << 30, "max_allocation_bytes": 1u64 << 30,
                "context_bytes": 4u64 << 30, "headroom_bytes": 1u64 << 30,
                "host_output_bytes": 3u64 << 30},
        "host": {"worker_bytes": 3u64 << 30, "spill_bytes": 1u64 << 30,
                 "coordinator_bytes": 1u64 << 30},
        "cpu": {"rayon_threads": 4}
    })
}

#[test]
fn cuda_assignment_requires_explicit_backend_and_complete_construction_bounds() {
    let valid = assignment();
    let settings = Settings::from_assignment(&valid).unwrap();
    assert_eq!(settings.device.validate().unwrap(), 12usize << 30);
    assert_eq!(settings.session.construction.program_host_bytes, 1 << 30);
    for pointer in [
        "/backend",
        "/cuda",
        "/cuda/version",
        "/cuda/wires",
        "/cuda/input_values",
        "/cuda/program_host_bytes",
        "/gpu/headroom_bytes",
        "/gpu/max_allocation_bytes",
        "/gpu/host_output_bytes",
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(Settings::from_assignment(&changed).is_err(), "{pointer}");
    }
    for backend in ["cpu", "opencl", "metal", "auto"] {
        let mut changed = valid.clone();
        changed["backend"] = json!(backend);
        assert!(Settings::from_assignment(&changed).is_err());
    }
    let mut changed = valid;
    changed["cuda"]["unknown"] = json!(true);
    assert!(Settings::from_assignment(&changed).is_err());
}

#[test]
fn cuda_assignment_reserves_protocol_cache_and_construction_before_device_creation() {
    let valid = assignment();
    for (pointer, value) in [
        ("/cuda/version", json!(2)),
        ("/cuda/input_values", json!(1 << 25)),
        ("/cuda/wires", json!(0)),
        ("/cuda/program_host_bytes", json!(3u64 << 30)),
        ("/gpu/managed_bytes", json!(0)),
        ("/gpu/max_allocation_bytes", json!(8u64 << 30)),
        ("/gpu/context_bytes", json!(3u64 << 30)),
        ("/gpu/headroom_bytes", json!(0)),
        ("/gpu/host_output_bytes", json!(1u64 << 30)),
        ("/gpu/uuid", json!("GPU-invalid")),
        ("/host/worker_bytes", json!(256u64 << 20)),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(Settings::from_assignment(&changed).is_err(), "{pointer}");
    }
    let mut changed = valid;
    changed["preprocessing_cache"] = json!({"entries": 2, "reserve_bytes": 2u64 << 30});
    assert!(Settings::from_assignment(&changed).is_err());
}

#[test]
fn cuda_assignment_changes_are_bound_by_existing_native_protocol_identity() {
    use p3_field::PrimeCharacteristicRing;
    let registry = Registry::<12> {
        height: 8,
        caps: std::array::from_fn(|_| {
            vec![[crate::config::Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]
        }),
    };
    let bootstrap = Bootstrap::new(
        registry.clone(),
        registry.id().unwrap(),
        [9; 32],
        [7; 32],
        PathBuf::from("/tmp/lattica-cuda-test-launches"),
        &PolicyContext::new([8; 32], vec![]).unwrap(),
    )
    .unwrap();
    let valid = assignment();
    let identity = bootstrap.identity(&valid).unwrap();
    for (pointer, value) in [
        ("/backend", json!("opencl")),
        ("/cuda/wires", json!(1 << 23)),
        ("/gpu/managed_bytes", json!(6u64 << 30)),
        ("/gpu/host_output_bytes", json!(2u64 << 30)),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(bootstrap.identity(&changed).unwrap(), identity);
    }
    assert_eq!(
        Bootstrap::decode(&bootstrap.encode().unwrap())
            .unwrap()
            .identity(&valid)
            .unwrap(),
        identity
    );
}
