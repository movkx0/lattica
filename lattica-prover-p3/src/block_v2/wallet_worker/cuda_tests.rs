use super::*;

fn value() -> serde_json::Value {
    serde_json::json!({
        "schema": "lattica-wallet-local-cuda-v1",
        "service": "lattica-wallet-cuda-fixture.service",
        "gpu_uuid": "GPU-00000000-0000-0000-0000-000000000000",
        "host_bytes": 3u64 << 30, "threads": 4,
        "managed_gpu_bytes": 1u64 << 30, "context_gpu_bytes": 4u64 << 30,
        "host_output_bytes": 512u64 << 20,
        "cuda": {"max_allocation_bytes": 1u64 << 30, "headroom_bytes": 1u64 << 30}
    })
}

#[test]
fn cuda_wallet_assignment_requires_backend_and_complete_immutable_resources() {
    let original = value();
    serde_json::from_value::<Budget>(original.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (key, value) in [
        ("schema", serde_json::json!("lattica-wallet-local-gpu-v1")),
        ("service", serde_json::json!("public-worker.service")),
        ("context_gpu_bytes", serde_json::json!(1u64 << 30)),
        ("managed_gpu_bytes", serde_json::json!(0)),
        ("host_output_bytes", serde_json::json!(1)),
        ("threads", serde_json::json!(0)),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(
            serde_json::from_value::<Budget>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("headroom_bytes", 0),
        ("headroom_bytes", (1u64 << 30) - 1),
        ("max_allocation_bytes", 0),
        ("max_allocation_bytes", (1u64 << 30) + 1),
    ] {
        let mut changed = original.clone();
        changed["cuda"][key] = value.into();
        assert!(
            serde_json::from_value::<Budget>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{key}"
        );
    }
    for key in ["cuda", "context_gpu_bytes", "service"] {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<Budget>(changed).is_err());
    }
    let mut changed = original;
    changed["cuda"]["witness"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Budget>(changed).is_err());
}
