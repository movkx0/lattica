use super::*;
use lattica_prover_p3::block_v2::machine::{
    verifier::batch::shape::OperationCounts, OuterSourceEnvelope, OuterSourceShape, ProgramBuilder,
};

#[test]
#[ignore = "exclusive guarded physical GPU selection and host-tree source preissuance; no proofs"]
fn expanded_worker_preissue_keeps_registered_operation_ceiling() {
    let standard = crate::opencl::Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    };
    let expanded = crate::opencl::Limits { host_bytes: 36 << 30, ..standard };

    // Passing the enclosing worker ceiling directly was the N4 refusal.
    // The registered operation's existing limit must continue to reject it.
    assert!(RegisteredGpuLimits::new(expanded.host_bytes, expanded.device_bytes,
        4 << 30, expanded.max_rows).is_err());

    let mut builder = ProgramBuilder::new(28).unwrap();
    let input = builder.input();
    builder.poseidon([input; 8]);
    let program = builder.finish(None).unwrap();
    let shape = OuterSourceShape::registered_graph_bounds(28,
        OperationCounts::from_program(&program), program.wire_count(),
        program.witness_values(), 0).unwrap();
    for limits in [standard, expanded] {
        let registered = registered_operation_limits(limits).unwrap();
        // This source envelope accepts exactly the unchanged 32/8/4 GiB
        // operation/device/context profile and its 8 GiB host-tree allowance.
        let envelope = OuterSourceEnvelope::inspect(shape, registered, 16 << 30).unwrap();
        let pending = envelope.preissue().unwrap();
        pending.check_execution_selection().unwrap();
    }
    for host in [0, (32 << 30) + 1, (36 << 30) + 1, u64::MAX] {
        assert!(registered_operation_limits(crate::opencl::Limits {
            host_bytes: host, ..standard
        }).is_err());
    }
    for device in [0, (8 << 30) + 1] {
        assert!(registered_operation_limits(crate::opencl::Limits {
            device_bytes: device, ..expanded
        }).is_err());
    }
    assert!(registered_operation_limits(crate::opencl::Limits {
        max_rows: 1 << 21, ..expanded
    }).is_err());
}
