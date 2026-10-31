//! Full-relation admission check, run under the serialized research guard.
use lattica_pq_direct_spend_research::{
    ring,
    ring_circuit::{
        compile_with_representation_diagnostics, CompilerCapacityProfile, CompilerMemoryProfile,
        CompilerRepresentation, CompilerWireProfile,
    },
    Context,
};

#[test]
#[ignore = "full relation compiler and complete GPU selection; serialized direct-full/host guard"]
fn full_direct_memory_plan_is_complete_without_dispatch() {
    let context = Context([19; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    let capacity = CompilerCapacityProfile::new(
        CompilerMemoryProfile::Program2GiB,
        CompilerWireProfile::Research16M,
    );
    let relation = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        capacity,
        CompilerRepresentation::FusedTernaryRangesV1,
        capacity.limits().required_host_bytes as usize,
    )
    .unwrap();
    drop(witness);
    assert_eq!(relation.summary().deferred_crypto_obligations, 0);
    let footprint = relation.into_gpu_memory_diagnostic().unwrap();
    assert_eq!(footprint.rows, 524_288);
    assert_eq!(footprint.main_columns, 94);
    assert_eq!(footprint.preprocessing_columns, 200);
    assert!(footprint.host_phase_bound_complete);
    assert!(footprint.device_phase_bound_complete);
    assert!(footprint.requires_consuming_registration);
    assert!(footprint.witness_instructions_retired_before_quotient_required);
    assert_eq!(footprint.host_tree_quota_bytes, 8 << 30);
    assert!(footprint.host_phase_peak_bytes.unwrap() <= 32 << 30);
    assert!(footprint.device_phase_peak_bytes.unwrap() <= 8 << 30);
    assert!(
        footprint.largest_allocation_bytes.unwrap()
            <= footprint.physical_max_allocation_bytes.unwrap()
    );
    println!(
        "{}",
        serde_json::json!({
            "research_diagnostic": "gpu_memory_footprint",
            "cryptographic_proof_started": false,
            "gpu_dispatch_started": false,
            "footprint": footprint,
        })
    );
}
