//! CPU reference-fixture metadata checks; no GPU, STARK, or recursive proving.
use super::*;
use crate::graph_proofs::{ComponentKind, GraphProofPlan, ResourceLimits};
use crate::graph_tree::mul_sources::{MulLeafBlueprint, MulLeafFailure};
use crate::rust_verify::{committed_backend::source_binding::RegisteredGraphShape, Q, QHAT};
use lattica_prover_p3::block_v2::native_gpu::mul_preparation::MulDescriptor;
use p3_air::BaseAir;

fn family(kind: &ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Affine { .. } => "affine",
        ComponentKind::Ntt { .. } => "ntt",
        ComponentKind::Mul { .. } => "mul",
        ComponentKind::GBound { .. } => "g_bound",
        ComponentKind::Permutation { .. } => "permutation",
        ComponentKind::LinearMap { .. } => "linear_map",
        ComponentKind::External => "external",
    }
}

#[test]
#[ignore = "guarded complete reference graph metadata regression"]
fn full_workflow_native_metadata_budget_regression() {
    let (graph, _) = super::super::tests::fixture();
    let fixed = FixedSourceCensus::from_graph(&graph).unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(&registered, &graph, ResourceLimits {
        max_batch_count: 64, max_ntt_batch_count: 32, max_mul_batch_count: 32,
        max_trace_cells: 1 << 27, max_estimated_prover_bytes: 24 << 30,
    }).unwrap();
    let fixed_bytes = fixed.source_scratch_bytes.checked_add(fixed.frame_bytes).unwrap();
    let mut ntt_reproduced = false;
    let mut mul_reproduced = false;
    let mut families = [false; 6];
    for batch in plan.batches() {
        if matches!(batch.kind(), ComponentKind::External) { continue; }
        let count = batch.operation_indices().len();
        let storage = OtherNativeDescriptor::Algebra { kind: batch.kind(), count }
            .storage(construction()).unwrap();
        assert!(storage.auxiliary_peak_bytes <= NATIVE_AUXILIARY_BYTES);
        let subtotal = storage.auxiliary_peak_bytes.checked_add(fixed_bytes).unwrap();
        let scratch = match batch.kind() {
            ComponentKind::Ntt { modulus } => {
                families[1] = true;
                ntt_reproduced |= count == 32 && subtotal > NATIVE_AUXILIARY_BYTES;
                Some(NttLeafBlueprint::source_requirements(
                    NttDescriptor::new(*modulus, count).unwrap(), &storage, &fixed).unwrap().2)
            }
            ComponentKind::Mul { modulus } => {
                families[2] = true;
                mul_reproduced |= count == 32 && subtotal > NATIVE_AUXILIARY_BYTES;
                Some(MulLeafBlueprint::source_requirements(
                    MulDescriptor::new(*modulus, count).unwrap(), &storage, &fixed).unwrap().2)
            }
            other => {
                families[match other {
                    ComponentKind::Affine { .. } => 0,
                    ComponentKind::GBound { .. } => 3,
                    ComponentKind::Permutation { .. } => 4,
                    ComponentKind::LinearMap { .. } => 5,
                    _ => unreachable!(),
                }] = true;
                // Adjacent unchanged families retain their combined ceiling.
                assert!(subtotal <= NATIVE_AUXILIARY_BYTES);
                None
            }
        };
        let full_scratch = scratch.map(|required| {
            let bytes = required.get(Category::PhaseScratch);
            assert_eq!(required.total().unwrap(), bytes);
            assert_eq!(bytes.device, 0);
            assert!(bytes.host > subtotal as u64, "wrapper storage remains additive");
            assert!(bytes.host < 32 << 30, "unchanged whole-worker host ceiling");
            bytes.host
        });
        eprintln!("native_metadata_actual family={} count={} native_auxiliary={} fixed_source={} subtotal={} full_scratch={:?} native_cap={}",
            family(batch.kind()), count, storage.auxiliary_peak_bytes, fixed_bytes, subtotal,
            full_scratch, NATIVE_AUXILIARY_BYTES);
    }
    assert!(families.into_iter().all(|seen| seen));
    assert!(ntt_reproduced && mul_reproduced, "actual full-screen batches reproduce the former combined-cap refusal");

    // The source descriptors also admit non-power-of-two counts. Exercise each
    // legal count for both moduli and compare against the real AIR definitions.
    for modulus in [Q, QHAT] {
        for count in 1..=crate::graph_proofs::owned_ntt::verification_memory::MAX_VERIFIER_COUNT {
            let descriptor = NttDescriptor::new(modulus, count).unwrap();
            let air = crate::ntt_air::NttAir::new(modulus, count).unwrap();
            assert_eq!((air.height, air.width(), air.num_public_values(), air.num_periodic_columns()),
                descriptor.geometry_tuple());
            assert_eq!(air.max_constraint_degree(), None);
            let kind = ComponentKind::Ntt { modulus };
            let storage = OtherNativeDescriptor::Algebra { kind: &kind, count }.storage(construction()).unwrap();
            let (_, _, scratch) = NttLeafBlueprint::source_requirements(descriptor, &storage, &fixed).unwrap();
            assert!(scratch.get(Category::PhaseScratch).host > (storage.auxiliary_peak_bytes + fixed_bytes) as u64);
            eprintln!("native_metadata_ntt modulus={} count={} native_auxiliary={} full_scratch={}",
                modulus, count, storage.auxiliary_peak_bytes, scratch.get(Category::PhaseScratch).host);
        }
        for count in 1..=crate::graph_proofs::owned_mul::verification_memory::MAX_VERIFIER_COUNT {
            let descriptor = MulDescriptor::new(modulus, count).unwrap();
            let air = crate::poly_air::MulAir::new(modulus, count).unwrap();
            assert_eq!((air.height, air.width(), air.num_public_values(), air.num_periodic_columns()),
                descriptor.geometry_tuple());
            assert_eq!(air.max_constraint_degree(), None);
            let kind = ComponentKind::Mul { modulus };
            let storage = OtherNativeDescriptor::Algebra { kind: &kind, count }.storage(construction()).unwrap();
            let (_, _, scratch) = MulLeafBlueprint::source_requirements(descriptor, &storage, &fixed).unwrap();
            assert!(scratch.get(Category::PhaseScratch).host > (storage.auxiliary_peak_bytes + fixed_bytes) as u64);
            eprintln!("native_metadata_mul modulus={} count={} native_auxiliary={} full_scratch={}",
                modulus, count, storage.auxiliary_peak_bytes, scratch.get(Category::PhaseScratch).host);
        }
        for kind in [ComponentKind::Ntt { modulus }, ComponentKind::Mul { modulus }] {
            assert!(OtherNativeDescriptor::Algebra { kind: &kind, count: 33 }.storage(construction()).is_err());
        }
    }

    // Deliberate test-only census mutations probe the exact local cap and
    // arithmetic boundary. No ledger original or compiler permit is created.
    let ntt = NttDescriptor::new(Q, 1).unwrap();
    let ntt_kind = ComponentKind::Ntt { modulus: Q };
    let mut ntt_storage = OtherNativeDescriptor::Algebra { kind: &ntt_kind, count: 1 }.storage(construction()).unwrap();
    ntt_storage.auxiliary_peak_bytes = NATIVE_AUXILIARY_BYTES;
    ntt_storage.total_requested_bytes = PROGRAM_BYTES + ntt_storage.auxiliary_peak_bytes;
    assert!(NttLeafBlueprint::source_requirements(ntt, &ntt_storage, &fixed).is_ok());
    ntt_storage.auxiliary_peak_bytes += 1;
    ntt_storage.total_requested_bytes += 1;
    assert!(matches!(NttLeafBlueprint::source_requirements(ntt, &ntt_storage, &fixed), Err(NttLeafFailure::Resource)));
    let mul = MulDescriptor::new(Q, 1).unwrap();
    let mul_kind = ComponentKind::Mul { modulus: Q };
    let mut mul_storage = OtherNativeDescriptor::Algebra { kind: &mul_kind, count: 1 }.storage(construction()).unwrap();
    mul_storage.auxiliary_peak_bytes = NATIVE_AUXILIARY_BYTES;
    mul_storage.total_requested_bytes = PROGRAM_BYTES + mul_storage.auxiliary_peak_bytes;
    assert!(MulLeafBlueprint::source_requirements(mul, &mul_storage, &fixed).is_ok());
    mul_storage.auxiliary_peak_bytes += 1;
    mul_storage.total_requested_bytes += 1;
    assert!(matches!(MulLeafBlueprint::source_requirements(mul, &mul_storage, &fixed), Err(MulLeafFailure::Resource)));
    let mut overflow = fixed;
    overflow.source_scratch_bytes = usize::MAX;
    ntt_storage.auxiliary_peak_bytes = NATIVE_AUXILIARY_BYTES;
    mul_storage.auxiliary_peak_bytes = NATIVE_AUXILIARY_BYTES;
    assert!(NttLeafBlueprint::source_requirements(ntt, &ntt_storage, &overflow).is_err());
    assert!(MulLeafBlueprint::source_requirements(mul, &mul_storage, &overflow).is_err());
}
