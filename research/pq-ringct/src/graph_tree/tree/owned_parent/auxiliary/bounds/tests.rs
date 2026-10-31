use super::*;
use crate::transcript_air::{PartKind, TranscriptAir};
use lattica_prover_p3::block_v2::machine::{ProgramBuilder, verifier::ProofInputs};

/// Exercise the actual pure compiler helper for every auxiliary leaf in the
/// full-screen graph. No PreparedWorkflowSources owner or proof authority is
/// fabricated, and complete case admission remains a separate qualification.
#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "guarded CPU auxiliary compiler-budget regression; no GPU or recursive proving"]
fn full_workflow_first_auxiliary_compiler_census() {
    use crate::{graph_auxiliary::{AuxiliaryFactory, Kind as NativeKind},
        graph_crypto::{Admission, Plan as CryptoPlan, Policy as CryptoPolicy},
        graph_proofs::{GraphProofPlan, ResourceLimits},
        rust_verify::committed_backend::source_binding::RegisteredGraphShape};
    let (graph, statement) = crate::graph_tree::tests::fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits {
        max_batch_count: 64, max_ntt_batch_count: 32, max_mul_batch_count: 32,
        max_trace_cells: 1 << 27, max_estimated_prover_bytes: 24 << 30,
    }).unwrap();
    let tree = crate::graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = crate::graph_tree::tests::context(&tree, &graph, &statement);
    let natives = AuxiliaryFactory::new(&tree, &graph, &context, 24 << 30).unwrap();
    let crypto = CryptoPlan::new(&tree, &graph, CryptoPolicy {
        maximum_aes_blocks: 64, maximum_shake_permutations: 32,
        child_memory_budget_bytes: 24 << 30, admission: Admission::Estimated,
    }).unwrap();
    let fixed = FixedSourceCensus::from_graph(&graph).unwrap();
    let construction = super::super::super::source::construction();
    let cap = super::super::super::source::AUXILIARY_BYTES;
    let mut seen = [false; 4];
    let mut first = None;
    for (ordinal, leaf) in tree.leaves().iter().enumerate() {
        let (kind, label, keys, digests, expected_requests, expected_natives) = match leaf.kind() {
            LeafKind::Operations(OperationFamily::SampleG) =>
                (AuxiliaryGraphKind::SampleG, "sample_g", 1, 0, 1, 1),
            LeafKind::Operations(OperationFamily::ExpandAlpha) =>
                (AuxiliaryGraphKind::ExpandAlpha, "expand_alpha", 2, 0, 2, 2),
            LeafKind::Operations(OperationFamily::HashAlpha) =>
                (AuxiliaryGraphKind::HashAlpha, "hash_alpha", 0, 1, 1, 1),
            LeafKind::Operations(OperationFamily::HashX) =>
                (AuxiliaryGraphKind::HashX, "hash_x", 0, 0, 1, 2),
            _ => continue,
        };
        let [operation] = leaf.operation_indices() else { panic!("one auxiliary operation required"); };
        eprintln!("auxiliary_compiler_census_source leaf={} operation={} kind={}", ordinal, operation, label);
        first.get_or_insert(ordinal);
        seen[kind.tag() as usize] = true;
        let request_count = crypto.requests().iter().filter(|request| request.operation_index() == *operation).count();
        assert_eq!(request_count, expected_requests);
        let mut descriptors = [None; 2];
        let mut native_count = 0;
        let mut transcript_parts = 0;
        let mut native_peak = 0;
        for request in natives.requests().iter().filter(|request| request.operation_index() == *operation) {
            let descriptor = match request.kind() {
                NativeKind::Uniform(kind) => NativeDescriptor::Uniform(kind),
                NativeKind::Sparse(kind) => NativeDescriptor::Sparse(kind),
                NativeKind::Transcript => {
                    let parts = request.transcript_air().unwrap().parts();
                    transcript_parts = parts.len();
                    NativeDescriptor::Transcript(parts)
                }
            };
            assert!(native_count < descriptors.len());
            descriptors[native_count] = Some(descriptor);
            native_count += 1;
            let storage = NativePlanningStorage::for_descriptor(descriptor, construction).unwrap();
            native_peak = native_peak.max(storage.auxiliary_peak_bytes);
        }
        assert_eq!(native_count, expected_natives);
        let shapes = [child_shape(super::super::super::source::MAX_ROWS).unwrap(); 2];
        let request_storage = PlanningStorage::for_children(PUBLIC_VALUES, &shapes[..request_count], construction).unwrap();
        let (cores, input_backing) = core_storage_parts(request_count, descriptors, PUBLIC_VALUES).unwrap();
        assert_eq!(cores, request_storage.auxiliary_peak_bytes.max(native_peak));
        let coverage = sum([graph.polynomials().len(), graph.bytes().len(), graph.operations().len()]).unwrap();
        let group = add(mul(coverage, 2 * size_of::<bool>() + 4 * size_of::<usize>()).unwrap(), bytes::<Vec<usize>>(16).unwrap()).unwrap();
        let byte_count = mul(4, add(mul(keys, 32 + 52 + 20).unwrap(), mul(digests, 64).unwrap()).unwrap()).unwrap();
        let roots = 4 * transcript_parts.max(4);
        let dynamic = sum([group,
            bytes::<lattica_prover_p3::block_v2::machine::pq_bytes::Byte>(byte_count).unwrap(),
            bytes::<u8>(byte_count).unwrap(), bytes::<Wire>(byte_count).unwrap(), bytes::<Val>(byte_count).unwrap(),
            bytes::<[Wire; 4]>(roots).unwrap(), bytes::<Vec<[Wire; 4]>>(16).unwrap(),
            bytes::<Vec<crate::graph_tree::LeafArtifact<'static>>>(8).unwrap(),
            bytes::<crate::graph_tree::LeafArtifact<'static>>(2).unwrap(), frames().unwrap()]).unwrap();
        let auxiliary = sum([cores, fixed.source_scratch_bytes, fixed.frame_bytes, dynamic]).unwrap();
        let (compiled, scratch) = compiler_requirements_from_census(&graph, kind,
            transcript_parts, cores, input_backing, &fixed).unwrap();
        assert!(cores <= cap, "each real core remains inside the unchanged core ceiling");
        assert!(auxiliary > cap, "actual full-screen auxiliary sources reproduce the former combined-cap refusal");
        assert_eq!(scratch, requirement(Category::PhaseScratch, auxiliary).unwrap());
        assert_eq!(compiled.get(Category::SymbolicCompiler), Bytes {
            host: add(super::super::super::source::PROGRAM_BYTES,
                bytes::<OwnedGraphCompiled<'static>>(8).unwrap()).unwrap() as u64, device: 0,
        });
        assert_eq!(compiled.get(Category::CompilerInputs), Bytes {
            host: add(input_backing, bytes::<Val>(2 * PUBLIC_VALUES).unwrap()).unwrap() as u64, device: 0,
        });
        assert!(combine(&[compiled, scratch]).unwrap().total().unwrap().host < 32 << 30);

        // Local core admission is exact; fixed/source/wrapper scratch is still
        // charged additively and cannot borrow any byte from the core ceiling.
        let (edge_compiled, edge_scratch) = compiler_requirements_from_census(&graph, kind,
            transcript_parts, cap, input_backing, &fixed).unwrap();
        assert_eq!(edge_compiled, compiled);
        assert_eq!(edge_scratch, requirement(Category::PhaseScratch,
            add(auxiliary, cap - cores).unwrap()).unwrap());
        assert_eq!(compiler_requirements_from_census(&graph, kind, transcript_parts,
            cap + 1, input_backing, &fixed).unwrap_err(), GraphParentFailure::Capacity);
        let mut overflowing_fixed = fixed;
        overflowing_fixed.source_scratch_bytes = usize::MAX;
        assert_eq!(compiler_requirements_from_census(&graph, kind, transcript_parts,
            cores, input_backing, &overflowing_fixed).unwrap_err(), GraphParentFailure::Overflow);
        overflowing_fixed = fixed;
        overflowing_fixed.frame_bytes = usize::MAX;
        assert_eq!(compiler_requirements_from_census(&graph, kind, transcript_parts,
            cores, input_backing, &overflowing_fixed).unwrap_err(), GraphParentFailure::Overflow);
        assert_eq!(compiler_requirements_from_census(&graph, kind, transcript_parts,
            cores, usize::MAX, &fixed).unwrap_err(), GraphParentFailure::Overflow);
        assert_eq!(compiler_requirements_from_census(&graph, kind, usize::MAX,
            cores, input_backing, &fixed).unwrap_err(), GraphParentFailure::Overflow);
        let planning = construction_scratch(core_storage_parts(request_count, descriptors, 0).unwrap().0)
            .unwrap().total().unwrap().host;
        eprintln!(concat!("auxiliary_compiler_regression leaf={} operation={} kind={} requests={} natives={} transcript_parts={} ",
            "request_auxiliary={} native_auxiliary={} core_peak={} fixed_source={} fixed_frames={} ",
            "dynamic={} full_auxiliary={} auxiliary_cap={} formerly_over_combined_cap={} compiler_inputs={} ",
            "planning_original={} graph_leaves={} native_fixture_proof=true stark_proof_produced=false ",
            "recursive_proof_produced=false compiler_requirement_called=true compiler_ok=true complete_admission=false"),
            ordinal, operation, label, request_count, native_count, transcript_parts,
            request_storage.auxiliary_peak_bytes, native_peak, cores, fixed.source_scratch_bytes,
            fixed.frame_bytes, dynamic, auxiliary, cap, auxiliary > cap, input_backing, planning, tree.leaves().len());
    }
    assert_eq!(first, Some(54), "fixture must reproduce the observed first auxiliary source ordinal");
    assert!(seen.into_iter().all(|present| present), "fixture must cover all four auxiliary families");
    assert_eq!(core_storage_parts(0, [None; 2], PUBLIC_VALUES).unwrap_err(), GraphParentFailure::Source);
    assert_eq!(core_storage_parts(3, [None; 2], PUBLIC_VALUES).unwrap_err(), GraphParentFailure::Source);
}

fn covered(actual: OperationCounts, expected: OperationCounts) {
    assert!(actual.scalar <= expected.scalar);
    assert!(actual.cubic <= expected.cubic);
    assert!(actual.poseidon <= expected.poseidon);
}
#[test]
fn auxiliary_key_census_covers_the_maintained_two_opening_expand_alpha_path() {
    let mut builder = ProgramBuilder::new(4).unwrap();
    let root = core::array::from_fn(|i| builder.public(i).unwrap());
    let mut inputs = ProofInputs::default();
    for descriptor in [crate::aes_air::Descriptor { domain: 0x4368, start_counter: 0, output_len: 2572 },
        crate::aes_air::Descriptor { domain: 0x4368, start_counter: 161, output_len: 127 }] {
        crate::sampler_bridge::bind_key_request(&mut builder, &mut inputs, &root, &[17; 32], descriptor).unwrap();
    }
    let program = builder.finish(None).unwrap();
    // Each maintained call opens all 32 key bytes even for the same key.
    assert_eq!(inputs.values.len(), 64);
    covered(OperationCounts::from_program(&program), joined(key_and_request().unwrap(), key_and_request().unwrap()).unwrap());
    assert_eq!(extra_inputs(AuxiliaryGraphKind::ExpandAlpha), 64 + 8);
}
#[test]
fn auxiliary_transcript_census_covers_ordered_reference_bundle_and_maximum_parts() {
    for parts in [vec![PartKind::Bytes32], vec![PartKind::Bytes32, PartKind::PolynomialQ, PartKind::PolynomialQhat],
        (0..256).map(|i| if i % 2 == 0 { PartKind::PolynomialQ } else { PartKind::PolynomialQhat }).collect()] {
        let mut builder = ProgramBuilder::new(4).unwrap();
        let root = core::array::from_fn(|i| builder.public(i).unwrap());
        let air = TranscriptAir::new(parts).unwrap();
        crate::transcript_air::join::bundle_wires(&mut builder, &air, &vec![root; air.parts().len()]).unwrap();
        let program = builder.finish(None).unwrap();
        covered(OperationCounts::from_program(&program), transcript_bundle(air.parts().len()).unwrap());
        assert!(consumer(AuxiliaryGraphKind::HashX, air.parts().len()).is_ok());
    }
    assert!(consumer(AuxiliaryGraphKind::HashX, 0).is_err());
    assert!(consumer(AuxiliaryGraphKind::HashX, 257).is_err());
    assert!(consumer(AuxiliaryGraphKind::HashAlpha, 0).is_err());
    assert!(consumer(AuxiliaryGraphKind::HashAlpha, 257).is_err());
    assert_eq!(REQUEST_PUBLICS, 46);
}
