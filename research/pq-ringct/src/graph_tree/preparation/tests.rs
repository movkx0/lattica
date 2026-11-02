use super::*;
use crate::{graph_auxiliary::AuxiliaryFactory, graph_sources::SourceFactory,
    graph_proofs::{GraphProofPlan, ResourceLimits}, rust_verify::{committed_backend, Proof, Statement}};

#[test]
#[ignore = "verified public N3 fixture; exclusive admitted GPU bindings and failure parity"]
fn prepared_bindings_match_reference_and_reject_changed_inputs() {
    use sha3::{Digest, Sha3_256};
    let file = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.tools/metadata-fixtures/baseline-n3.bin")).unwrap();
    let expected = [217,152,156,215,129,148,136,190,83,161,91,197,191,196,208,39,191,156,61,190,246,52,158,243,182,180,137,124,201,137,216,203];
    assert_eq!(&file[..17], b"RINGCT-N3-FIX-v1\0");
    assert_eq!(file.len(), 17 + 3 * (64 + crate::native_packet::STATEMENT_BYTES + crate::native_packet::PROOF_BYTES) + 32);
    assert_eq!(&file[file.len()-32..], &expected);
    assert_eq!(Sha3_256::digest(&file[..file.len()-32]).as_slice(), &expected);
    let seed: [u8; 32] = file[17..49].try_into().unwrap();
    let context: [u8; 32] = file[49..81].try_into().unwrap();
    let end = 81 + crate::native_packet::STATEMENT_BYTES;
    let statement = &file[81..end];
    let proof = &file[end..end + crate::native_packet::PROOF_BYTES];
    assert!(crate::native::verify(&context, statement, proof).unwrap());
    // Independent CPU references are test setup, never preparation fallbacks.
    let graph = committed_backend::lower_unproved(seed, &context,
        &Statement::decode(statement).unwrap(), &Proof::decode(proof).unwrap()).unwrap();
    let registered = committed_backend::source_binding::RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let tree = Plan::from_registered_graph(&graph, algebra.operation_batches(), registered).unwrap();
    let structure = committed_backend::source_binding::prepared::PreparedGraphStructure::new(&graph).unwrap();
    let foreign = committed_backend::source_binding::prepared::PreparedGraphStructure::new(&graph).unwrap();
    let inventory = committed_backend::inventory::inventory(&graph);
    assert_eq!(structure.counts(), inventory.counts());
    assert_eq!(structure.digest(), inventory.shape_sha3_256());
    assert!(structure.shape().matches(&graph));
    let prepared_tree = Plan::from_prepared(&structure, algebra.operation_batches()).unwrap();
    assert_eq!(tree.label(), prepared_tree.label());
    let expected_context = GraphContext { context,
        statement: LeafStatement::from_bytes(tree.label(), context, statement).unwrap().digest.map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap() };
    let expected_source = SourceFactory::new(&tree, &graph, &expected_context, statement, proof, 1 << 30).unwrap();
    let expected_aux = AuxiliaryFactory::new(&tree, &graph, &expected_context, 1 << 30).unwrap();
    let policy = graph_crypto::Policy { maximum_aes_blocks: 64, maximum_shake_permutations: 32,
        child_memory_budget_bytes: 24 << 30, admission: graph_crypto::Admission::Estimated };
    let expected_crypto = graph_crypto::Plan::new(&tree, &graph, policy).unwrap();
    let worker = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30, device_bytes: 8 << 30, max_rows: 4096 }).unwrap();
    let (mut prepared_crypto, _) = worker.with_witness_preparation(8 << 20, |operations| {
        operations.enable_reusable_storage()?;
        let prepared = PreparedStatement::new(prepared_tree.label(), context, statement, operations)?
            .bind_structure(&prepared_tree, &structure)?;
        assert_eq!(prepared.context().statement, expected_context.statement);
        assert_eq!(prepared.context().node_manifest, expected_context.node_manifest);
        assert!(PreparedStatement::new(prepared_tree.label(), context, statement, operations)?
            .bind_structure(&prepared_tree, &foreign).is_err());
        let prepared_algebra = GraphProofPlan::new_prepared_operations(&structure, ResourceLimits::default(), operations, true).unwrap();
        for (i, batch) in prepared_algebra.batches().iter().enumerate() {
            if !matches!(batch.kind(), crate::graph_proofs::ComponentKind::External) {
                assert_eq!(prepared_algebra.cache_key(i).unwrap(), algebra.cache_key(i).unwrap());
            }
        }

        let bindings = PreparedStatement::new(tree.label(), context, statement, operations)?.bind(&tree, &graph)?;
        assert_eq!(bindings.context().statement, expected_context.statement);
        assert_eq!(bindings.context().node_manifest, expected_context.node_manifest);
        SourceFactory::new_prepared(&bindings, proof, 1 << 30).unwrap().assert_preparation_equivalent(&expected_source);
        let mut crypto = bindings.crypto(policy)?;
        crypto.prepare_endpoints(true)?;
        for request in crypto.plan().requests() {
            assert!(request.prepared_endpoint_context(&expected_context).is_err());
        }
        for (a, b) in crypto.plan().requests().iter().zip(expected_crypto.requests()) {
            assert_eq!(a.descriptor(), b.descriptor());
            assert_eq!(a.maximum_segment_units(), b.maximum_segment_units());
            assert_eq!(a.segments().len(), b.segments().len());
            for index in 0..a.segments().len() { assert_eq!(a.cache_key(index).unwrap(), b.cache_key(index).unwrap()); }
        }
        let auxiliary = AuxiliaryFactory::new_prepared(&crypto, 1 << 30).unwrap();
        assert_eq!(auxiliary.requests().len(), expected_aux.requests().len());
        for (a, b) in auxiliary.requests().iter().zip(expected_aux.requests()) {
            assert_eq!(a.operation_index(), b.operation_index()); assert_eq!(a.role(), b.role());
            assert_eq!(a.kind(), b.kind()); assert_eq!(a.expected_public_values(), b.expected_public_values());
            assert_eq!(a.cache_key(), b.cache_key());
        }
        let mut wrong = statement.to_vec(); wrong[32] ^= 1;
        let changed = PreparedStatement::new(tree.label(), context, &wrong, operations)?.bind(&tree, &graph)?;
        assert!(SourceFactory::new_prepared(&changed, proof, 1 << 30).is_err());
        let mut wrong_proof = proof.to_vec(); wrong_proof[0] ^= 1;
        assert!(SourceFactory::new_prepared(&bindings, &wrong_proof, 1 << 30).is_err());
        assert!(PreparedStatement::new(tree.label(), [99; 32], statement, operations)?.bind(&tree, &graph).is_err());
        let batched = GraphProofPlan::new_with_batched_operations(&committed_backend::source_binding::RegisteredGraphShape::from_trusted_graph(&graph).unwrap(), &graph, ResourceLimits::default(), operations).unwrap();
        assert_eq!(batched.batches().len(), algebra.batches().len());
        for (index, batch) in batched.batches().iter().enumerate() {
            if !matches!(batch.kind(), crate::graph_proofs::ComponentKind::External) {
                assert_eq!(batched.cache_key(index).unwrap(), algebra.cache_key(index).unwrap());
            }
        }
        Ok(crypto.into_plan())
    }).unwrap();
    prepared_crypto.publish_endpoint_facts(&expected_context).unwrap();
    assert!(prepared_crypto.publish_endpoint_facts(&expected_context).is_err());
    for (actual, reference) in prepared_crypto.requests().iter().zip(expected_crypto.requests()) {
        let endpoints = actual.prepared_endpoint_context(&expected_context).unwrap().unwrap();
        let expected = reference.endpoint_context_hint(&expected_context);
        assert_eq!(endpoints.input, expected.input); assert_eq!(endpoints.output, expected.output);
        for field in 0..3 {
            let mut changed = expected_context.clone();
            match field { 0 => changed.context[0] ^= 1, 1 => changed.statement[0] += Val::ONE, _ => changed.node_manifest[0] += Val::ONE }
            assert!(actual.prepared_endpoint_context(&changed).is_err());
        }
    }
    let rejected = worker.with_witness_preparation(8 << 20, |operations| {
        operations.enable_reusable_storage()?;
        let bindings = PreparedStatement::new(tree.label(), context, statement, operations)?.bind(&tree, &graph)?;
        assert!(operations.commit_canonical_node(&[crate::rust_verify::Q; 256], crate::rust_verify::Q).is_err());
        assert!(SourceFactory::new_prepared(&bindings, proof, 1 << 30).is_err());
        assert!(bindings.crypto(policy).is_err());
        assert!(crate::producer_branch::Factory::new_prepared(&bindings, &worker).is_err());
        Ok(())
    });
    assert!(rejected.is_err());
    assert_eq!(worker.report()["operations"]["native_gpu_calls"], 0);
    assert_eq!(worker.report()["operations"]["native_cpu_calls"], 0);
}
