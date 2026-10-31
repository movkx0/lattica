use super::*;
use lattica_prover_p3::block_v2::machine::{MachineAir, ProgramBuilder};

#[test]
fn exact_byte_domain_bridge_binds_word_order_range_and_every_root_field() {
    let bytes = core::array::from_fn(|i| (7 * i + 13) as u8);
    let mut builder = ProgramBuilder::new(12).unwrap();
    let words = core::array::from_fn(|i| builder.public(i).unwrap());
    let root = core::array::from_fn(|i| builder.public(8 + i).unwrap());
    bind_words(&mut builder, &words, root).unwrap();
    let machine = MachineAir::new(builder.finish(None).unwrap());
    let mut public = native_words(&bytes).to_vec();
    public.extend(commit_bytes(BYTES32_DOMAIN, &bytes));
    machine.trace(&public, &[]).unwrap();
    for index in 0..12 {
        public[index] += Val::ONE;
        assert!(
            machine.trace(&public, &[]).is_err(),
            "unbound public{index}"
        );
        public[index] -= Val::ONE;
    }
    public.swap(0, 1);
    assert!(machine.trace(&public, &[]).is_err());
    public.swap(0, 1);
    public[0] += Val::from_u64(1 << 32);
    assert!(machine.trace(&public, &[]).is_err());
}

#[cfg(feature = "native-matrict")]
fn fixture() -> (Statement, Proof, Vec<u8>, UnprovedRelationGraph) {
    let (statement, proof, bytes) = super::super::tests::fixture();
    let graph = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    (statement, proof, bytes, graph)
}

#[cfg(feature = "native-matrict")]
#[test]
fn registered_shape_and_six_norm_sources_reject_metadata_substitution() {
    let (statement, proof, _, mut graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let alternate_owner = lower_unproved([29; 32], &[72; 32], &statement, &proof).unwrap();
    assert_ne!(alternate_owner.owner, graph.owner);
    assert!(registered.matches(&alternate_owner));
    assert_ne!(
        registered.node_manifest_hint(&graph).unwrap(),
        registered.node_manifest_hint(&alternate_owner).unwrap()
    );
    drop(alternate_owner);
    for (group, &operation_index) in registered.plan.norms.iter().enumerate() {
        let Operation::Norm { inputs, maximum } = &graph.operations[operation_index] else {
            unreachable!()
        };
        let (first, end, limit) = proof_air::NORMS[group];
        assert_eq!(*maximum, proof_air::NORM_LIMITS[limit]);
        assert_eq!(
            inputs.iter().map(|id| id.index()).collect::<Vec<_>>(),
            registered.plan.proof[first..end]
        );
    }
    let norm = registered.plan.norms[0];
    let original = graph.operations[norm].clone();
    let Operation::Norm { maximum, .. } = &mut graph.operations[norm] else {
        unreachable!()
    };
    *maximum += 1;
    assert!(SourcePlan::from_graph(&graph).is_err());
    assert!(!registered.matches(&graph));
    graph.operations[norm] = original.clone();
    let Operation::Norm { inputs, .. } = &mut graph.operations[norm] else {
        unreachable!()
    };
    inputs.swap(0, 1);
    assert!(SourcePlan::from_graph(&graph).is_err());
    assert!(!registered.matches(&graph));
    graph.operations[norm] = original;
    let duplicate = graph.operations[norm].clone();
    graph.operations.push(duplicate);
    assert!(SourcePlan::from_graph(&graph).is_err());
    assert!(!registered.matches(&graph));
    graph.operations.pop();
    let index = registered.plan.proof[83];
    let kind = graph.polynomials[index].kind;
    graph.polynomials[index].kind = PolynomialKind::Signed { bound: 6212587 };
    assert!(SourcePlan::from_graph(&graph).is_err());
    graph.polynomials[index].kind = kind;
    graph.polynomials[index].expressions.swap(0, 1);
    assert!(!registered.matches(&graph));
    graph.polynomials[index].expressions.swap(0, 1);
    assert!(registered.matches(&graph));
}

#[cfg(feature = "native-matrict")]
#[test]
fn ordered_node_manifest_keeps_unverified_sources_and_operations_pending() {
    let (_, _, bytes, graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let digest =
        crate::recursive_aggregation::LeafStatement::from_bytes([0; 32], [71; 32], &bytes).unwrap();
    let mut public = native_words(&[71; 32]).to_vec();
    public.extend(digest.digest.map(Val::from_u64));
    public.extend(registered.node_manifest_hint(&graph).unwrap());
    let mut builder = ProgramBuilder::new(16).unwrap();
    let context = core::array::from_fn(|i| builder.public(i).unwrap());
    let statement = core::array::from_fn(|i| builder.public(8 + i).unwrap());
    let manifest = core::array::from_fn(|i| builder.public(12 + i).unwrap());
    let mut inputs = ProofInputs::default();
    let binding = SourceBinding::new(
        &registered,
        &graph,
        &mut builder,
        &mut inputs,
        context,
        statement,
        manifest,
    )
    .unwrap();
    assert_eq!(
        binding.remaining(),
        Remaining {
            polynomial_nodes: 1770,
            byte_nodes: 6,
            operations: 1311
        }
    );
    assert!(binding.require_complete().is_err());
    let machine = MachineAir::new(builder.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for index in [0, 4 * 1770, inputs.values.len() - 1] {
        inputs.values[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        inputs.values[index] -= Val::ONE;
    }
    for index in [0, 12, 15] {
        public[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[index] -= Val::ONE;
    }
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "two actual source STARKs and full recursive source/inventory join; reserve8GiB"]
fn actual_source_proofs_bind_inventory_and_exact_six_norms_without_accepting_spend() {
    use lattica_prover_p3::block_v2::profile;
    let (_, proof, bytes, mut graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let statement_air = statement_air::StatementAir {
        setup_seed: [29; 32],
    };
    let statement_witness = statement_air.generate(&bytes).unwrap();
    let mut public = native_words(&[71; 32]).to_vec();
    public.extend_from_slice(&statement_witness.public_values[..4]);
    public.extend(registered.node_manifest_hint(&graph).unwrap());
    let config = profile::make_config();
    let statement_proof = p3_uni_stark::prove(
        &config,
        &statement_air,
        statement_witness.trace,
        &statement_witness.public_values,
    );
    p3_uni_stark::verify(
        &config,
        &statement_air,
        &statement_proof,
        &statement_witness.public_values,
    )
    .unwrap();
    let statement_artifact = statement_air::bundle::StatementProof {
        public_values: statement_witness.public_values,
        proof: statement_proof,
    };
    let private_witness = proof_air::ProofAir
        .generate(&proof_air::ProofValues::from_proof(&proof).unwrap())
        .unwrap();
    let config = profile::make_config();
    let private_proof = p3_uni_stark::prove(
        &config,
        &proof_air::ProofAir,
        private_witness.trace,
        &private_witness.public_values,
    );
    p3_uni_stark::verify(
        &config,
        &proof_air::ProofAir,
        &private_proof,
        &private_witness.public_values,
    )
    .unwrap();
    let private_artifact = proof_air::join::ProofArtifact {
        public_values: private_witness.public_values,
        proof: private_proof,
    };
    let mut builder = ProgramBuilder::new(16).unwrap();
    let context = core::array::from_fn(|i| builder.public(i).unwrap());
    let statement = core::array::from_fn(|i| builder.public(8 + i).unwrap());
    let manifest = core::array::from_fn(|i| builder.public(12 + i).unwrap());
    let mut inputs = ProofInputs::default();
    let mut binding = SourceBinding::new(
        &registered,
        &graph,
        &mut builder,
        &mut inputs,
        context,
        statement,
        manifest,
    )
    .unwrap();
    binding.verify_statement(&statement_artifact).unwrap();
    binding.verify_private_proof(&private_artifact).unwrap();
    assert!(binding.verify_statement(&statement_artifact).is_err());
    assert!(binding.verify_private_proof(&private_artifact).is_err());
    assert_eq!(
        binding.remaining(),
        Remaining {
            polynomial_nodes: 1481,
            byte_nodes: 3,
            operations: 1305
        }
    );
    assert!(binding.require_complete().is_err());
    let program = builder.finish(None).unwrap();
    eprintln!(
        "full_source_inventory_rows={} padded={} wires={}",
        program.active_rows(),
        program.height(),
        program.wire_count()
    );
    let machine = MachineAir::new(program);
    machine.trace(&public, &inputs.values).unwrap();
    for index in [0, 8, 12] {
        public[index] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[index] -= Val::ONE;
    }
    // Update the public inventory to agree with the changed source root. The
    // source proof itself must still reject, independently of manifest equality.
    for index in [registered.plan.statement[0], registered.plan.proof[0]] {
        graph.polynomials[index].commitment[0] += Val::ONE;
        inputs.values[4 * index] += Val::ONE;
        public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
        assert!(machine.trace(&public, &inputs.values).is_err());
        graph.polynomials[index].commitment[0] -= Val::ONE;
        inputs.values[4 * index] -= Val::ONE;
    }
    let alpha = registered.plan.alpha;
    graph.bytes[alpha].commitment[0] += Val::ONE;
    inputs.values[4 * (graph.polynomials.len() + alpha)] += Val::ONE;
    public[12..].copy_from_slice(&registered.node_manifest_hint(&graph).unwrap());
    assert!(machine.trace(&public, &inputs.values).is_err());
}
