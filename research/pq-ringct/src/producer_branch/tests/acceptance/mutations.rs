//! All checks here run only after actual producer and atomic consumer proofs
//! have passed their native verifiers. No invalid template or invented key is
//! used as a positive baseline.
use super::*;
use lattica_prover_p3::block_v2::profile::Challenge;

fn branch_public_and_proof(branch: &mut ProvenBranch) -> usize {
    branch.key.verify(&branch.proof).unwrap();
    assert_eq!(branch.proof.public.len(), PUBLIC_VALUES);
    for index in 0..PUBLIC_VALUES {
        branch.proof.public[index] += Val::ONE;
        assert!(
            branch.key.verify(&branch.proof).is_err(),
            "producer public field {index}"
        );
        branch.proof.public[index] -= Val::ONE;
    }
    for index in 0..4 {
        branch.proof.public.swap(INPUT + index, OUTPUT + index);
    }
    assert!(
        branch.key.verify(&branch.proof).is_err(),
        "producer input/output order"
    );
    for index in 0..4 {
        branch.proof.public.swap(INPUT + index, OUTPUT + index);
    }
    branch.proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    assert!(
        branch.key.verify(&branch.proof).is_err(),
        "corrupted producer opening"
    );
    branch.proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] -= Challenge::ONE;
    branch.key.verify(&branch.proof).unwrap();
    PUBLIC_VALUES
}

fn contract_probe(
    setup: &Setup,
    branch: &ProvenBranch,
    operation: usize,
    role: Role,
    transcript: Option<&TranscriptAir>,
) -> Result<(MachineAir, Vec<Val>)> {
    let mut b = ProgramBuilder::new(0).unwrap();
    let context = ContextWires {
        profile: words(&setup.plan.label()).map(|value| b.constant(value)),
        context: words(&setup.context.context).map(|value| b.constant(value)),
        statement: setup.context.statement.map(|value| b.constant(value)),
    };
    let manifest = setup.context.node_manifest.map(|value| b.constant(value));
    let mut inputs = ProofInputs::default();
    Artifact {
        key: &branch.key,
        proof: &branch.proof,
    }
    .compile_roots(
        &mut b,
        &mut inputs,
        operation,
        role,
        transcript,
        &context,
        &manifest,
    )?;
    Ok((MachineAir::new(b.finish(None).unwrap()), inputs.values))
}

fn branch_contracts(
    setup: &Setup,
    branch: &ProvenBranch,
    transcript: Option<&TranscriptAir>,
) -> usize {
    let operation = branch.key.operation_index();
    let role = branch.key.role();
    let (machine, witness) = contract_probe(setup, branch, operation, role, transcript).unwrap();
    machine.trace(&[], &witness).unwrap();
    drop((machine, witness));
    assert!(contract_probe(setup, branch, operation + 1, role, transcript).is_err());
    let wrong_role = if role == Role::AlphaUniform {
        Role::AlphaSparse
    } else {
        Role::AlphaUniform
    };
    assert!(contract_probe(setup, branch, operation, wrong_role, transcript).is_err());
    if let Some(air) = transcript {
        let mut parts = air.parts().to_vec();
        if let Some(index) = parts.iter().position(|part| *part != parts[0]) {
            parts.swap(0, index);
        } else {
            parts[0] = match parts[0] {
                PartKind::PolynomialQ => PartKind::PolynomialQhat,
                _ => PartKind::PolynomialQ,
            };
        }
        let wrong = TranscriptAir::new(parts).unwrap();
        assert!(contract_probe(setup, branch, operation, role, Some(&wrong)).is_err());
        3
    } else {
        2
    }
}

fn reject_context(
    setup: &Setup,
    ordinal: usize,
    branches: &Branches,
    context: &graph_tree::GraphContext,
) {
    match graph_tree::compile_leaf(
        &setup.plan,
        &setup.graph,
        ordinal,
        context,
        branches.artifact(),
    ) {
        Err(_) => {}
        Ok(compiled) => assert!(
            compiled.evaluate().is_err(),
            "substituted consumer context accepted"
        ),
    }
}

pub(super) fn check(
    setup: &Setup,
    operation: usize,
    ordinal: usize,
    branches: &mut Branches,
    key: &graph_tree::NodeKey,
    proof: &mut graph_tree::NodeProof,
) -> serde_json::Value {
    key.verify(proof).unwrap();
    let (branch_public_fields, typed_contracts, cross_key_checks, role_order_checks) =
        match branches {
            Branches::Alpha { uniform, sparse } => {
                uniform.key.verify(&uniform.proof).unwrap();
                sparse.key.verify(&sparse.proof).unwrap();
                assert!(uniform.key.verify(&sparse.proof).is_err());
                assert!(sparse.key.verify(&uniform.proof).is_err());
                assert!(graph_tree::compile_leaf(
                    &setup.plan,
                    &setup.graph,
                    ordinal,
                    &setup.context,
                    LeafArtifact::ExpandAlphaBranches {
                        uniform: Artifact {
                            key: &sparse.key,
                            proof: &sparse.proof
                        },
                        sparse: Artifact {
                            key: &uniform.key,
                            proof: &uniform.proof
                        },
                    }
                )
                .is_err());
                let contracts =
                    branch_contracts(setup, uniform, None) + branch_contracts(setup, sparse, None);
                let fields = branch_public_and_proof(uniform) + branch_public_and_proof(sparse);
                (fields, contracts, 2, 1)
            }
            Branches::HashX {
                branch, transcript, ..
            } => {
                let contracts = branch_contracts(setup, branch, Some(transcript));
                (branch_public_and_proof(branch), contracts, 0, 0)
            }
        };
    // Re-establish the complete valid atomic-consumer witness before probing
    // expected context joins with the unchanged, accepted producer proofs.
    graph_tree::compile_leaf(
        &setup.plan,
        &setup.graph,
        ordinal,
        &setup.context,
        branches.artifact(),
    )
    .unwrap()
    .evaluate()
    .unwrap();
    for word in 0..8 {
        let mut context = setup.context.clone();
        context.context[4 * word] ^= 1;
        reject_context(setup, ordinal, branches, &context);
    }
    for lane in 0..4 {
        let mut context = setup.context.clone();
        context.statement[lane] += Val::ONE;
        reject_context(setup, ordinal, branches, &context);
        let mut context = setup.context.clone();
        context.node_manifest[lane] += Val::ONE;
        reject_context(setup, ordinal, branches, &context);
    }
    let consumer_fields = proof.public.len();
    assert_eq!(consumer_fields, graph_tree::PUBLIC_VALUES);
    for index in 0..consumer_fields {
        proof.public[index] += Val::ONE;
        assert!(key.verify(proof).is_err(), "consumer public field {index}");
        proof.public[index] -= Val::ONE;
    }
    proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    assert!(
        key.verify(proof).is_err(),
        "corrupted atomic consumer opening"
    );
    proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] -= Challenge::ONE;
    key.verify(proof).unwrap();
    let incomplete = key
        .verify_complete(proof, &setup.context)
        .err()
        .expect("partial graph accepted");
    assert!(incomplete.0.contains("incomplete graph coverage"));
    serde_json::json!({
        "operation": operation,
        "positive_producer_and_consumer_proof_baselines": true,
        "producer_public_fields_rejected": branch_public_fields,
        "producer_input_output_order_swaps_rejected": branches.count(),
        "corrupted_producer_openings_rejected": branches.count(),
        "typed_operation_role_descriptor_contracts_rejected": typed_contracts,
        "distinct_actual_producer_key_substitutions_rejected": cross_key_checks,
        "alpha_branch_role_order_swaps_rejected": role_order_checks,
        "consumer_expected_context_statement_manifest_substitutions_rejected": 16,
        "consumer_public_fields_rejected": consumer_fields,
        "corrupted_consumer_opening_rejected": true,
        "restored_original_proofs_verified": true,
        "incomplete_graph_rejected": true,
        "scope": "Fixed representative mutations of these accepted proofs and compiler contracts; not a security proof or exhaustive mutation analysis.",
    })
}
