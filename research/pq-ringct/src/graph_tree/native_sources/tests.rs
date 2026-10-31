use super::*;
use crate::rust_verify::{Proof, Statement, committed_backend};
use super::super::tests::{context, singles};
use lattica_prover_p3::ringct_research_quota::WorkerAllowance;

fn with_sources(body: impl FnOnce(&Plan, &UnprovedRelationGraph, &GraphContext, &SourceFactory<'_>)) {
    let native = crate::native::generate_fixture_with_setup_seed([73; 32], [91; 32], 4,
        crate::native::FixtureAmounts { input: [19, 31], output: [23, 27] }).unwrap();
    let graph = committed_backend::lower_unproved([91; 32], &[73; 32],
        &Statement::decode(&native.statement).unwrap(), &Proof::decode(&native.proof).unwrap()).unwrap();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &native.statement);
    let factory = SourceFactory::new(&plan, &graph, &context,
        &native.statement, &native.proof, 8 << 30).unwrap();
    body(&plan, &graph, &context, &factory);
}

#[test]
fn source_leaf_rejects_wrong_family_reordering_and_missing_norms() {
    with_sources(|_, graph, context, factory| {
        for kind in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof] {
            let mut plan = Plan::from_trusted_graph(graph, singles(graph)).unwrap();
            let ordinal = if kind == GraphSourceKind::Statement { 1 } else { 2 };
            NativeSourceBlueprint::new(&plan, graph, context, factory, kind).unwrap();
            Arc::get_mut(&mut plan.0).unwrap().leaves[ordinal].kind = LeafKind::FixedSources;
            assert!(matches!(NativeSourceBlueprint::new(&plan, graph, context, factory, kind),
                Err(NativeSourceFailure::Coverage)));
            let leaf = &mut Arc::get_mut(&mut plan.0).unwrap().leaves[ordinal];
            leaf.kind = if kind == GraphSourceKind::Statement { LeafKind::Statement } else { LeafKind::PrivateProof };
            leaf.polynomials.swap(0, 1);
            assert!(matches!(NativeSourceBlueprint::new(&plan, graph, context, factory, kind),
                Err(NativeSourceFailure::Coverage)));
            let leaf = &mut Arc::get_mut(&mut plan.0).unwrap().leaves[ordinal];
            leaf.polynomials.swap(0, 1);
            leaf.bytes.pop();
            assert!(matches!(NativeSourceBlueprint::new(&plan, graph, context, factory, kind),
                Err(NativeSourceFailure::Coverage)));
        }
        let mut plan = Plan::from_trusted_graph(graph, singles(graph)).unwrap();
        Arc::get_mut(&mut plan.0).unwrap().leaves[2].operations.pop();
        assert!(matches!(NativeSourceBlueprint::new(&plan, graph, context, factory, GraphSourceKind::PrivateProof),
            Err(NativeSourceFailure::Coverage)));
    });
}

#[test]
fn source_planner_refuses_foreign_or_short_originals_before_recording() {
    with_sources(|plan, graph, context, factory| {
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        let other = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        for kind in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof] {
            let blueprint = NativeSourceBlueprint::new(plan, graph, context, factory, kind).unwrap();
            let needed = blueprint.planning_requirements().get(Category::PhaseScratch).host;
            let short = ledger.admit_phase(Requirements::single(Category::PhaseScratch,
                Bytes { host: needed - 1, device: 0 })).unwrap();
            let foreign = other.admit_phase(blueprint.planning_requirements()).unwrap();
            assert!(matches!(blueprint.inspect(&short, &ledger), Err(NativeSourceFailure::Authority)));
            assert!(matches!(blueprint.inspect(&foreign, &ledger), Err(NativeSourceFailure::Authority)));
            drop(short); drop(foreign);
        }
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(other.snapshot().current, Bytes::ZERO);
    });
}

#[test]
#[ignore = "large source compiler comparison; coordinator serial release guard required"]
fn bounded_source_joins_match_legacy_verifier_and_exact_coverage() {
    use crate::component_tree::shape_diagnostic::invalid_native_template;
    use lattica_prover_p3::block_v2::native_graph_source_proof::{NativeStatementProof, NativePrivateProof};
    with_sources(|plan, graph, context, factory| {
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        for kind in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof] {
            let blueprint = NativeSourceBlueprint::new(plan, graph, context, factory, kind).unwrap();
            let original = ledger.admit_phase(blueprint.planning_requirements()).unwrap();
            let compiled = blueprint.inspect(&original, &ledger).unwrap();
            drop(original);
            let (artifact, legacy) = match kind {
                GraphSourceKind::Statement => {
                    let proof = invalid_native_template(&crate::statement_air::StatementAir {
                        setup_seed: graph.setup_seed() }, crate::statement_air::HEIGHT);
                    let old = crate::statement_air::bundle::StatementProof {
                        proof, public_values: [Val::ZERO; 8] };
                    let node = compile_leaf(plan, graph, 1, context, LeafArtifact::Statement(&old)).unwrap();
                    (NativeGraphSourceProof::Statement(NativeStatementProof { proof: old.proof,
                        public_values: old.public_values }), node)
                }
                GraphSourceKind::PrivateProof => {
                    let proof = invalid_native_template(&crate::proof_air::ProofAir, crate::proof_air::HEIGHT);
                    let old = crate::proof_air::join::ProofArtifact {
                        proof, public_values: [Val::ZERO; 4] };
                    let node = compile_leaf(plan, graph, 2, context, LeafArtifact::PrivateProof(&old)).unwrap();
                    (NativeGraphSourceProof::PrivateProof(NativePrivateProof { proof: old.proof,
                        public_values: old.public_values }), node)
                }
            };
            // This test deliberately exercises raw compiler relations only.
            // An invalid template never becomes a VerifiedSourceProof owner.
            let spec = Spec { plan: Arc::clone(&plan.0), first: blueprint.ordinal as u32, count: 1, level: 0 };
            let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, construction()).unwrap();
            let public = public_wires(&mut builder, &spec).unwrap();
            let mut inputs = ProofInputs::default();
            let mut session = SourceBinding::new(&plan.0.shape, graph, &mut builder, &mut inputs,
                public[CONTEXT..CONTEXT + 8].try_into().unwrap(),
                public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
                public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap()).unwrap();
            match &artifact {
                NativeGraphSourceProof::Statement(value) => session.verify_statement_owned(value).unwrap(),
                NativeGraphSourceProof::PrivateProof(value) => session.verify_private_owned(value).unwrap(),
            }
            let leaf = &plan.leaves()[blueprint.ordinal];
            session.require_exact_coverage(leaf.polynomial_indices(), leaf.byte_indices(), leaf.operation_indices()).unwrap();
            let bounded = CompiledNode { spec: spec.clone(), program: Arc::new(builder.finish(None).unwrap()),
                public: header(&spec, context), witness: inputs.values };
            compiled.facts.check(&bounded).unwrap();
            assert_eq!(bounded.program.manifest_fields(), legacy.program.manifest_fields());
            assert_eq!(bounded.public, legacy.public);
            assert_eq!(bounded.witness, legacy.witness);
            assert!(!bounded.spec.complete());
        }
    });
}

#[test]
fn compiled_source_retains_original_until_payload_destruction() {
    with_sources(|plan, graph, context, factory| {
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        let blueprint = NativeSourceBlueprint::new(plan, graph, context, factory,
            GraphSourceKind::Statement).unwrap();
        let requirement = blueprint.compiler_requirements().0;
        // This private fixture exercises owner destruction only. It does not
        // produce a verified native proof or enter a workflow phase.
        let fixture = |original| {
            let spec = Spec { plan: Arc::clone(&plan.0), first: 1, count: 1, level: 0 };
            let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, construction()).unwrap();
            public_wires(&mut builder, &spec).unwrap();
            let _secret = builder.input();
            let program = Arc::new(builder.finish(None).unwrap());
            let facts = NativeSourceFacts { operations: OperationCounts::from_program(&program),
                maximum_active_rows: program.active_rows(), maximum_padded_rows: program.height(),
                maximum_wires: program.wire_count(), input_values: program.witness_values(),
                selection_hint_words: selection_hint_words(&program).unwrap() };
            OwnedCompiledSource { node: Some(CompiledNode { spec: spec.clone(), program,
                public: header(&spec, context), witness: vec![Val::ONE] }),
                blueprint: &blueprint, facts, compile_ns: 7, output: Some(original) }
        };
        let held = ledger.admit_phase(requirement).unwrap();
        let charged = ledger.snapshot().current;
        let output = fixture(held);
        assert_eq!(output.reservation().requirements(), requirement);
        assert_eq!(output.compile_ns(), 7);
        assert_eq!(ledger.snapshot().current, charged);
        let returned = output.destroy_into_original();
        assert!(returned.belongs_to(&ledger));
        assert_eq!(returned.requirements(), requirement);
        assert_eq!(ledger.snapshot().current, charged);
        drop(returned);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        drop(fixture(ledger.admit_phase(requirement).unwrap()));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    });
}
