use super::*;

#[test]
fn selections_are_exact_and_preserve_original_relation_parameters() {
    assert_eq!(Selection::N3.transactions(), 3);
    assert_eq!(Selection::N4.transactions(), 4);
    assert_eq!(crate::ring::RING_PAIRS, 10);
    assert_eq!(crate::INPUTS, 2);
    assert_eq!(crate::OUTPUTS, 2);
    assert_eq!(crate::VALUE_BITS, 52);
    assert_eq!(CAPACITY.limits().program_byte_limit, 2 << 30);
    assert_eq!(CAPACITY.limits().wire_limit, 1 << 24);
    assert_eq!(construction().max_input_values, 1 << 20);
    assert!(caller_bound_for_tests());
}
fn caller_bound_for_tests() -> bool { bounds::caller_census().is_ok() }

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod complete {
    use super::*;
    use std::{fs::{File, OpenOptions}, path::PathBuf};

    const CONTEXT: Context = Context([0x73; 32]);
    fn fixture_batch(selection: Selection, start: usize) -> (Vec<Statement>, Vec<Witness>) {
        let n = selection.transactions();
        // Admit fixture staging alongside every retained public/private owner
        // before the native parameter/AES allocator can be called.
        let staging = crate::ring_screen::aggregate_fixture_staging_bytes().unwrap();
        let retained = MAX_CHILDREN * (size_of::<Statement>() + size_of::<Witness>()
            + crate::ring::RING_PAIRS * size_of::<[crate::ring::Account; crate::INPUTS]>());
        assert!(staging + retained + (4 << 20) <= HOST_BYTES);
        let mut statements = Vec::new();
        let mut witnesses = Vec::new();
        statements.try_reserve_exact(n).unwrap();
        witnesses.try_reserve_exact(n).unwrap();
        assert_eq!(statements.capacity(), n);
        assert_eq!(witnesses.capacity(), n);
        for case in start..start+n {
            let (statement, witness) = crate::ring_screen::aggregate_fixture(case).unwrap();
            assert_eq!(statement.context, CONTEXT);
            assert_eq!(statement.setup_seed, [7; 32]);
            crate::ring::check_relation(&statement, &witness, CONTEXT).unwrap();
            statements.push(statement);
            witnesses.push(witness);
        }
        (statements, witnesses)
    }

    #[test]
    fn expected_batch_rejects_omission_duplicates_profile_context_seed_and_capacity() {
        let (statements, witnesses) = fixture_batch(Selection::N3, 0);
        drop(witnesses);
        assert!(matches!(ExpectedBatch::new(Selection::N4, CONTEXT, statements.clone()), Err(Error::Geometry)));
        let mut missing = statements.clone(); missing.pop();
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, missing), Err(Error::Geometry)));
        let mut duplicate = statements.clone(); duplicate[1] = duplicate[0].clone();
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, duplicate), Err(Error::DuplicateSpend)));
        let mut serial = statements.clone(); serial[2].serials[0] = serial[0].serials[1];
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, serial), Err(Error::DuplicateSpend)));
        let mut profile = statements.clone(); profile[1].profile = crate::Profile::PrivateNoteDirectV1;
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, profile), Err(Error::Profile)));
        let mut context = statements.clone(); context[1].context.0[0] ^= 1;
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, context), Err(Error::Context)));
        let mut seed = statements.clone(); seed[1].setup_seed[0] ^= 1;
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, seed), Err(Error::Context)));
        let mut capacity = statements.clone(); capacity[1].ring.reserve(100);
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, capacity), Err(Error::ResourceLimit)));
        let mut coefficient = statements.clone(); coefficient[2].output_coins[0][0][0] = crate::ring::Q;
        assert!(matches!(ExpectedBatch::new(Selection::N3, CONTEXT, coefficient), Err(Error::NonCanonical)));
        let expected = ExpectedBatch::new(Selection::N3, CONTEXT, statements.clone()).unwrap();
        let mut reordered = statements; reordered.swap(0, 1);
        assert_ne!(expected.public_binding(), ExpectedBatch::new(Selection::N3, CONTEXT, reordered).unwrap().public_binding());
    }

    #[test]
    fn owned_batch_refuses_invalid_private_domains_before_public_setup() {
        let (statements, mut witnesses) = fixture_batch(Selection::N3, 0);
        witnesses[1].input_values[0] = crate::VALUE_LIMIT;
        let expected = ExpectedBatch::new(Selection::N3, CONTEXT, statements).unwrap();
        assert!(matches!(BatchInput::new(expected, witnesses), Err(Error::Range)));
        let (statements, mut witnesses) = fixture_batch(Selection::N3, 0);
        witnesses[2].spending[0][0][0] = 2;
        let expected = ExpectedBatch::new(Selection::N3, CONTEXT, statements).unwrap();
        assert!(matches!(BatchInput::new(expected, witnesses), Err(Error::NonCanonical)));
    }

    #[derive(Serialize)]
    struct Case {
        selection: Selection,
        fixture_start: usize,
        transactions: usize,
        whole_transaction_proofs: usize,
        recursive_aggregate_proofs: usize,
        independent_cpu_acceptances: usize,
        public_mutation_rejections: usize,
        opening_mutation_rejections: usize,
        setup_ns: u128,
        proving_ns: u128,
        cpu_verification_ns: u128,
        complete_workflow_ns: u128,
    }
    #[derive(Serialize)]
    struct Suite {
        schema: &'static str,
        distinct_transactions: usize,
        cases: [Option<Case>; 2],
        complete_workflow_ns: u128,
        final_artifacts_destroyed: bool,
        faithful_ringct_protocol: bool,
        redesign_2x_gate_passed: bool,
        security_adoption_review_complete: bool,
    }
    fn fresh_file(path: &std::path::Path) -> File {
        OpenOptions::new().write(true).create_new(true).open(path).unwrap()
    }

    #[test]
    #[ignore = "coordinator-only genuine direct N3/N4 workflow; exact fresh output and serialized GPU/process guard required"]
    fn direct_ring_n3_n4_complete_owned_aggregates_roundtrip_and_retire() {
        assert_eq!(std::env::var("LATTICA_DIRECT_RING_AGGREGATE_QUALIFICATION").as_deref(), Ok("1"));
        let root = std::env::var("LATTICA_DIRECT_RING_AGGREGATE_OUTPUT").expect("fresh bounded output required");
        assert!(root.len() <= 384);
        let root = PathBuf::from(root);
        assert!(root.is_absolute());
        assert!(root.components().all(|part| matches!(part, std::path::Component::RootDir | std::path::Component::Normal(_))));
        std::fs::create_dir(&root).unwrap();
        runtime::request().unwrap();
        bounds::caller_census().unwrap();
        let total_started = Instant::now();
        let mut suite = Suite { schema: "lattica-research-direct-ring-complete-n3-n4-v1",
            distinct_transactions: 7, cases: [None, None], complete_workflow_ns: 0,
            final_artifacts_destroyed: false, faithful_ringct_protocol: false,
            redesign_2x_gate_passed: false, security_adoption_review_complete: false };
        for (index, selection, start, name) in [(0, Selection::N3, 0, "N3"), (1, Selection::N4, 3, "N4")] {
            let started = Instant::now();
            let (statements, witnesses) = fixture_batch(selection, start);
            let expected = ExpectedBatch::new(selection, CONTEXT, statements).unwrap();
            let input = BatchInput::new(expected, witnesses).unwrap();
            let outcome = prove_complete(input, &root.join(format!("{name}.aggregate")));
            let Outcome { aggregate, report } = match outcome {
                Ok(value) => value,
                Err(failure) => {
                    let file = fresh_file(&root.join(format!("{name}.failure.json")));
                    serde_json::to_writer(file, &failure).unwrap();
                    panic!("complete direct aggregate failed: {failure}");
                }
            };
            let n = selection.transactions();
            assert_eq!(report.fresh_whole_transaction_proofs, n);
            assert_eq!(report.fresh_recursive_aggregate_proofs, 1);
            assert_eq!(report.independent_child_cpu_acceptances, n);
            assert_eq!(report.independent_final_cpu_acceptances, 1);
            assert_eq!(report.public_mutation_rejections, 4 * (n + 1));
            assert_eq!(report.opening_mutation_rejections, n + 1);
            assert_eq!(report.restored_proof_acceptances, n + 1);
            assert_eq!(report.public_setup_reused_for_child_cpu_checks, n);
            assert!(report.artifact_roundtrip.as_ref().unwrap().exact_disk_roundtrip);
            assert!(report.phases.iter().all(|phase| phase.terminal.context_closed && phase.terminal.queue_drained));
            assert_eq!(aggregate.artifact().selection(), selection);
            // All secret/proof/GPU owners retire before the complete case timer
            // ends. Only bounded public summary fields survive into case2.
            drop(aggregate);
            let mut case = Case { selection, fixture_start: start, transactions: n,
                whole_transaction_proofs: n, recursive_aggregate_proofs: 1,
                independent_cpu_acceptances: n + 1,
                public_mutation_rejections: report.public_mutation_rejections,
                opening_mutation_rejections: report.opening_mutation_rejections,
                setup_ns: report.phases.iter().map(|phase| phase.setup_ns).sum(),
                proving_ns: report.phases.iter().map(|phase| phase.proving_ns).sum(),
                cpu_verification_ns: report.cpu_verification_ns,
                complete_workflow_ns: 0 };
            let file = fresh_file(&root.join(format!("{name}.report.json")));
            serde_json::to_writer(file, &report).unwrap();
            drop(report);
            case.complete_workflow_ns = started.elapsed().as_nanos();
            suite.cases[index] = Some(case);
        }
        suite.final_artifacts_destroyed = true;
        suite.complete_workflow_ns = total_started.elapsed().as_nanos();
        serde_json::to_writer(fresh_file(&root.join("complete.json")), &suite).unwrap();
    }
}
