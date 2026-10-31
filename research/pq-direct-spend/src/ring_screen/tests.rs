use super::*;

#[test]
fn seven_genuine_relations_regenerate_distinct_statements_and_serials() {
    bounds::Staging::new().unwrap();
    let manifest = fixtures::preflight().unwrap();
    for (case, expected) in manifest.into_iter().enumerate() {
        let (statement, witness) = fixtures::generate(case).unwrap();
        assert_eq!(statement.context, CONTEXT);
        assert_eq!(statement.setup_seed, [7; 32]);
        assert_eq!(statement.ring.len(), 10);
        assert_eq!(statement.ring.capacity(), 10);
        assert_eq!(witness.selected_pair, [0, 1, 3, 4, 6, 8, 9][case]);
        ring::check_relation(&statement, &witness, CONTEXT).unwrap();
        assert_eq!(Some(fixtures::identity(case, &statement)), expected);
        assert!(witness
            .input_values
            .into_iter()
            .chain(witness.output_values)
            .all(|n| n < crate::VALUE_LIMIT));
    }
    assert!(fixtures::generate(CASES).is_err());
}

#[test]
fn direct_screen_rejects_wrong_ownership_selection_openings_and_serials() {
    fn reject(change: fn(&mut ring::Statement, &mut ring::Witness), expected: Error) {
        let (mut statement, mut witness) = fixtures::generate(2).unwrap();
        change(&mut statement, &mut witness);
        assert_eq!(
            ring::check_relation(&statement, &witness, CONTEXT),
            Err(expected)
        );
    }
    fn change(v: &mut i64) {
        *v = if *v == -1 { 0 } else { -1 };
    }
    reject(
        |_, w| w.selected_pair = (w.selected_pair + 1) % 10,
        Error::Ownership,
    );
    reject(|_, w| change(&mut w.spending[0][0][0]), Error::Ownership);
    reject(
        |s, w| {
            s.ring[w.selected_pair][1].public_key[0][0] =
                (s.ring[w.selected_pair][1].public_key[0][0] + 1) % ring::Q
        },
        Error::Ownership,
    );
    reject(
        |_, w| change(&mut w.input_openings[1][0][0]),
        Error::Opening,
    );
    reject(
        |_, w| change(&mut w.output_openings[0][0][0]),
        Error::Opening,
    );
    reject(|s, _| s.serials[0][0] ^= 1, Error::Ownership);
    reject(|s, _| s.serials[1] = s.serials[0], Error::DuplicateSpend);
    reject(
        |s, _| s.ring[0][0].coin[0][0] = ring::Q,
        Error::NonCanonical,
    );
    reject(|_, w| w.spending[0][0][0] = 2, Error::NonCanonical);
    reject(|_, w| w.input_values[0] = crate::VALUE_LIMIT, Error::Range);
    reject(|_, w| w.input_values = [u64::MAX; 2], Error::Range);
    reject(|_, w| w.output_values[0] += 1, Error::Balance);
    reject(
        |s, _| s.profile = Profile::PrivateNoteDirectV1,
        Error::Profile,
    );
    reject(|s, _| s.context.0[0] ^= 1, Error::Context);
    reject(
        |s, _| {
            s.ring.pop();
        },
        Error::Geometry,
    );
    reject(|_, w| w.selected_pair = 10, Error::Geometry);
}

#[test]
fn manifest_rejects_repeated_statements_serials_cases_and_wrong_coverage() {
    let (statement, _) = fixtures::generate(0).unwrap();
    let first = fixtures::identity(0, &statement);
    let mut manifest = [None; CASES];
    fixtures::insert(&mut manifest, first).unwrap();
    assert_eq!(
        fixtures::insert(&mut manifest, first),
        Err(Error::DuplicateSpend)
    );
    let mut repeated_statement = first;
    repeated_statement.case = 1;
    repeated_statement.serials = [[0; 32], [1; 32]];
    assert_eq!(
        fixtures::insert(&mut manifest, repeated_statement),
        Err(Error::DuplicateSpend)
    );
    let mut repeated_serial = first;
    repeated_serial.case = 1;
    repeated_serial.statement_sha3_256[0] ^= 1;
    assert_eq!(
        fixtures::insert(&mut manifest, repeated_serial),
        Err(Error::DuplicateSpend)
    );
    let mut out_of_range = first;
    out_of_range.case = CASES;
    assert_eq!(
        fixtures::insert(&mut manifest, out_of_range),
        Err(Error::DuplicateSpend)
    );
    assert_eq!(manifest.iter().flatten().count(), 1);
}

#[test]
fn staging_and_report_paths_fit_unchanged_worker_and_caller_allowances() {
    let staging = bounds::Staging::new().unwrap();
    assert_eq!(
        staging.ring_backing_bytes,
        10 * std::mem::size_of::<[ring::Account; 2]>()
    );
    assert!(staging.required_host_bytes < WORKER_HOST_BYTES);
    let admitted = bounds::orchestration(io::MAX_OUTPUT_BYTES, None).unwrap();
    assert!(admitted <= ring_circuit::verification::CALLER_ORCHESTRATION_BYTES);
    assert!(
        bounds::orchestration(ring_circuit::verification::CALLER_ORCHESTRATION_BYTES, None)
            .is_err()
    );
    for invalid in ["relative", "/", "/tmp/../escape", "/tmp/./ambiguous"] {
        assert!(io::validate_output(invalid).is_err());
    }
    io::validate_output("/tmp/fresh-direct-ring-screen").unwrap();
    let longest = format!("/{}", "a".repeat(io::MAX_OUTPUT_BYTES - 1));
    io::validate_output(&longest).unwrap();
    assert!(io::validate_output(&(longest + "b")).is_err());
}

#[test]
fn fixture_staging_census_pins_native_allocation_and_array_geometry() {
    let source = include_str!("../ring_native.rs");
    for needle in [
        "Vec::with_capacity(count.div_ceil(16) * 16)",
        "stream(seed, 0x4d617431, 7648 * 4)",
        "stream(seed, 0x4d617432, 3366 * 4)",
        "Vec::with_capacity(7)",
        "vec![[[0; D]; 3]; 4]",
        "stream(serial, 0, 1197 * 4)",
        "spending.each_ref().map(|p| ntt(b, p))",
        "opening.each_ref().map(|p| ntt(b, p))",
    ] {
        assert!(
            source.contains(needle),
            "fixture native census changed: {needle}"
        );
    }
    let fixed = source
        .split("pub(crate) fn public_key")
        .nth(1)
        .unwrap()
        .split("#[cfg(all(test, feature = \"native-reference\"))]")
        .next()
        .unwrap();
    for allocation in ["vec!", "Vec::", ".collect", ".to_vec"] {
        assert!(!fixed.contains(allocation));
    }
    assert_eq!(ring::D, 256);
    assert_eq!(ring::RING_PAIRS, 10);
    assert_eq!(crate::VALUE_BITS, 52);
}

#[test]
#[ignore = "coordinator-only baseline direct-full host-tree screen; exact environment, fresh output and serialized GPU guard required"]
fn gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire() {
    workflow::run().unwrap();
}
