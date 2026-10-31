use lattica_pq_direct_spend_research::{
    note, ring, Context, Error, Profile, GOLDILOCKS_MODULUS, VALUE_LIMIT,
};
use lattica_prover_p3::joinsplit_air as js;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
const CONTEXT: Context = Context([19; 32]);

#[test]
fn ring_direct_relation_and_fail_closed_prover() {
    let (s, w) = ring::fixture(CONTEXT).unwrap();
    ring::check_relation(&s, &w, CONTEXT).unwrap();
    assert_eq!(
        ring::prove(&s, &w, CONTEXT),
        Err(Error::IncompleteProofCoverage)
    );
}

#[test]
fn ring_rejects_wrong_authority_selection_and_openings() {
    let (s, mut w) = ring::fixture(CONTEXT).unwrap();
    let old = w.spending[0][0][0];
    w.spending[0][0][0] = if old == 0 { 1 } else { 0 };
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Ownership));
    w.spending[0][0][0] = old;
    let selected = w.selected_pair;
    w.selected_pair = (selected + 1) % ring::RING_PAIRS;
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Ownership));
    w.selected_pair = selected;
    let old = w.input_openings[1][0][0];
    w.input_openings[1][0][0] = if old == 0 { 1 } else { 0 };
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Opening));
    w.input_openings[1][0][0] = old;
    let old = w.output_openings[0][0][0];
    w.output_openings[0][0][0] = if old == 0 { 1 } else { 0 };
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Opening));
}

#[test]
fn ring_rejects_duplicate_serial_noncanonical_range_balance_and_context() {
    let (s, mut w) = ring::fixture(CONTEXT).unwrap();
    let mut changed = s.clone();
    changed.serials[1] = changed.serials[0];
    assert_eq!(
        ring::check_relation(&changed, &w, CONTEXT),
        Err(Error::DuplicateSpend)
    );
    changed = s.clone();
    changed.serials[0][0] ^= 1;
    assert_eq!(
        ring::check_relation(&changed, &w, CONTEXT),
        Err(Error::Ownership)
    );
    changed = s.clone();
    changed.ring[0][0].coin[0][0] = ring::Q;
    assert_eq!(
        ring::check_relation(&changed, &w, CONTEXT),
        Err(Error::NonCanonical)
    );
    changed = s.clone();
    changed.profile = Profile::PrivateNoteDirectV1;
    assert_eq!(
        ring::check_relation(&changed, &w, CONTEXT),
        Err(Error::Profile)
    );
    assert_eq!(
        ring::check_relation(&s, &w, Context([20; 32])),
        Err(Error::Context)
    );
    let old = w.spending[0][0][0];
    w.spending[0][0][0] = 2;
    assert_eq!(
        ring::check_relation(&s, &w, CONTEXT),
        Err(Error::NonCanonical)
    );
    w.spending[0][0][0] = old;
    let old = w.input_values;
    w.input_values = [u64::MAX, 1];
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Range));
    w.input_values = [VALUE_LIMIT, 0];
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Range));
    w.input_values = old;
    w.output_values[1] += 1;
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Balance));
}

#[test]
fn ring_has_exactly_ten_pairs() {
    let (mut s, mut w) = ring::fixture(CONTEXT).unwrap();
    w.selected_pair = 10;
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Geometry));
    w.selected_pair = 4;
    s.ring.pop();
    assert_eq!(ring::check_relation(&s, &w, CONTEXT), Err(Error::Geometry));
}

#[test]
fn note_differential_reference_public_values() {
    let (s, w) = note::fixture(CONTEXT).unwrap();
    note::check_relation(&s, &w, CONTEXT).unwrap();
    assert_eq!(
        s.public,
        js::public_values(&w)
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect::<Vec<_>>()
    );
}

#[test]
fn note_rejects_ownership_membership_opening_asset_and_balance_mutations() {
    let (s, w) = note::fixture(CONTEXT).unwrap();
    let mut x = w.clone();
    x.inputs[0].nk[1] ^= 1;
    assert!(note::check_relation(&s, &x, CONTEXT).is_err());
    x = w.clone();
    x.inputs[0].sib[17][2] += Val::ONE;
    assert_eq!(
        note::check_relation(&s, &x, CONTEXT),
        Err(Error::Membership)
    );
    x = w.clone();
    x.inputs[0].bits[11] = !x.inputs[0].bits[11];
    assert_eq!(
        note::check_relation(&s, &x, CONTEXT),
        Err(Error::Membership)
    );
    x = w.clone();
    x.outputs[1].rcm[1] += Val::ONE;
    assert!(note::check_relation(&s, &x, CONTEXT).is_err());
    x = w.clone();
    x.outputs[0].asset += Val::ONE;
    assert_eq!(note::check_relation(&s, &x, CONTEXT), Err(Error::Asset));
    x = w.clone();
    x.outputs[0].value += 1;
    assert_eq!(note::check_relation(&s, &x, CONTEXT), Err(Error::Balance));
}

#[test]
fn note_rejects_duplicate_nullifiers_ranges_noncanonical_and_profile() {
    let (s, w) = note::fixture(CONTEXT).unwrap();
    let mut x = w.clone();
    x.inputs[1] = x.inputs[0].clone();
    x.outputs[1].value += 500;
    assert_eq!(
        note::check_relation(&s, &x, CONTEXT),
        Err(Error::DuplicateSpend)
    );
    x = w.clone();
    x.inputs[0].nk[0] = GOLDILOCKS_MODULUS;
    assert_eq!(
        note::check_relation(&s, &x, CONTEXT),
        Err(Error::NonCanonical)
    );
    x = w.clone();
    x.inputs[0].value = u64::MAX;
    assert_eq!(note::check_relation(&s, &x, CONTEXT), Err(Error::Range));
    x = w.clone();
    x.outputs[0].value = VALUE_LIMIT;
    assert_eq!(note::check_relation(&s, &x, CONTEXT), Err(Error::Range));
    x = w.clone();
    x.mint = 1;
    assert_eq!(
        note::check_relation(&s, &x, CONTEXT),
        Err(Error::UnsupportedIssuance)
    );
    let mut wrong = s.clone();
    wrong.profile = Profile::RingDirectV1;
    assert_eq!(
        note::check_relation(&wrong, &w, CONTEXT),
        Err(Error::Profile)
    );
    wrong = s.clone();
    wrong.public[js::PI_ANCHOR] = GOLDILOCKS_MODULUS;
    assert_eq!(
        note::check_relation(&wrong, &w, CONTEXT),
        Err(Error::NonCanonical)
    );
    assert_eq!(
        note::check_relation(&s, &w, Context([21; 32])),
        Err(Error::Context)
    );
}

#[test]
#[cfg(feature = "ring-circuit")]
fn ring_compiler_refuses_unreserved_storage_before_arithmetic() {
    let (s, w) = ring::fixture(CONTEXT).unwrap();
    assert!(matches!(
        lattica_pq_direct_spend_research::ring_circuit::compile(&s, &w, CONTEXT, 1),
        Err(Error::ResourceLimit)
    ));
}

#[test]
#[ignore = "serialized CPU proof qualification; run in release mode with coordinator approval"]
fn note_real_proof_roundtrip_and_cryptographic_statement_mutations() {
    let (s, w) = note::fixture(CONTEXT).unwrap();
    let (artifact, measurement) = note::prove(&s, &w, CONTEXT).unwrap();
    assert!(measurement.fresh_proof);
    assert!(!measurement.matched_ringct_workflow);
    let encoded = artifact.encode();
    let restored = note::Artifact::decode(&encoded, &s, CONTEXT).unwrap();
    note::verify(&restored, &s, CONTEXT).unwrap();
    // Mutate both the expected statement and encoded envelope so rejection
    // must come from the actual CPU cryptographic verifier, not envelope equality.
    for index in [js::PI_ANCHOR, js::PI_NF, js::PI_OUTCM] {
        let mut altered = s.clone();
        altered.public[index] ^= 1;
        let mut bytes = encoded.clone();
        bytes[40 + index * 8..48 + index * 8].copy_from_slice(&altered.public[index].to_le_bytes());
        let decoded = note::Artifact::decode(&bytes, &altered, CONTEXT).unwrap();
        assert_eq!(
            note::verify(&decoded, &altered, CONTEXT),
            Err(Error::ProofRejected)
        );
    }
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let decoded = note::Artifact::decode(&corrupt, &s, CONTEXT).unwrap();
    assert_eq!(
        note::verify(&decoded, &s, CONTEXT),
        Err(Error::ProofRejected)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(note::Artifact::decode(&trailing, &s, CONTEXT).is_err());
    assert!(note::Artifact::decode(&encoded, &s, Context([22; 32])).is_err());
    eprintln!("{}", serde_json::to_string(&measurement).unwrap());
}
