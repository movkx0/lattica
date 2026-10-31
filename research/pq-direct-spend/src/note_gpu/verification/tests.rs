use super::*;
use crate::{note, Context};
use lattica_prover_p3::joinsplit_air::{self as js, JoinSplitAir};
use p3_air::{
    symbolic::{
        get_max_constraint_degree_extension, get_symbolic_constraints, AirLayout, BaseLeaf,
        SymbolicExpression,
    },
    BaseAir,
};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

#[cfg(feature = "note-verification-allocation-audit")]
mod observation;

fn same_expression(a: &SymbolicExpression<Val>, b: &SymbolicExpression<Val>) -> bool {
    use SymbolicExpression as E;
    match (a, b) {
        (E::Leaf(a), E::Leaf(b)) => match (a, b) {
            (BaseLeaf::Variable(a), BaseLeaf::Variable(b)) => {
                a.entry == b.entry && a.index == b.index
            }
            (BaseLeaf::Constant(a), BaseLeaf::Constant(b)) => a == b,
            (BaseLeaf::IsFirstRow, BaseLeaf::IsFirstRow)
            | (BaseLeaf::IsLastRow, BaseLeaf::IsLastRow)
            | (BaseLeaf::IsTransition, BaseLeaf::IsTransition) => true,
            _ => false,
        },
        (E::Add { x: a, y: b, .. }, E::Add { x: c, y: d, .. })
        | (E::Sub { x: a, y: b, .. }, E::Sub { x: c, y: d, .. })
        | (E::Mul { x: a, y: b, .. }, E::Mul { x: c, y: d, .. }) => {
            same_expression(a, c) && same_expression(b, d)
        }
        (E::Neg { x: a, .. }, E::Neg { x: b, .. }) => same_expression(a, b),
        _ => false,
    }
}

#[test]
fn exact_degree_hint_preserves_every_reference_constraint_and_metadata() {
    let original = JoinSplitAir;
    let hinted = air::VerifierAir;
    let layout = AirLayout::from_air::<Val>(&original);
    let base_degree = get_max_constraint_degree_extension::<Val, Val, _>(&original, layout);
    let quadratic_degree =
        get_max_constraint_degree_extension::<Val, Challenge, _>(&original, layout);
    assert_eq!((base_degree, quadratic_degree), (air::DEGREE, air::DEGREE));
    assert_eq!(hinted.max_constraint_degree(), Some(base_degree));
    let original_constraints = get_symbolic_constraints::<Val, _>(&original, layout);
    let delegated_constraints = get_symbolic_constraints::<Val, _>(&hinted, layout);
    assert_eq!(original_constraints.len(), delegated_constraints.len());
    assert!(original_constraints
        .iter()
        .zip(&delegated_constraints)
        .all(|(a, b)| same_expression(a, b)));
    assert_eq!(hinted.width(), original.width());
    assert_eq!(hinted.num_public_values(), original.num_public_values());
    assert_eq!(
        hinted.num_periodic_columns(),
        original.num_periodic_columns()
    );
    assert_eq!(
        hinted.main_next_row_columns(),
        original.main_next_row_columns()
    );
    assert_eq!(
        hinted.preprocessed_next_row_columns(),
        original.preprocessed_next_row_columns()
    );
    assert_eq!(hinted.preprocessed_width(), original.preprocessed_width());
    assert_eq!(hinted.num_constraints(), original.num_constraints());
    assert!(hinted.preprocessed_trace().is_none());
    assert_eq!(hinted.periodic_columns(), original.periodic_columns());
    for hiding in [0, 1] {
        assert_eq!(
            p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&original, layout, hiding),
            p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&hinted, layout, hiding)
        );
    }
}

#[test]
fn verifier_admission_refuses_debug_and_unsupported_architectures() {
    assert_eq!(
        VerificationPlan::new().is_ok(),
        !cfg!(debug_assertions) && cfg!(target_arch = "x86_64")
    );
}

#[test]
fn fresh_configuration_retains_legacy_hiding_types_and_parameters() {
    let candidate: config::MyConfig = fresh_config().unwrap();
    let reference = config::make_config();
    assert_eq!(candidate.is_zk(), 1);
    assert_eq!(candidate.is_zk(), reference.is_zk());
    use p3_commit::Pcs;
    let max = |cfg: &config::MyConfig| {
        <config::MyPcs as Pcs<Challenge, config::Challenger>>::log_max_lde_height(cfg.pcs())
    };
    assert_eq!(max(&candidate), max(&reference));
    // fresh_config obtains FRI parameters directly from production_fri and
    // refuses any change to queries, blowup, arities, PoW, masking or caps.
}

#[test]
fn verifier_scratch_is_added_to_the_artifact_owner_before_numerical_work() {
    if cfg!(debug_assertions) || !cfg!(target_arch = "x86_64") {
        return;
    }
    let plan = VerificationPlan::new().unwrap();
    let expected = crate::note_gpu::tests::statement();
    let bytes =
        crate::note_gpu::tests::packet(&crate::note_gpu::tests::fixture(&[4, 4, 4, 1]), &expected);
    let required = decode_required_bytes(&bytes, &expected).unwrap();
    let session = DecodeSession::new(required + plan.required_temporary_bytes() - 1).unwrap();
    let artifact = session.decode(bytes, &expected, expected.context).unwrap();
    let before = session.snapshot().live_reserved_bytes;
    assert!(matches!(
        plan.verify(&artifact),
        Err(VerificationError::ResourceLimit)
    ));
    assert_eq!(session.snapshot().live_reserved_bytes, before);
    drop(artifact);
    assert_eq!(
        session.snapshot().live_reserved_bytes,
        session.snapshot().ledger_bytes
    );
}

fn encoded_raw(bytes: &[u8], expected: &note::Statement) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ARTIFACT_HEADER_BYTES + bytes.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&expected.context.0);
    for value in &expected.public {
        packet.extend_from_slice(&value.to_le_bytes());
    }
    packet.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    packet.extend_from_slice(bytes);
    packet
}

fn measure_full<T>(plan: VerificationPlan, work: impl FnOnce() -> T) -> T {
    #[cfg(feature = "note-verification-allocation-audit")]
    {
        observation::measure_checked(plan.required_temporary_bytes(), work)
    }
    #[cfg(not(feature = "note-verification-allocation-audit"))]
    {
        let _ = plan;
        work()
    }
}

#[test]
#[ignore = "fresh CPU proof plus serial numerical verification; run release x86_64 under campaign guard"]
fn complete_quadratic_verifier_matches_legacy_and_rejects_statement_and_proof_mutations() {
    let context = Context([91; 32]);
    let (expected, witness) = note::fixture(context).unwrap();
    let (bytes, _) = js::prove_to_bytes_with_request(&witness, crate::cpu_request()).unwrap();
    let plan = VerificationPlan::new().unwrap();
    let raw = encoded_raw(&bytes, &expected);
    let required = decode_required_bytes(&raw, &expected).unwrap();
    let session = DecodeSession::new(required + plan.required_temporary_bytes()).unwrap();
    let artifact = session.decode(raw, &expected, context).unwrap();
    assert!(js::verify_bytes(&bytes, artifact.public()));
    let before = session.snapshot().live_reserved_bytes;
    let verified = measure_full(plan, || plan.verify(&artifact)).unwrap();
    assert!(verified.receipt().independent_cpu_verification);
    assert!(!verified.receipt().production_acceptance);
    assert_eq!(session.snapshot().live_reserved_bytes, before);
    drop(verified);
    drop(artifact);
    for index in [js::PI_ANCHOR, js::PI_NF, js::PI_OUTCM] {
        let mut changed = expected.clone();
        changed.public[index] ^= 1;
        let raw = encoded_raw(&bytes, &changed);
        let artifact = session.decode(raw, &changed, context).unwrap();
        assert!(!js::verify_bytes(&bytes, artifact.public()));
        assert!(matches!(
            measure_full(plan, || plan.verify(&artifact)),
            Err(VerificationError::ProofRejected)
        ));
        drop(artifact);
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            session.snapshot().ledger_bytes
        );
    }
    let mut mutated: Proof = postcard::from_bytes(&bytes).unwrap();
    mutated.opened_values.trace_local[0] += Challenge::ONE;
    let mutated = postcard::to_allocvec(&mutated).unwrap();
    let raw = encoded_raw(&mutated, &expected);
    // Mutated varints can change packet length; reserve its own exact capacity.
    let mutated_required = decode_required_bytes(&raw, &expected).unwrap();
    let mutated_session =
        DecodeSession::new(mutated_required + plan.required_temporary_bytes()).unwrap();
    let artifact = mutated_session.decode(raw, &expected, context).unwrap();
    assert!(!js::verify_bytes(&mutated, artifact.public()));
    assert!(matches!(
        measure_full(plan, || plan.verify(&artifact)),
        Err(VerificationError::ProofRejected)
    ));
    drop(artifact);
    assert_eq!(
        mutated_session.snapshot().live_reserved_bytes,
        mutated_session.snapshot().ledger_bytes
    );
    eprintln!("private_note_quadratic_verifier_reference proof_bytes={} temporary_source_bound={} honest_and_mutation_cases=5 unchanged_legacy_parameters=true gpu_work=false",
        bytes.len(), plan.required_temporary_bytes());
}
