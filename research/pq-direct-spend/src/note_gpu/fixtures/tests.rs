use super::*;
use crate::note_gpu::{codec, quota::LEDGER_BYTES};

#[test]
fn seven_fixtures_match_reference_and_have_fourteen_distinct_spends() {
    let context = Context([101; 32]);
    let session = DecodeSession::new(super::super::WORKER_HOST_BYTES).unwrap();
    let fixtures = session.research_fixtures(context).unwrap();
    assert_eq!(fixtures.iter().len(), CASE_COUNT);
    assert_eq!(fixtures.receipt().distinct_nullifiers, 14);
    assert_eq!(fixtures.receipt().distinct_statements, 7);
    assert!(!fixtures.receipt().production_keys);
    assert_eq!(PERMUTATIONS_PER_CASE, 115);
    assert_eq!(PERMUTATION_BACKING_BYTES, 688);
    for id in FixtureId::ALL {
        let fixture = fixtures.get(id);
        assert_eq!(fixture.id(), id);
        let witness = fixture.witness();
        let statement = fixture.statement();
        assert_eq!(statement.public.capacity(), js::N_PUBLIC);
        assert_eq!(note::statement(witness, context).unwrap(), *statement);
        assert_eq!(note::check_relation(statement, witness, context), Ok(()));
        assert_eq!(
            codec::expected_public(statement, context).unwrap(),
            std::array::from_fn(|i| Val::from_u64(statement.public[i]))
        );
        assert!(witness.inputs[0].value >= 1 << 51);
        assert!(witness.outputs[0].value >= 1 << 51);
        assert_eq!(witness.fee, 0);
        assert_eq!(witness.mint, 0);
        assert_eq!(js::pos_of(&witness.inputs[0].bits), Val::ZERO);
        assert_eq!(js::pos_of(&witness.inputs[1].bits), Val::ONE);
        for preceding in fixtures.iter().take(id.ordinal()) {
            assert_ne!(witness.inputs[0].nk, preceding.witness().inputs[0].nk);
            assert_ne!(witness.inputs[1].nk, preceding.witness().inputs[1].nk);
            assert_ne!(
                &statement.public[js::PI_ANCHOR..js::PI_ANCHOR + 4],
                &preceding.statement().public[js::PI_ANCHOR..js::PI_ANCHOR + 4]
            );
            assert_ne!(
                &statement.public[js::PI_OUTCM..js::PI_OUTCM + 8],
                &preceding.statement().public[js::PI_OUTCM..js::PI_OUTCM + 8]
            );
        }
    }
    assert_eq!(distinct(&fixtures.cases), Ok(()));
}

#[test]
fn fixture_admission_is_atomic_and_original_owner_survives_session_drop() {
    let plan = FixturePlan::new().unwrap();
    assert_eq!(
        plan.source_heap_requests_bytes,
        CASE_COUNT * (115 * 688 + js::N_PUBLIC * size_of::<u64>())
    );
    assert_eq!(
        plan.required_host_bytes,
        plan.source_heap_requests_bytes + plan.source_inline_owner_bytes
    );
    let context = Context([102; 32]);
    let short = DecodeSession::new(LEDGER_BYTES + plan.required_host_bytes - 1).unwrap();
    assert!(matches!(
        short.research_fixtures(context),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(short.snapshot().live_reserved_bytes, LEDGER_BYTES);
    assert_eq!(short.snapshot().admitted_attempts, 0);
    let exact = DecodeSession::new(LEDGER_BYTES + plan.required_host_bytes).unwrap();
    let marker = exact.reserve_for_producer(0).unwrap();
    let different = short.reserve_for_producer(0).unwrap();
    let fixtures = exact.research_fixtures(context).unwrap();
    assert!(fixtures.same_ledger(&marker));
    assert!(!fixtures.same_ledger(&different));
    assert_eq!(
        exact.snapshot().live_reserved_bytes,
        LEDGER_BYTES + plan.required_host_bytes
    );
    assert!(matches!(
        exact.research_fixtures(context),
        Err(Error::ResourceLimit)
    ));
    drop(exact);
    let moved = fixtures;
    assert_eq!(
        marker.snapshot().live_reserved_bytes,
        LEDGER_BYTES + plan.required_host_bytes
    );
    assert_eq!(moved.get(FixtureId::ALL[6]).statement().context, context);
    drop(moved);
    assert_eq!(marker.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn fixture_generation_is_deterministic_and_context_binding_is_separate() {
    let context = Context([103; 32]);
    let other_context = Context([104; 32]);
    let session = DecodeSession::new(super::super::WORKER_HOST_BYTES).unwrap();
    let first = session.research_fixtures(context).unwrap();
    let second = session.research_fixtures(context).unwrap();
    let rebound = session.research_fixtures(other_context).unwrap();
    for id in FixtureId::ALL {
        assert_eq!(first.get(id).statement(), second.get(id).statement());
        assert_eq!(
            first.get(id).witness().inputs[0].nk,
            rebound.get(id).witness().inputs[0].nk
        );
        assert_ne!(first.get(id).statement(), rebound.get(id).statement());
        assert_eq!(
            &first.get(id).statement().public[..js::PI_TXBIND],
            &rebound.get(id).statement().public[..js::PI_TXBIND]
        );
        assert!(codec::expected_public(first.get(id).statement(), other_context).is_err());
    }
    assert_eq!(
        fixed_context_binding(context),
        crate::context_binding(Profile::PrivateNoteDirectV1, context)
    );
}

#[test]
fn reference_rejects_invalid_ownership_membership_balance_and_domains() {
    let context = Context([105; 32]);
    let session = DecodeSession::new(super::super::WORKER_HOST_BYTES).unwrap();
    let fixtures = session.research_fixtures(context).unwrap();
    let fixture = fixtures.get(FixtureId::ALL[3]);
    let expected = fixture.statement();
    let original = fixture.witness();
    let mut changed = original.clone();
    changed.inputs[0].nk[0] ^= 1;
    assert!(note::check_relation(expected, &changed, context).is_err());
    changed = original.clone();
    changed.inputs[0].sib[17][2] += Val::ONE;
    assert!(note::check_relation(expected, &changed, context).is_err());
    changed = original.clone();
    changed.inputs[0].nk[0] = GOLDILOCKS_MODULUS;
    assert_eq!(
        note::check_relation(expected, &changed, context),
        Err(crate::Error::NonCanonical)
    );
    changed = original.clone();
    changed.outputs[0].value += 1;
    assert_eq!(
        note::check_relation(expected, &changed, context),
        Err(crate::Error::Balance)
    );
    changed = original.clone();
    changed.inputs[0].value = u64::MAX;
    changed.outputs[0].value = u64::MAX;
    assert_eq!(
        note::check_relation(expected, &changed, context),
        Err(crate::Error::Range)
    );
    changed = original.clone();
    changed.inputs[1] = changed.inputs[0].clone();
    changed.outputs[0].value = changed.inputs[0].value;
    changed.outputs[1].value = changed.inputs[1].value;
    assert_eq!(
        note::check_relation(expected, &changed, context),
        Err(crate::Error::DuplicateSpend)
    );
    let mut wrong = expected.clone();
    wrong.profile = Profile::RingDirectV1;
    assert_eq!(
        note::check_relation(&wrong, original, context),
        Err(crate::Error::Profile)
    );
    assert_eq!(
        note::check_relation(expected, original, Context([106; 32])),
        Err(crate::Error::Context)
    );
    wrong = expected.clone();
    wrong.public[js::PI_NF + 4..js::PI_NF + 8]
        .copy_from_slice(&expected.public[js::PI_NF..js::PI_NF + 4]);
    assert_eq!(
        note::check_relation(&wrong, original, context),
        Err(crate::Error::DuplicateSpend)
    );
}

#[test]
fn distinctness_preflight_rejects_repeated_case_and_cross_case_nullifier() {
    let context = Context([107; 32]);
    let session = DecodeSession::new(super::super::WORKER_HOST_BYTES).unwrap();
    let mut fixtures = session.research_fixtures(context).unwrap();
    let first = fixtures.cases[0].statement.public[js::PI_NF..js::PI_NF + 4].to_vec();
    fixtures.cases[6].statement.public[js::PI_NF + 4..js::PI_NF + 8].copy_from_slice(&first);
    assert_eq!(distinct(&fixtures.cases), Err(Error::Statement));
    let mut fixtures = session.research_fixtures(context).unwrap();
    fixtures.cases[6].statement = fixtures.cases[0].statement.clone();
    assert_eq!(distinct(&fixtures.cases), Err(Error::Statement));
}
