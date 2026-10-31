use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy, ShakeRequestPlan},
};

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: DEVICE_BYTES,
    })
}
fn active_plan(input: &[u8]) -> ShakeRequestPlan<'_> {
    ShakeRequestPlan::new_active_opt_validate_v1(
        [41; 32],
        9,
        0,
        input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap()
}

fn owned(ledger: &Ledger, byte: u8) -> ReservedShakeRequest {
    let input = [byte; 16_416];
    let plan = active_plan(&input);
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

fn zero(ledger: &Ledger) {
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.current, Bytes::ZERO);
    for category in snapshot.categories {
        assert_eq!(category.current, Bytes::ZERO);
    }
}

#[test]
fn ten_original_outputs_share_exactly_one_preparation_and_verifier_component() {
    let ledger = ledger(HOST_BYTES);
    let owner = owned(&ledger, 11);
    let before = ledger.snapshot();
    let mut expected = bookkeeping_requirement().unwrap();
    let first = NativePreparationPlan::new(&owner, 0).unwrap();
    include(&mut expected, first.requirements()).unwrap();
    include(&mut expected, VerificationPlan::component_requirement()).unwrap();
    for ordinal in 0..SEGMENTS {
        let preparation = NativePreparationPlan::new(&owner, ordinal).unwrap();
        assert_eq!(preparation.requirements(), first.requirements());
        let output = ShakeOutputPlan::new(preparation.census()).unwrap();
        for part in [
            output.proof_requirement(),
            output.report_requirement(),
            retained_requirement().unwrap(),
            attachment::requirements().unwrap(),
        ] {
            include(&mut expected, part).unwrap();
        }
    }
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger).unwrap();
    assert!(pending.preparation.is_for(&owner, 0, &ledger));
    assert_eq!(
        pending.future.iter().filter(|p| p.is_some()).count(),
        SEGMENTS - 1
    );
    assert_eq!(
        pending.outputs.iter().filter(|p| p.is_some()).count(),
        SEGMENTS
    );
    assert_eq!(
        pending.attachments.iter().filter(|p| p.is_some()).count(),
        SEGMENTS
    );
    let after = ledger.snapshot();
    assert_eq!(
        after.current.host - before.current.host,
        expected.total().unwrap().host
    );
    assert_eq!(after.current.device, before.current.device);
    for category in Category::ALL {
        assert_eq!(
            after.categories[category as usize].current.host
                - before.categories[category as usize].current.host,
            expected.get(category).host
        );
    }
    drop(pending);
    assert_eq!(ledger.snapshot().current, before.current);
    drop(owner);
    zero(&ledger);
}

#[test]
fn exact_source_identity_and_worker_limits_refuse_before_claiming_scratch() {
    let ledger = ledger(HOST_BYTES);
    let owner = owned(&ledger, 13);
    let other = self::ledger(HOST_BYTES);
    let before = ledger.snapshot();
    assert!(matches!(
        PendingNativeHashx::reserve_before_native(&owner, &other),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    zero(&other);
    let input = [13; 16_416];
    let default = ShakeRequestPlan::new([41; 32], 9, 0, &input, 137, Policy::default()).unwrap();
    let claim = ledger.admit_phase(default.requirements()).unwrap();
    let default = default.construct(claim, &ledger).unwrap();
    let before = ledger.snapshot();
    assert!(matches!(
        PendingNativeHashx::reserve_before_native(&default, &ledger),
        Err(Error::Source)
    ));
    assert_eq!(ledger.snapshot(), before);
    drop((default, owner));
    zero(&ledger);
    let enlarged = self::ledger(HOST_BYTES + 1);
    let input = [17; 16_416];
    let plan = active_plan(&input);
    let original = enlarged.admit_phase(plan.requirements()).unwrap();
    // Request construction already enforces the unchanged worker envelope.
    // An enlarged ledger cannot produce an owner for scratch admission.
    assert!(plan.construct(original, &enlarged).is_err());
    zero(&enlarged);
}

#[test]
fn one_byte_short_source_admission_releases_every_original_partial_owner() {
    let generous = ledger(HOST_BYTES);
    let owner = owned(&generous, 19);
    let pending = PendingNativeHashx::reserve_before_native(&owner, &generous).unwrap();
    let exact = generous.snapshot().current.host;
    drop(pending);
    drop(owner);
    zero(&generous);
    for (host, accepted) in [(exact, true), (exact - 1, false)] {
        let ledger = self::ledger(host);
        let owner = owned(&ledger, 19);
        let before = ledger.snapshot().current;
        let result = PendingNativeHashx::reserve_before_native(&owner, &ledger);
        assert_eq!(result.is_ok(), accepted);
        if !accepted {
            assert!(matches!(&result, Err(Error::Admission)));
        }
        drop(result);
        assert_eq!(ledger.snapshot().current, before);
        drop(owner);
        zero(&ledger);
    }
}

#[test]
fn startup_shortage_is_terminal_before_device_preflight_or_any_native_attempt() {
    let generous = ledger(HOST_BYTES);
    let owner = owned(&generous, 23);
    let pending = PendingNativeHashx::reserve_before_native(&owner, &generous).unwrap();
    let source_bytes = generous.snapshot().current.host;
    let runtime = PendingRuntime::reserve_outer_host_v1(&generous, limits()).unwrap();
    let startup = runtime.reserved_bytes().host;
    drop(runtime);
    drop(pending);
    drop(owner);
    zero(&generous);
    let short = ledger(source_bytes + startup - 1);
    let owner = owned(&short, 23);
    let before = short.snapshot().current;
    let pending = PendingNativeHashx::reserve_before_native(&owner, &short).unwrap();
    // SAFETY: exact startup admission is one byte short, so no preflight,
    // environment/physical query, context, recording or runtime can be reached.
    let result = unsafe { pending.prepare() };
    assert!(matches!(&result, Err(Error::Runtime)));
    drop(result);
    assert_eq!(short.snapshot().current, before);
    drop(owner);
    zero(&short);
}

#[test]
#[ignore = "ten fresh GPU native proofs per witness; exclusive immutable coordinator guard only"]
fn genuine_hashx_sequence_reuses_original_scratch_for_distinct_inputs_and_retains_children() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_NATIVE_HASHX_SCRATCH_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let mut previous = None;
    for (case, byte) in [29, 31].into_iter().enumerate() {
        let ledger = ledger(HOST_BYTES);
        let test_callers = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: 64 << 10,
                    device: 0,
                },
            )
            .unwrap();
        let verifier = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        let owner = owned(&ledger, byte);
        let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger).unwrap();
        // SAFETY: ignored test requires the external immutable/exclusive guard.
        let prepared = unsafe { pending.prepare() }.unwrap();
        let original_capacity = prepared.original_pcs_bytes().unwrap();
        let before = ledger.snapshot();
        let declared = prepared.outer_continuation_capacity().unwrap();
        assert_eq!(declared.pcs, original_capacity);
        assert_eq!(declared.retained_tree_host_bytes, 8 << 30);
        assert_eq!(declared.startup.device + declared.pcs.device, DEVICE_BYTES);
        assert_eq!(ledger.snapshot(), before);
        let mut completed = unsafe { prepared.produce() }.unwrap();
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(completed.retained_native_count(), SEGMENTS);
        assert!(retirement_is_complete(completed.retirement()));
        let public = completed.segments[SEGMENTS - 1]
            .as_ref()
            .unwrap()
            .output
            .artifact()
            .public_values;
        if let Some(prior) = previous {
            assert_ne!(prior, public);
        }
        previous = Some(public);
        let before = ledger.snapshot();
        assert!(matches!(
            completed.take_next_child(1, &ledger),
            Err(Error::Authority)
        ));
        assert_eq!(ledger.snapshot(), before);
        let mut original_verifier = Some(verifier);
        for index in 0..SEGMENTS {
            let child = completed.take_next_child(index, &ledger).unwrap();
            assert!(child.is_for(owner.request(), index, &ledger));
            let before = ledger.snapshot();
            let (_, returned) = child
                .verify_pre_reserved_retaining_original(original_verifier.take().unwrap(), &ledger)
                .unwrap_or_else(|_| panic!("retained child independent verification failed"));
            assert_eq!(ledger.snapshot(), before);
            original_verifier = Some(returned);
            drop(child);
        }
        assert_eq!(completed.retained_native_count(), 0);
        eprintln!("hashx_original_scratch_component case={} native=10 cpu_verified=20 original_pcs_host={} peak_retained_children=10 retained_children=0 original_snapshots_equal=true whole_workflow=false",
            case, original_capacity.host);
        drop(completed);
        drop(original_verifier);
        drop(owner);
        drop(test_callers);
        zero(&ledger);
        let terminal = ledger.snapshot();
        eprintln!("hashx_original_scratch_terminal case={} current_host={} current_device={} categories_zero={}",
            case, terminal.current.host, terminal.current.device,
            terminal.categories.iter().filter(|category| category.current == Bytes::ZERO).count());
    }
}

#[test]
#[ignore = "one genuine GPU native proof then refused reordered successor; coordinator guard only"]
fn genuine_retirement_reordered_successor_preserves_complete_owners_until_terminal_drop() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_NATIVE_HASHX_SCRATCH_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let ledger = ledger(HOST_BYTES);
    let test_callers = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: 64 << 10,
                device: 0,
            },
        )
        .unwrap();
    let owner = owned(&ledger, 37);
    let baseline = ledger.snapshot().current;
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger).unwrap();
    let mut prepared = unsafe { pending.prepare() }.unwrap();
    let current = prepared.current.take().unwrap();
    let completion = unsafe { current.produce(&prepared.bookkeeping, &ledger) }.unwrap();
    let later = prepared.successors[1].take().unwrap();
    let before = ledger.snapshot();
    let (error, later, completion) = match later.advance(completion, &prepared.bookkeeping, &ledger)
    {
        Ok(_) => panic!("skipped source successor accepted"),
        Err(refused) => refused,
    };
    assert_eq!(error, Error::Authority);
    assert_eq!(ledger.snapshot(), before);
    assert!(completion.verified.is_for(&owner, 0, &ledger));
    assert!(retirement_is_complete(completion.originals.retirement()));
    eprintln!("hashx_original_scratch_rejection native=1 cpu_verified=1 rejected_next=2 original_snapshots_equal=true whole_workflow=false");
    drop(later);
    drop(completion);
    drop(prepared);
    assert_eq!(ledger.snapshot().current, baseline);
    drop(owner);
    drop(test_callers);
    zero(&ledger);
    let terminal = ledger.snapshot();
    eprintln!("hashx_original_scratch_terminal case=0 current_host={} current_device={} categories_zero={}",
        terminal.current.host, terminal.current.device,
        terminal.categories.iter().filter(|category| category.current == Bytes::ZERO).count());
}
