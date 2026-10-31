use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use crate::graph_crypto::{NativeProductionPlan, ShakeWrapperLayout};
use p3_air::BaseAir;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 2 << 30,
        device: 0,
    })
}

fn plan(input: &[u8], output_len: usize, policy: Policy) -> ShakeRequestPlan<'_> {
    ShakeRequestPlan::new([9; 32], 3, 1, input, output_len, policy).unwrap()
}

#[test]
fn checked_source_bounds_match_existing_partition_and_identity() {
    for (input_len, output_len) in [
        (0, 0),
        (0, 32),
        (137, 137),
        (8 * 136 + 7, 10 * 136),
        (65 * 136, 65 * 136 + 1),
    ] {
        let input = vec![37; input_len];
        for maximum in [1, 8, 64] {
            let policy = Policy {
                maximum_shake_permutations: maximum,
                admission: Admission::Estimated,
                ..Policy::default()
            };
            let plan = plan(&input, output_len, policy);
            let bounds = plan.bounds();
            assert!((1..=7).contains(&bounds.attempts));
            assert!(bounds.selected_maximum <= maximum);
            let ledger = ledger();
            let token = ledger.admit_phase(plan.requirements()).unwrap();
            let owner = plan.construct(token, &ledger).unwrap();
            let expected = Request::new(
                [9; 32],
                3,
                1,
                RequestDescriptor::Shake(shake_air::Descriptor {
                    input_len,
                    output_len,
                }),
                Payload::Shake(input.clone()),
                policy,
            )
            .unwrap();
            assert_eq!(owner.request().segments(), expected.segments());
            assert_eq!(owner.request().descriptor(), expected.descriptor());
            assert_eq!(owner.request().request_index(), expected.request_index());
            assert_eq!(owner.request().segments().len(), bounds.selected_segments);
            for (a, b) in owner
                .request()
                .shake_partition()
                .unwrap()
                .segments()
                .iter()
                .zip(expected.shake_partition().unwrap().segments())
            {
                assert_eq!(
                    (
                        a.first_permutation(),
                        a.permutations(),
                        a.height(),
                        a.width()
                    ),
                    (
                        b.first_permutation(),
                        b.permutations(),
                        b.height(),
                        b.width()
                    )
                );
            }
            assert_eq!(
                owner.request().cache_key(0).unwrap(),
                expected.cache_key(0).unwrap()
            );
            assert_eq!(
                ledger.snapshot().current.host,
                bounds.requested_bytes as u64
            );
            assert!(owner.belongs_to(&ledger));
            drop(owner);
            assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        }
    }
}

#[test]
fn construction_copies_exact_source_and_borrows_keep_request_charge_live() {
    let mut source = vec![41; 137];
    let ledger = ledger();
    let plan = plan(
        &source,
        137,
        Policy {
            maximum_shake_permutations: 1,
            ..Policy::default()
        },
    );
    let charge = plan.requirements();
    let token = ledger.admit_phase(charge).unwrap();
    let owner = plan.construct(token, &ledger).unwrap();
    let key = owner.request().cache_key(0).unwrap();
    source.fill(43); // construction owns its copy; source borrow has ended
    assert_eq!(owner.request().cache_key(0).unwrap(), key);
    let Payload::Shake(payload) = &owner.request().payload else {
        panic!("SHAKE owner")
    };
    assert_eq!(payload, &vec![41; 137]);
    let native = NativeProductionPlan::new(owner.request(), 0).unwrap();
    let native_token = ledger.admit_phase(native.requirement()).unwrap();
    let pending = native
        .claim_for(owner.request(), 0, native_token, &ledger)
        .unwrap();
    assert_eq!(
        ledger.snapshot().current.host,
        charge.total().unwrap().host + (64 << 20)
    );
    drop(pending);
    let compiler = crate::component_tree::owned_shake::GroupCompilePlan::new(
        owner.request(),
        ShakeWrapperLayout::PairedV1,
        0,
        crate::component_tree::EndpointContext {
            context: [0; 32],
            statement: Default::default(),
            input: Default::default(),
            output: Default::default(),
        },
    )
    .unwrap();
    let token = ledger.admit_phase(compiler.requirements());
    // The separate 2 GiB test worker cannot admit the unchanged >2 GiB
    // compiler recipe while the request is retained; no allowance is added.
    assert!(token.is_err());
    drop(compiler);
    assert_eq!(ledger.snapshot().current, charge.total().unwrap());
    let moved = owner;
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn invalid_source_policy_identity_and_tokens_refuse_before_construction() {
    let input = [47; 8];
    for (operation, subrequest, output_len, policy, expected) in [
        (usize::MAX, 0, 32, Policy::default(), Error::Identity),
        (0, 2, 32, Policy::default(), Error::Identity),
        (0, 0, usize::MAX, Policy::default(), Error::Descriptor),
        (
            0,
            0,
            32,
            Policy {
                maximum_shake_permutations: 3,
                ..Policy::default()
            },
            Error::Policy,
        ),
        (
            0,
            0,
            32,
            Policy {
                child_memory_budget_bytes: 1,
                ..Policy::default()
            },
            Error::NativeBudget,
        ),
        (
            0,
            0,
            32,
            Policy {
                child_memory_budget_bytes: (8 << 30) + 1,
                ..Policy::default()
            },
            Error::Policy,
        ),
    ] {
        assert_eq!(
            ShakeRequestPlan::new([0; 32], operation, subrequest, &input, output_len, policy).err(),
            Some(expected)
        );
    }
    let ledger = ledger();
    let foreign = self::ledger();
    for variant in 0..3 {
        let plan = plan(&input, 32, Policy::default());
        let token = match variant {
            0 => foreign.admit_phase(plan.requirements()).unwrap(),
            1 => {
                let mut required = plan.requirements();
                required
                    .add(Category::CompilerInputs, Bytes { host: 1, device: 0 })
                    .unwrap();
                ledger.admit_phase(required).unwrap()
            }
            _ => ledger
                .reserve(
                    Category::CompilerInputs,
                    Bytes {
                        host: input.len() as u64,
                        device: 0,
                    },
                )
                .unwrap(),
        };
        assert_eq!(
            plan.construct(token, &ledger).err(),
            Some(if variant == 0 {
                Error::WrongLedger
            } else {
                Error::WrongReservation
            })
        );
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
    let plan = self::plan(&input, 32, Policy::default());
    let oversized = Ledger::new(WorkerAllowance {
        host: (32 << 30) + 1,
        device: 0,
    });
    let token = oversized.admit_phase(plan.requirements()).unwrap();
    assert_eq!(
        plan.construct(token, &oversized).err(),
        Some(Error::WrongReservation)
    );
    assert_eq!(oversized.snapshot().current, Bytes::ZERO);
}

fn failure_plan(input: &[u8]) -> ShakeRequestPlan<'_> {
    let mut plan = plan(
        input,
        32,
        Policy {
            maximum_shake_permutations: 64,
            admission: Admission::Estimated,
            child_memory_budget_bytes: estimated_native_peak(1).unwrap(),
            ..Policy::default()
        },
    );
    assert_eq!(plan.bounds().attempts, 7);
    assert_eq!(plan.bounds().selected_maximum, 1);
    // Private test mutation forces the final source constructor error without
    // adding a partition attempt or changing the already admitted source bound.
    plan.policy.child_memory_budget_bytes = 0;
    plan
}

#[test]
fn all_pre_dispatch_attempts_and_original_error_cleanup_remain_charged() {
    let input = vec![53; 65 * shake_air::RATE];
    let ledger = ledger();
    let plan = failure_plan(&input);
    let bytes = plan.bounds().requested_bytes;
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    assert_eq!(
        plan.construct(token, &ledger).err(),
        Some(Error::Construction)
    );
    assert_eq!(ledger.snapshot().peak.host, bytes as u64);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "process-wide allocation observation; serialized guarded qualification required"]
fn allocation_requests_fit_source_bound_including_growth_and_failure() {
    use crate::component_tree::shake_verification_memory::observe_planner_allocations;
    assert_eq!(
        std::env::var("LATTICA_REQUEST_OWNER_QUALIFICATION").as_deref(),
        Ok("1")
    );
    for (input_len, output_len) in [
        (0, 0),
        (137, 137),
        (65 * 136, 65 * 136 + 1),
        (4096 * 136 + 17, 137),
    ] {
        let input = vec![59; input_len];
        let ledger = ledger();
        let plan = observe_planner_allocations(0, || {
            plan(
                &input,
                output_len,
                Policy {
                    maximum_shake_permutations: 64,
                    admission: Admission::Estimated,
                    child_memory_budget_bytes: estimated_native_peak(1).unwrap(),
                    ..Policy::default()
                },
            )
        });
        let bound = plan.bounds().requested_bytes;
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        let owner = observe_planner_allocations(bound, || plan.construct(token, &ledger)).unwrap();
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let input = vec![61; 65 * shake_air::RATE];
    let ledger = ledger();
    let plan = failure_plan(&input);
    let bound = plan.bounds().requested_bytes;
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let failure = observe_planner_allocations(bound, || plan.construct(token, &ledger));
    assert_eq!(failure.err(), Some(Error::Construction));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    let plan = self::plan(&input, 32, Policy::default());
    let token = ledger
        .reserve(Category::CompilerInputs, Bytes { host: 1, device: 0 })
        .unwrap();
    let failure = observe_planner_allocations(0, || plan.construct(token, &ledger));
    assert_eq!(failure.err(), Some(Error::WrongReservation));
}
