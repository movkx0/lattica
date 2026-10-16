use super::*;
use crate::spill_alloc::allocation_requests::measure;
use core::mem::MaybeUninit;
use p3_field::PrimeCharacteristicRing;

type Quadratic = crate::config::Challenge;
type Cubic = crate::block_v2::profile::Challenge;

fn rounds<F: PrimeCharacteristicRing>() -> Vec<(&'static (), Vec<Vec<F>>)> {
    vec![
        (&(), vec![vec![F::ONE, F::NEG_ONE], vec![F::ONE]]),
        (&(), vec![vec![F::ZERO]]),
    ]
}
fn shapes() -> [Shape; 3] {
    [
        Shape {
            width: 5,
            points: 2,
            log_height: 7,
        },
        Shape {
            width: 3,
            points: 1,
            log_height: 6,
        },
        Shape {
            width: 2,
            points: 1,
            log_height: 7,
        },
    ]
}

fn census<F: FriExtension>() {
    let (rounds, round_requests) = measure(rounds::<F>);
    for resident in [true, false] {
        let (plan, admission) = measure(|| Plan::new(&rounds, &shapes(), resident, 1 << 20));
        assert_eq!(admission.calls, 0);
        let plan = plan.unwrap();
        assert_eq!(plan.rounds_bytes, round_requests.bytes);
        // An independent typed allocation fixture includes all initialized
        // nested outputs, even when their values are still dummy field values.
        let (opened, opened_requests) = measure(|| {
            vec![
                vec![
                    vec![vec![F::ZERO; 5], vec![F::ZERO; 5]],
                    vec![vec![F::ZERO; 3]],
                ],
                vec![vec![vec![F::ZERO; 2]]],
            ]
        });
        assert_eq!(plan.opened_bytes, opened_requests.bytes);
        let (prepared, prepared_requests) =
            measure(|| Vec::<MaybeUninit<(u32, DeviceOpening)>>::with_capacity(3));
        assert_eq!(plan.prepared_bytes, prepared_requests.bytes);
        let (_fri, fri_requests) = measure(|| {
            if resident {
                (
                    Some(Vec::<MaybeUninit<DeviceMatrix>>::with_capacity(2)),
                    None,
                )
            } else {
                (None, Some(vec![vec![F::ZERO; 128], vec![F::ZERO; 64]]))
            }
        });
        assert_eq!(plan.fri_bytes, fri_requests.bytes);
        let (readback, raw_requests) =
            measure(|| vec![0u64; if resident { 10 } else { 128 } * F::DIMENSION]);
        assert_eq!(plan.readback_bytes, raw_requests.bytes);
        assert_eq!(
            plan.total_bytes,
            round_requests.bytes
                + opened_requests.bytes
                + prepared_requests.bytes
                + fri_requests.bytes
                + raw_requests.bytes
        );
        assert!(
            opened_requests.calls > 0 && prepared_requests.calls == 1 && raw_requests.calls == 1
        );
        assert!(plan.raw_opening_bytes == 10 * size_of::<F>());
        assert!(plan.raw_fri_bytes == if resident { 0 } else { 128 * size_of::<F>() });
        assert!([
            round_requests,
            admission,
            opened_requests,
            prepared_requests,
            fri_requests,
            raw_requests
        ]
        .iter()
        .all(|r| !r.overflow));
        eprintln!("opening_construction_census field_bytes={} resident={} planned_bytes={} independent_bytes={} allocation_free_admission=true",
            size_of::<F>(), resident, plan.total_bytes,
            round_requests.bytes + opened_requests.bytes + prepared_requests.bytes + fri_requests.bytes + raw_requests.bytes);
        drop((opened, prepared, readback));
    }
}

#[test]
fn construction_backing_matches_independent_allocations_in_both_fields_and_modes() {
    census::<Quadratic>();
    census::<Cubic>();
}

#[test]
fn retained_round_spare_capacity_is_charged_at_all_three_levels() {
    let mut rounds = rounds::<Cubic>();
    let base = Plan::new(&rounds, &shapes(), true, 1 << 20).unwrap();
    let cap = rounds.capacity();
    rounds.reserve_exact(cap + 7 - rounds.len());
    let outer = (rounds.capacity() - cap) * size_of::<(&(), Vec<Vec<Cubic>>)>();
    let cap = rounds[0].1.capacity();
    let additional = cap + 7 - rounds[0].1.len();
    rounds[0].1.reserve_exact(additional);
    let matrices = (rounds[0].1.capacity() - cap) * size_of::<Vec<Cubic>>();
    let cap = rounds[0].1[0].capacity();
    let additional = cap + 7 - rounds[0].1[0].len();
    rounds[0].1[0].reserve_exact(additional);
    let points = (rounds[0].1[0].capacity() - cap) * size_of::<Cubic>();
    let updated = Plan::new(&rounds, &shapes(), true, 1 << 20).unwrap();
    assert_eq!(
        updated.rounds_bytes - base.rounds_bytes,
        outer + matrices + points
    );
    assert_eq!(
        updated.total_bytes - base.total_bytes,
        outer + matrices + points
    );
    assert_eq!(updated.opened_bytes, base.opened_bytes);
    assert!(Plan::new(&rounds, &shapes(), true, base.total_bytes).is_err());
}

#[test]
fn exact_limit_passes_and_short_limits_reject_without_allocating() {
    let rounds = rounds::<Quadratic>();
    for resident in [true, false] {
        let plan = Plan::new(&rounds, &shapes(), resident, 1 << 20).unwrap();
        let (exact, requests) =
            measure(|| Plan::new(&rounds, &shapes(), resident, plan.total_bytes));
        assert_eq!(exact.unwrap().total_bytes, plan.total_bytes);
        assert_eq!(requests.calls, 0);
        for allowance in [0, plan.rounds_bytes, plan.total_bytes - 1] {
            let (short, requests) = measure(|| Plan::new(&rounds, &shapes(), resident, allowance));
            assert!(short.is_err());
            assert_eq!(requests.calls, 0);
            assert!(!requests.overflow);
        }
    }
}

#[test]
fn duplicate_heights_share_one_fri_input_and_resident_plan_never_charges_host_layers() {
    let rounds = rounds::<Cubic>();
    let mut shape = shapes();
    let two = Plan::new(&rounds, &shape, true, 1 << 20).unwrap();
    assert_eq!(two.heights, (1 << 7) | (1 << 6));
    assert_eq!(two.height_count, 2);
    shape[1].log_height = 7;
    let one = Plan::new(&rounds, &shape, true, 1 << 20).unwrap();
    assert_eq!(one.height_count, 1);
    assert_eq!(two.total_bytes - one.total_bytes, size_of::<DeviceMatrix>());
    shape.iter_mut().for_each(|s| s.log_height = 25);
    let large = Plan::new(&rounds, &shape, true, 1 << 20).unwrap();
    assert_eq!(large.total_bytes, one.total_bytes);
    assert!(Plan::new(&rounds, &shape, false, 1 << 20).is_err());
}

#[test]
fn malformed_matrix_shapes_and_round_counts_reject_without_allocating() {
    let rounds = rounds::<Cubic>();
    for invalid in [
        Shape {
            width: 0,
            ..shapes()[0]
        },
        Shape {
            width: 4097,
            ..shapes()[0]
        },
        Shape {
            points: 0,
            ..shapes()[0]
        },
        Shape {
            points: 33,
            ..shapes()[0]
        },
        Shape {
            points: 1,
            ..shapes()[0]
        },
        Shape {
            log_height: 26,
            ..shapes()[0]
        },
    ] {
        let mut shape = shapes();
        shape[0] = invalid;
        let (result, requests) = measure(|| Plan::new(&rounds, &shape, true, usize::MAX));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
    }
    for shape in [&shapes()[..0], &shapes()[..2]] {
        let (result, requests) = measure(|| Plan::new(&rounds, shape, true, usize::MAX));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
    }
    let mut extra = shapes().to_vec();
    extra.push(shapes()[0]);
    assert!(Plan::new(&rounds, &extra, true, usize::MAX).is_err());
    let empty = Vec::<(&(), Vec<Vec<Cubic>>)>::new();
    assert!(Plan::new(&empty, &shapes(), true, usize::MAX).is_err());
}

#[test]
fn backing_arithmetic_rejects_overflow_and_unaddressable_buffers() {
    assert!(bytes::<u64>(usize::MAX).is_err());
    assert!(bytes::<u8>(isize::MAX as usize + 1).is_err());
    let mut sum = usize::MAX;
    assert!(add(&mut sum, 1).is_err());
}

#[test]
fn canonical_point_words_use_only_fixed_stack_storage() {
    fn check<F: FriExtension>() {
        let input = [F::NEG_ONE; 32];
        let mut output = [0u64; 96];
        let (_, requests) = measure(|| fill_words(&input, &mut output[..32 * F::DIMENSION]));
        assert_eq!(requests.calls, 0);
        assert!(!requests.overflow);
        for (field, words) in input.iter().zip(output.chunks_exact(F::DIMENSION)) {
            for (coefficient, word) in field.as_basis_coefficients_slice().iter().zip(words) {
                assert_eq!(*word, coefficient.as_canonical_u64());
            }
        }
    }
    check::<Quadratic>();
    check::<Cubic>();
}
