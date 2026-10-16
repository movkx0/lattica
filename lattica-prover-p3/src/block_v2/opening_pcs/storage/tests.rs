use super::*;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;
type Quadratic = crate::config::Challenge;
type Cubic = crate::block_v2::profile::Challenge;
const LIMIT: usize = 1 << 20;

fn values<F: PrimeCharacteristicRing>() -> OpenedValues<F> {
    vec![
        vec![vec![vec![F::ONE; 5], vec![F::NEG_ONE; 4]]],
        vec![vec![vec![F::ZERO; 3]]],
    ]
}
fn rounds<F: PrimeCharacteristicRing>() -> Vec<(&'static (), Vec<Vec<F>>)> {
    vec![
        (&(), vec![vec![F::ONE, F::NEG_ONE]]),
        (&(), vec![vec![F::ONE]]),
    ]
}
fn plan<F>(values: &OpenedValues<F>, rounds: &Vec<(&(), Vec<Vec<F>>)>) -> Partition {
    let (result, requests) = measure(|| Partition::new(values, rounds, 2, 2, None, LIMIT));
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    result.unwrap()
}

fn census<F: PrimeCharacteristicRing>() {
    let (values, requests) = measure(values::<F>);
    let (rounds, descriptors) = measure(rounds::<F>);
    let plan = plan(&values, &rounds);
    assert_eq!(plan.opened_bytes, requests.bytes);
    assert_eq!(plan.rounds_bytes, descriptors.bytes);
    assert!(!requests.overflow && !descriptors.overflow);
    assert_eq!(
        plan.bridge_bytes,
        2 * (size_of::<DeviceMatrix>() + size_of::<&()>())
    );
    assert_eq!(
        plan.retained_bytes,
        plan.opened_bytes + plan.rounds_bytes + plan.bridge_bytes + plan.hiding_bytes
    );
    assert_eq!(plan.retained_bytes + plan.fri_allowance, LIMIT);
    eprintln!("opening_host_census field_bytes={} opened_bytes={} independent_opened_bytes={} rounds_bytes={} independent_rounds_bytes={} allocation_free=true",
        size_of::<F>(), plan.opened_bytes, requests.bytes, plan.rounds_bytes, descriptors.bytes);
}

#[test]
fn retained_capacities_match_independent_allocation_requests_in_both_fields() {
    census::<Quadratic>();
    census::<Cubic>();
}

fn grow<T>(values: &mut Vec<T>) -> usize {
    let before = values.capacity();
    values.reserve_exact(before + 7 - values.len());
    (values.capacity() - before) * size_of::<T>()
}

#[test]
fn spare_capacity_at_every_retained_level_reduces_fri_allowance() {
    let mut values = values::<Cubic>();
    let mut rounds = rounds::<Cubic>();
    let mut previous = plan(&values, &rounds).retained_bytes;
    let mut checks = 0;
    macro_rules! check {
        ($change:expr) => {{
            let added = $change;
            let current = plan(&values, &rounds);
            assert_eq!(current.retained_bytes - previous, added);
            assert_eq!(current.fri_allowance, LIMIT - previous - added);
            previous = current.retained_bytes;
            checks += 1;
        }};
    }
    check!(grow(&mut values));
    check!(grow(&mut values[0]));
    check!(grow(&mut values[0][0]));
    check!(grow(&mut values[0][0][0]));
    check!(grow(&mut rounds));
    check!(grow(&mut rounds[0].1));
    check!(grow(&mut rounds[0].1[0]));
    assert_eq!(checks, 7);
    let more = Partition::new(&values, &rounds, 9, 2, None, LIMIT).unwrap();
    assert_eq!(
        more.retained_bytes - previous,
        7 * size_of::<DeviceMatrix>()
    );
}

#[test]
fn exact_remainder_and_hiding_limits_reject_before_allocation_or_mutation() {
    let mut values = values::<Quadratic>();
    let rounds = rounds::<Quadratic>();
    let plan = plan(&values, &rounds);
    let exact = Partition::new(&values, &rounds, 2, 2, None, plan.retained_bytes + 1).unwrap();
    assert_eq!(exact.fri_allowance, 1);
    for limit in [0, plan.opened_bytes - 1, plan.retained_bytes] {
        let (result, requests) = measure(|| Partition::new(&values, &rounds, 2, 2, None, limit));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
        assert!(!requests.overflow);
    }
    let original = values.clone();
    let (result, requests) = measure(|| split_hiding(&mut values, 2, None, plan.hiding_bytes - 1));
    assert!(result.is_err());
    assert_eq!(values, original);
    assert_eq!(requests.calls, 0);
    let (result, requests) = measure(|| split_hiding(&mut values, 2, None, plan.hiding_bytes));
    assert!(result.is_ok());
    assert_eq!(requests.bytes, plan.hiding_bytes);
    assert!(!requests.overflow);
}

fn split_oracle<F: PrimeCharacteristicRing + Copy + serde::Serialize>() {
    for unhidden in [None, Some(0), Some(1)] {
        for columns in [0, 1, 2, 3] {
            let mut values = values::<F>();
            let original_capacity = plan(&values, &rounds::<F>()).opened_bytes;
            let mut expected = values.clone();
            let expected_random: OpenedValues<F> = expected
                .iter_mut()
                .enumerate()
                .map(|(i, matrices)| {
                    matrices
                        .iter_mut()
                        .map(|points| {
                            points
                                .iter_mut()
                                .map(|point| {
                                    let count = if unhidden == Some(i) { 0 } else { columns };
                                    point.drain(point.len() - count..).collect()
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect();
            let required = hiding_bytes(&values, columns, unhidden, LIMIT).unwrap();
            let (actual, requests) =
                measure(|| split_hiding(&mut values, columns, unhidden, required));
            let actual = actual.unwrap();
            assert_eq!(requests.bytes, required);
            assert!(!requests.overflow);
            assert_eq!(
                postcard::to_allocvec(&actual).unwrap(),
                postcard::to_allocvec(&expected_random).unwrap()
            );
            assert_eq!(
                postcard::to_allocvec(&values).unwrap(),
                postcard::to_allocvec(&expected).unwrap()
            );
            // Count retained backing without imposing a second hiding split.
            let retained = Partition::new(&values, &rounds::<F>(), 0, 0, None, LIMIT).unwrap();
            assert_eq!(retained.opened_bytes, original_capacity);
        }
    }
}

#[test]
fn hiding_split_preserves_preprocessing_order_and_bytes_in_both_fields() {
    split_oracle::<Quadratic>();
    split_oracle::<Cubic>();
}

#[test]
fn zero_hiding_and_empty_vectors_still_charge_descriptors() {
    let mut values: OpenedValues<Cubic> = vec![vec![vec![Vec::with_capacity(17)], Vec::new()]];
    let rounds = vec![(&(), vec![vec![Cubic::ONE], Vec::new()])];
    let plan = Partition::new(&values, &rounds, 0, 0, None, LIMIT).unwrap();
    let (output, requests) = measure(|| split_hiding(&mut values, 0, None, plan.hiding_bytes));
    assert_eq!(output.unwrap(), vec![vec![vec![vec![]], vec![]]]);
    assert_eq!(requests.bytes, plan.hiding_bytes);
    assert_eq!(requests.calls, 3);
    assert!(plan.opened_bytes >= 17 * size_of::<Cubic>());
    assert_eq!(values[0][0][0].capacity(), 17);
}

#[test]
fn invalid_width_and_geometry_reject_without_allocating() {
    let mut values = values::<Cubic>();
    let rounds = rounds::<Cubic>();
    for count in [4, usize::MAX] {
        let (result, requests) =
            measure(|| Partition::new(&values, &rounds, 2, count, None, LIMIT));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
        let (result, requests) = measure(|| split_hiding(&mut values, count, None, LIMIT));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
    }
    let (result, requests) = measure(|| {
        Partition::new(
            &values,
            &Vec::<(&(), Vec<Vec<Cubic>>)>::new(),
            2,
            2,
            None,
            LIMIT,
        )
    });
    assert!(result.is_err());
    assert_eq!(requests.calls, 0);
}

#[test]
fn capacity_arithmetic_rejects_overflow() {
    let mut backing = Backing::new(usize::MAX);
    assert!(backing.capacity::<u64>(usize::MAX).is_err());
    backing.capacity::<u8>(usize::MAX).unwrap();
    assert!(backing.capacity::<u8>(1).is_err());
    let values = values::<Cubic>();
    let rounds = rounds::<Cubic>();
    let (result, requests) =
        measure(|| Partition::new(&values, &rounds, usize::MAX, 2, None, LIMIT));
    assert!(result.is_err());
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
}
