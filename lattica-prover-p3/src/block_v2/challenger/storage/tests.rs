use super::*;
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn transient_maximum_shapes_fit_existing_envelope_without_allocating() {
    let (plans, allocations) = measure(|| {
        [
            Plan::observation().unwrap(),
            Plan::grind().unwrap(),
            Plan::sample(4096).unwrap(),
            Plan::scalar(4099, 12288).unwrap(),
            Plan::next_points(4096, 2).unwrap(),
            Plan::next_points(4096, 3).unwrap(),
            Plan::lookup(4096, 4096).unwrap(),
            Plan::lookup(4096, 0).unwrap(),
            Plan::domains(256).unwrap(),
        ]
    });
    assert_eq!(allocations.calls, 0);
    assert!(!allocations.overflow);
    for plan in plans {
        plan.admit(plan.bytes).unwrap();
        assert!(plan.admit(plan.bytes - 1).is_err());
        assert!(plan.bytes <= reservation().unwrap());
    }
    assert_eq!(
        reservation().unwrap() as u64,
        resources::reservation().host_bytes
    );
    eprintln!("transcript_host_envelope limit_bytes={} maximum_planned_bytes={} shapes=9 allocation_free=true",
        resources::HOST_BYTES, plans.iter().map(|p| p.bytes).max().unwrap());
}

#[test]
fn registered_states_and_maximum_scratch_fit_the_original_shared_allowance() {
    let state = DeviceSession::transcript_state_host_backing().unwrap();
    let scratch = Plan::lookup(resources::SCALAR_OUTPUTS, resources::SCALAR_OUTPUTS).unwrap();
    let required = state
        .checked_mul(resources::LIVE_STATES)
        .unwrap()
        .checked_add(scratch.bytes)
        .unwrap();
    assert!(required <= resources::HOST_BYTES);
    eprintln!("transcript_host_ownership states={} state_bytes={state} scratch_bytes={} aggregate_bytes={required} allowance_bytes={}",
        resources::LIVE_STATES, scratch.bytes, resources::HOST_BYTES);
}

#[test]
fn transient_shapes_reject_overflow_and_out_of_range_counts() {
    for count in [4097, usize::MAX] {
        assert!(Plan::sample(count).is_err());
        assert!(Plan::next_points(count, 3).is_err());
        assert!(Plan::lookup(count, 0).is_err());
        assert!(Plan::lookup(1, count).is_err());
    }
    assert!(Plan::sample(0).is_err());
    assert!(Plan::next_points(1, 1).is_err());
    assert!(Plan::next_points(1, usize::MAX).is_err());
    assert!(Plan::scalar(0, 1).is_err());
    assert!(Plan::scalar(4100, 1).is_err());
    assert!(Plan::scalar(1, 12289).is_err());
    assert!(Plan::domains(0).is_err());
    assert!(Plan::domains(257).is_err());
    assert!(Plan::new(&[usize::MAX, 1]).is_err());
    assert!(exact::<u64>(usize::MAX).is_err());
    assert!(exact::<u64>(resources::HOST_BYTES / 8 + 1).is_err());
}

#[test]
fn exact_transcript_vectors_match_allocator_requests_and_keep_capacity() {
    for count in [0, 1, 3, 4096, 12288] {
        let (words, requests) = measure(|| zeroed_words(count).unwrap());
        assert_eq!(words.len(), count);
        assert_eq!(words.capacity(), count);
        assert_eq!(requests.bytes, count * 8);
        assert_eq!(requests.calls, usize::from(count != 0));
        assert!(!requests.overflow);
        assert!(words.iter().all(|&word| word == 0));
    }
}

#[test]
fn observation_batches_preserve_empty_tail_and_partial_chunks_without_heap_requests() {
    for count in [0, 1, 4095, 4096, 4097, 8192, 8203] {
        let mut lengths = [0usize; 3];
        let mut calls = 0;
        let mut seen = 0;
        let (result, requests) = measure(|| {
            observe_batches(
                (0..count).map(|i| Val::new(i as u64)).filter(|_| true),
                |words| {
                    lengths[calls] = words.len();
                    calls += 1;
                    for &word in words {
                        assert_eq!(word, seen as u64);
                        seen += 1;
                    }
                    Ok(())
                },
            )
        });
        result.unwrap();
        assert_eq!(requests.calls, 0);
        assert!(!requests.overflow);
        assert_eq!(seen, count);
        assert_eq!(calls, count / resources::BATCH_WORDS + 1);
        assert_eq!(lengths[calls - 1], count % resources::BATCH_WORDS);
        assert!(lengths[..calls - 1]
            .iter()
            .all(|&n| n == resources::BATCH_WORDS));
    }
}
