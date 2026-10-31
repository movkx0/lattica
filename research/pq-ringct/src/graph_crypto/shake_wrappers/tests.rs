use super::*;
use crate::graph_crypto::{Admission, Payload, Policy};
use crate::shake_air::{Descriptor, RATE};

fn request(input_len: usize, output_len: usize, maximum: usize) -> Request {
    Request::new(
        [7; 32],
        3,
        0,
        RequestDescriptor::Shake(Descriptor {
            input_len,
            output_len,
        }),
        Payload::Shake(vec![0; input_len]),
        Policy {
            maximum_aes_blocks: 8,
            maximum_shake_permutations: maximum,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap()
}

#[test]
fn singleton_is_default_and_paired_is_refused_without_dispatch() {
    assert_eq!(ShakeWrapperLayout::default(), ShakeWrapperLayout::Singleton);
    ShakeWrapperLayout::Singleton.require_executable().unwrap();
    let failure = ShakeWrapperLayout::PairedV1
        .require_executable()
        .unwrap_err();
    for missing in [
        "before proof dispatch",
        "scratch",
        "ownership",
        "height closure",
    ] {
        assert!(failure.0.contains(missing), "{}", failure.0);
    }
}

#[test]
fn pairs_and_odd_tail_preserve_every_original_native_segment() {
    for count in 1usize..=17 {
        let request = request((count - 1) * RATE, 32, 1);
        let original = request.segments().to_vec();
        let singleton = request
            .shake_wrapper_schedule(ShakeWrapperLayout::Singleton)
            .unwrap();
        let paired = request
            .shake_wrapper_schedule(ShakeWrapperLayout::PairedV1)
            .unwrap();
        assert_eq!(singleton.counts().native_proofs, count);
        assert_eq!(singleton.counts().recursive_leaves, count);
        assert_eq!(singleton.counts().recursive_parents, count - 1);
        assert_eq!(paired.counts().native_proofs, count);
        assert_eq!(paired.counts().recursive_leaves, count.div_ceil(2));
        assert_eq!(paired.counts().recursive_parents, count.div_ceil(2) - 1);
        let mut next_segment = 0;
        let mut next_unit = 0;
        for (index, group) in paired.groups().enumerate() {
            assert_eq!(group.first_segment, next_segment);
            assert_eq!(group.first_unit, next_unit);
            assert_eq!(group.segment_count, 2.min(count - next_segment));
            if group.segment_count == 1 {
                assert_eq!(count % 2, 1);
                assert_eq!(index, count / 2);
            }
            next_segment += group.segment_count;
            next_unit += group.units;
        }
        assert_eq!(next_segment, count);
        assert_eq!(next_unit, request.units());
        assert_eq!(request.segments(), original);
    }
}

#[test]
fn padding_and_squeezing_transitions_do_not_change_native_registration() {
    for (input, output, maximum) in [
        (RATE, 32, 1),
        (8 * RATE + 1, 32, 8),
        (0, 2 * RATE + 1, 8),
        (8 * RATE + 1, 10 * RATE + 1, 8),
    ] {
        let request = request(input, output, maximum);
        let schedule = request
            .shake_wrapper_schedule(ShakeWrapperLayout::PairedV1)
            .unwrap();
        let original = request.shake_partition().unwrap().segments();
        for group in schedule.groups() {
            let members = &original[group.first_segment..group.first_segment + group.segment_count];
            assert_eq!(members[0].first_permutation(), group.first_unit);
            assert_eq!(
                members.iter().map(|air| air.permutations()).sum::<usize>(),
                group.units
            );
            assert!(members
                .iter()
                .all(|air| air.height() <= maximum * crate::shake_air::lane::HEIGHT));
        }
        assert_eq!(
            schedule.groups().map(|group| group.units).sum::<usize>(),
            Descriptor {
                input_len: input,
                output_len: output
            }
            .permutations()
            .unwrap()
        );
    }
}

#[test]
fn incomplete_reordered_duplicate_and_mismatched_native_schedules_are_rejected() {
    for mutation in 0..9 {
        let mut request = request(3 * RATE, 32, 1);
        match mutation {
            0 => {
                request.segments.remove(0);
            }
            1 => {
                request.segments.pop();
            }
            2 => request.segments.swap(0, 1),
            3 => request.segments[1] = request.segments[0],
            4 => request.segments[1].units = 0,
            5 => request.segments[0].units = usize::MAX,
            6 => request.segments[0].width += 1,
            7 => request.segments[0].height *= 2,
            8 => {
                request.descriptor = RequestDescriptor::Shake(Descriptor {
                    input_len: 3 * RATE + 1,
                    output_len: 32,
                });
            }
            _ => unreachable!(),
        }
        assert!(
            request
                .shake_wrapper_schedule(ShakeWrapperLayout::PairedV1)
                .is_err(),
            "mutation {mutation}"
        );
    }
    let mut request = request(0, 32, 1);
    request.segments.clear();
    assert!(request
        .shake_wrapper_schedule(ShakeWrapperLayout::Singleton)
        .is_err());
}

#[test]
fn a_shake_layout_cannot_select_or_repartition_aes() {
    let request = Request::new(
        [7; 32],
        3,
        0,
        RequestDescriptor::Aes(crate::aes_lane_air::Descriptor {
            domain: 9,
            start_counter: 0,
            output_len: 32,
        }),
        Payload::Aes([0; 32]),
        Policy::default(),
    )
    .unwrap();
    assert!(request
        .shake_wrapper_schedule(ShakeWrapperLayout::PairedV1)
        .is_err());
}
