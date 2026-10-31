use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use p3_air::BaseAir;

fn active() -> Policy {
    Policy {
        maximum_aes_blocks: 64,
        maximum_shake_permutations: 32,
        child_memory_budget_bytes: 24u64 << 30,
        admission: Admission::Estimated,
    }
}

#[test]
fn exact_active_policy_refuses_variants_and_preserves_default_gate() {
    let input = [13; 137];
    assert!(check(active()).is_ok());
    let original = ShakeRequestPlan::new([11; 32], 3, 0, &input, 137, active());
    assert_eq!(original.err(), Some(Error::Policy));
    for policy in [
        Policy::default(),
        Policy {
            maximum_aes_blocks: 32,
            ..active()
        },
        Policy {
            maximum_shake_permutations: 16,
            ..active()
        },
        Policy {
            child_memory_budget_bytes: (24u64 << 30) - 1,
            ..active()
        },
        Policy {
            child_memory_budget_bytes: (24u64 << 30) + 1,
            ..active()
        },
        Policy {
            child_memory_budget_bytes: 8u64 << 30,
            ..active()
        },
        Policy {
            admission: Admission::ValidatedLocal,
            ..active()
        },
    ] {
        assert_eq!(
            ShakeRequestPlan::new_active_opt_validate_v1([11; 32], 3, 0, &input, 137, policy).err(),
            Some(Error::Policy),
        );
    }
    // The ordinary path remains available for its original max8 profile.
    let ordinary = ShakeRequestPlan::new([11; 32], 3, 0, &input, 137, Policy::default()).unwrap();
    assert_eq!(ordinary.bounds().selected_maximum, 8);
    assert_eq!(ordinary.bounds().selected_segments, 3);
}

#[test]
fn active_partition_matches_original_counts_shapes_identity_and_preclaims() {
    // These are the existing serialized full-graph request lengths. This
    // source-only differential check does not authenticate a graph or generate
    // a proof. Public fixture/reference storage is outside the owner's ledger.
    for (input_len, output_len, segments, maximum, units) in [
        (109, 32, 1, 32, 1),
        (230_496, 32, 109, 16, 1695),
        (16_416, 137, 10, 16, 122),
    ] {
        let input = vec![17; input_len];
        let plan = ShakeRequestPlan::new_active_opt_validate_v1(
            [19; 32],
            5,
            0,
            &input,
            output_len,
            active(),
        )
        .unwrap();
        let bounds = plan.bounds();
        assert_eq!(bounds.selected_segments, segments);
        assert_eq!(bounds.selected_maximum, maximum);
        assert_eq!(bounds.total_permutations, units);
        assert_eq!(bounds.attempts, if maximum == 32 { 1 } else { 2 });
        assert_eq!(bounds.payload_bytes, input_len);
        let requirements = plan.requirements();
        let required = requirements.total().unwrap();
        assert_eq!(required.device, 0);
        assert_eq!(required.host, bounds.requested_bytes as u64);
        assert_eq!(
            requirements.get(Category::CompilerInputs).host,
            input_len as u64
        );
        // A one-byte shortage rejects the whole source claim before copying
        // input or invoking Request::new; a 24 GiB estimate grants no storage.
        let short = Ledger::new(WorkerAllowance {
            host: required.host - 1,
            device: 0,
        });
        assert!(short.admit_phase(requirements).is_err());
        assert_eq!(short.snapshot().current, Bytes::ZERO);
        let ledger = Ledger::new(WorkerAllowance {
            host: required.host,
            device: 0,
        });
        let token = ledger.admit_phase(requirements).unwrap();
        let before = ledger.snapshot();
        let owner = plan.construct(token, &ledger).unwrap();
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(ledger.remaining(), Bytes::ZERO);
        let expected = Request::new(
            [19; 32],
            5,
            0,
            RequestDescriptor::Shake(shake_air::Descriptor {
                input_len,
                output_len,
            }),
            Payload::Shake(input),
            active(),
        )
        .unwrap();
        assert_eq!(owner.request().segments(), expected.segments());
        assert_eq!(owner.request().descriptor(), expected.descriptor());
        assert_eq!(owner.request().request_index(), expected.request_index());
        let mut counts = [0usize; 5]; // Singleton,2,4,8,16; no source splitting.
        let mut next = 0usize;
        for (index, (air, reference)) in owner
            .request()
            .shake_partition()
            .unwrap()
            .segments()
            .iter()
            .zip(expected.shake_partition().unwrap().segments())
            .enumerate()
        {
            assert_eq!(
                (
                    air.first_permutation(),
                    air.permutations(),
                    air.height(),
                    air.width()
                ),
                (
                    reference.first_permutation(),
                    reference.permutations(),
                    reference.height(),
                    reference.width()
                )
            );
            assert_eq!(air.first_permutation(), next);
            next += air.permutations();
            counts[air.permutations().ilog2() as usize] += 1;
            assert_eq!(air.height(), 4096 * air.permutations());
            assert_eq!(air.width(), if air.permutations() == 1 { 517 } else { 518 });
            assert_eq!(
                owner.request().cache_key(index).unwrap(),
                expected.cache_key(index).unwrap()
            );
        }
        assert_eq!(next, units);
        assert_eq!(
            counts,
            match input_len {
                109 => [1, 0, 0, 0, 0],
                230_496 => [1, 1, 1, 1, 105],
                16_416 => [2, 0, 0, 1, 7],
                _ => unreachable!(),
            }
        );
        if input_len == 16_416 {
            let shape = owner.request().segments();
            assert_eq!((shape[8].first_unit, shape[8].units), (120, 1));
            assert_eq!((shape[9].first_unit, shape[9].units), (121, 1));
        }
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
