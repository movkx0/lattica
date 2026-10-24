use super::*;

#[test]
fn carry_stack_preserves_order_and_logarithmic_live_nodes() {
    for count in 1usize..=129 {
        let mut stack = CarryStack::new();
        let mut merges = 0;
        let mut merge = |mut left: Vec<usize>, right: Vec<usize>| {
            assert_eq!(left.last().unwrap() + 1, right[0]);
            left.extend(right);
            merges += 1;
            Ok(left)
        };
        for next in 0..count {
            stack.push(vec![next], &mut merge).unwrap();
            assert!(stack.slots.len() <= (next + 1).ilog2() as usize + 1);
            assert_eq!(
                stack.slots.iter().filter(|x| x.is_some()).count(),
                (next + 1).count_ones() as usize
            );
        }
        assert_eq!(
            stack.finish(&mut merge).unwrap(),
            (0..count).collect::<Vec<_>>()
        );
        assert_eq!(merges, count - 1);
    }
    assert!(CarryStack::<usize>::new()
        .finish(|_, _| unreachable!())
        .is_err());
}

#[test]
fn admission_diagnostics_include_stage_span_actual_geometry_and_budget() {
    let geometry = Geometry {
        active_rows: 375679,
        padded_rows: 524288,
        wires: 0,
        main_width: 0,
        preprocessed_width: 0,
        permutation_width_base: 0,
        quotient_chunks: 0,
        constraints: 0,
        max_constraint_degree: 0,
        fri_ali_bits: 0,
        retained_lde_bytes: 59 << 30,
    };
    let message = admit("wide leaf", 0, 122, &geometry, 48 << 30)
        .unwrap_err()
        .0;
    for text in [
        "wide leaf",
        "[0, 122)",
        "before registration",
        "375679",
        "524288",
        "63350767616",
        "51539607552",
        "not a peak-memory bound",
    ] {
        assert!(message.contains(text), "missing {text}: {message}");
    }
    assert!(admit("wide leaf", 0, 122, &geometry, 59 << 30).is_ok());
}

#[cfg(feature = "recursive-wide")]
#[test]
#[ignore = "actual two-leaf complete request, parent proof and cache replay; schedule one guarded worker"]
fn actual_complete_request_replays_verified_native_and_outer_caches() {
    use p3_field::PrimeCharacteristicRing;
    let directory = std::path::PathBuf::from(
        std::env::var_os("LATTICA_REQUEST_PROVER_CACHE_DIR")
            .expect("explicit persistent cache directory required"),
    );
    let native = ProofCache::new(directory.join("native"), 64 << 20).unwrap();
    let outer = OuterProofCache::new(directory.join("outer"), 64 << 20).unwrap();
    let budget = std::env::var("LATTICA_OUTER_RETAINED_BUDGET_BYTES")
        .ok()
        .map(|v| v.parse::<u64>().unwrap())
        .unwrap_or(48 << 30);
    let prover = RequestProver::new(&native, &outer, budget).unwrap();
    let request = Request::new(
        [73; 32],
        0,
        0,
        RequestDescriptor::Aes(aes_lane_air::Descriptor {
            domain: 0x4368,
            start_counter: 3,
            output_len: 31,
        }),
        Payload::Aes([29; 32]),
        Policy {
            maximum_aes_blocks: 1,
            maximum_shake_permutations: 1,
            child_memory_budget_bytes: 8 << 30,
            admission: Admission::ValidatedLocal,
        },
    )
    .unwrap();
    let context = graph_tree::GraphContext {
        context: [71; 32],
        statement: [Val::from_u64(9); 4],
        node_manifest: [Val::ZERO; 4],
    };
    let first = prover.prove_serial(&request, &context).unwrap();
    assert_eq!(first.report.native_children, 2);
    assert_eq!(first.report.outer_leaves, 2);
    assert_eq!(first.report.outer_parents, 1);
    let mut wrong = request.endpoint_context_hint(&context);
    wrong.context[0] ^= 1;
    assert!(first.key.verify_request(&first.proof, &wrong).is_err());
    drop(first);
    let replay = prover.prove_serial(&request, &context).unwrap();
    assert_eq!(replay.report.native_cache_hits, 2);
    assert_eq!(replay.report.outer_cache_hits, 3);
    eprintln!("complete_request_cache_replay={:?}", replay.report);
}
