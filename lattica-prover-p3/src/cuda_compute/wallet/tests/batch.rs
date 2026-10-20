use super::*;
use crate::{batch_htlc_air as batch_htlc, batch_joinsplit_air as batch_js};

fn finish_operation(run: Run) {
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.capabilities.scope(), CoverageScope::Operation);
    assert!(report
        .observations
        .iter()
        .all(|o| o.backend == Backend::Cuda && o.calls == o.completed_calls && o.device_calls > 0));
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_batch_wallet_traces_match_cpu_with_only_validity_readback() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    for count in [0usize, 1, 3, 4, 5, 8] {
        let generated = count + usize::from(count < count.max(1).next_power_of_two());
        let witnesses: Vec<_> = (0..count).map(|i| joinsplit(i % 3)).collect();
        let before = runtime.snapshot();
        let operation = run();
        let frame = wallets
            .joinsplit_batch(&witnesses, 1 << 20, &operation)
            .unwrap();
        finish_operation(operation);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            (generated * 8) as u64
        );
        compare(
            &runtime,
            frame,
            batch_js::build_batch_trace(&witnesses).values,
            batch_js::batch_root(&witnesses).to_vec(),
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);

        let witnesses: Vec<_> = (0..count).map(|i| htlc(i % 3)).collect();
        let before = runtime.snapshot();
        let operation = run();
        let frame = wallets.htlc_batch(&witnesses, 1 << 20, &operation).unwrap();
        finish_operation(operation);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            (generated * 8) as u64
        );
        compare(
            &runtime,
            frame,
            batch_htlc::build_batch_trace(&witnesses).values,
            batch_htlc::batch_root(&witnesses).to_vec(),
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
    drop(wallets);
    let retired = runtime.retire().unwrap();
    assert_eq!(retired.live_bytes, 0);
    assert_eq!(retired.modules, 0);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_tree_roots_match_cpu_through_maximum_count_and_reject_before_allocation() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    let before = runtime.snapshot();
    let operation = run();
    for (values, count, host) in [
        (vec![], 0, 1 << 20),
        (vec![0; js::N_PUBLIC], crate::MAX_TREE_TX + 1, 1 << 20),
        (vec![0; js::N_PUBLIC - 1], 1, 1 << 20),
        (vec![crate::GOLDILOCKS_ORDER; js::N_PUBLIC], 1, 1 << 20),
        (vec![0; js::N_PUBLIC], 1, 1),
    ] {
        assert!(wallets
            .joinsplit_tree_root(&values, count, host, &operation)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    operation.finish(false).unwrap();
    for count in [
        1usize, 2, 3, 4, 5, 7, 8, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024,
    ] {
        let fields: Vec<_> = (0..count * js::N_PUBLIC)
            .map(|i| {
                if i % 3 == 0 {
                    crate::GOLDILOCKS_ORDER - 1
                } else {
                    i as u64 * 7919
                }
            })
            .collect();
        let operation = run();
        let before = runtime.snapshot();
        let actual = wallets
            .joinsplit_tree_root(&fields, count, 1 << 20, &operation)
            .unwrap();
        finish_operation(operation);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            40
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        let mut expected = [Val::ZERO; 4];
        for statement in fields.chunks_exact(js::N_PUBLIC) {
            let public: Vec<_> = statement.iter().copied().map(Val::from_u64).collect();
            expected = js::merge(expected, batch_js::tx_statement_digest(&public));
        }
        for _ in count..count.next_power_of_two() {
            expected = js::merge(expected, batch_js::dummy_sk());
        }
        assert_eq!(actual, expected.map(|value| value.as_canonical_u64()));
    }
    drop(wallets);
    assert_eq!(runtime.retire().unwrap().live_bytes, 0);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_batch_failure_releases_frames_and_runtime_can_retry() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    let before = runtime.snapshot();
    let operation = run();
    assert!(wallets
        .joinsplit_batch(&[joinsplit(0)], 1, &operation)
        .is_err());
    assert!(wallets.htlc_batch(&[htlc(0)], 1, &operation).is_err());
    assert_eq!(runtime.snapshot(), before);
    operation.finish(false).unwrap();
    let mut invalid = joinsplit(0);
    invalid.fee += 1;
    let operation = run();
    assert!(wallets
        .joinsplit_batch(&[joinsplit(0), invalid], 1 << 20, &operation)
        .is_err());
    operation.finish(false).unwrap();
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    assert_eq!(runtime.snapshot().pending_commands, 0);
    let operation = run();
    let frame = wallets
        .joinsplit_batch(&[joinsplit(0)], 1 << 20, &operation)
        .unwrap();
    finish_operation(operation);
    drop(frame);
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    drop(wallets);
    runtime.retire().unwrap();
}
