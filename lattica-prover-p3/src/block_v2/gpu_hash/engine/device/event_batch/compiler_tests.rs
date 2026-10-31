use super::*;

fn compiler_run() -> Run {
    use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, true, false)
        .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
    caps.set(Stage::Preprocessing, Backend::OpenCl);
    Run::new(
        "compiler_event_batch_test",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        caps,
    )
    .unwrap()
}

#[test]
#[ignore = "requires OpenCL GPU; coordinator must run serially in a bounded service"]
fn compiler_run_receipts_survive_enqueue_failure_and_unwind_without_session_attribution() {
    use crate::block_v2::gpu_hash;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_quotient_test_engine(super::super::super::Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let session = DeviceSession::new().unwrap();
    session
        .with_engine(|engine| {
            // The direct compiler sink batches even without the optional tuning profile.
            engine.tuning.events = false;
            let spec = MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?;
            let output = session.allocate(engine, spec)?;
            const GUARD: u64 = 0x8412_680a_45c2_9a0e;
            output
                .storage
                .buffer
                .write(&[GUARD; 4][..])
                .enq()
                .map_err(|e| e.to_string())?;
            let kernel = engine
                .pq
                .kernel_builder("device_transform_parameters")
                .arg(&output.storage.buffer)
                .arg(8u32)
                .arg(1u64)
                .arg(7u64)
                .global_work_size(1usize)
                .build()
                .map_err(|e| e.to_string())?;
            let invalid_group = engine
                .pq
                .device()
                .max_wg_size()
                .map_err(|e| e.to_string())?
                + 1;
            let untouched = session.stats();
            for failure in 0..5 {
                let run = compiler_run();
                let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                    let mut batch = EventBatch::for_run(engine, &run, Stage::Preprocessing);
                    let count = if failure == 0 { 2 * CAPACITY + 2 } else { 5 };
                    for _ in 0..count {
                        let mut event = compute::Event::empty();
                        // SAFETY: fixed two-word output is bounded by the four-word allocation.
                        unsafe {
                            kernel
                                .cmd()
                                .enew(&mut event)
                                .enq()
                                .map_err(|e| e.to_string())?;
                        }
                        batch.record("compiler_run_receipt_test", event)?;
                    }
                    match failure {
                        1 => {
                            // SAFETY: intentionally invalid workgroup must fail at enqueue,
                            // before executing; valid output arguments remain alive throughout.
                            unsafe {
                                kernel
                                    .cmd()
                                    .local_work_size(invalid_group)
                                    .enq()
                                    .map_err(|e| e.to_string())?;
                            }
                            panic!("invalid workgroup unexpectedly accepted");
                        }
                        2 => panic!("injected compiler producer unwind"),
                        3 => return Ok(()), // Missing finish must poison completion.
                        4 => {
                            let event = compute::Event::user(batch.engine.pq.context())
                                .map_err(|e| e.to_string())?;
                            event.set_complete().map_err(|e| e.to_string())?;
                            batch.record("compiler_missing_profile", event)?;
                        }
                        _ => {}
                    }
                    batch.finish()?;
                    Ok(())
                }));
                match failure {
                    0 | 3 => assert!(result.unwrap().is_ok()),
                    1 | 4 => assert!(result.unwrap().is_err()),
                    _ => assert!(result.is_err()),
                }
                assert_eq!(engine.event_receipts.len, 0);
                assert_eq!(
                    session.stats(),
                    untouched,
                    "compiler receipts belong only to explicit Run"
                );
                if failure == 3 {
                    assert!(
                        matches!(run.finish(true), Err(crate::proving::Error::IncompleteCoverage {
                    observation_errors, ..
                }) if observation_errors > 0)
                    );
                } else {
                    let report = run.finish(failure == 0).unwrap();
                    assert_eq!(report.observations.len(), 1);
                    assert_eq!(
                        report.observations[0].device_calls,
                        if failure == 0 {
                            (2 * CAPACITY + 2) as u64
                        } else {
                            5
                        }
                    );
                    assert_eq!(
                        report.observations[0].calls,
                        report.observations[0].completed_calls
                    );
                    assert_eq!(report.observation_errors == 0, failure == 0);
                    assert_eq!(report.stage_coverage_complete, failure == 0);
                }
                let mut words = [0u64; 4];
                output
                    .storage
                    .buffer
                    .read(&mut words[..])
                    .enq()
                    .map_err(|e| e.to_string())?;
                assert_eq!(&words[2..], &[GUARD; 2]);
            }
            Ok(())
        })
        .unwrap();
}
