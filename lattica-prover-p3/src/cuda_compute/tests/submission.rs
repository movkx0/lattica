use super::*;
use crate::cuda_compute::kernel::SubmissionBatch;

#[test]
#[ignore = "requires CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_submission_batches_respect_live_receipts_and_finish_every_command() {
    for limit in [1, 2, 4] {
        let runtime = runtime(limit);
        let output = runtime.allocate(18).unwrap();
        output.write(17, &[u64::MAX]).unwrap();
        let module = runtime.compile(SOURCE).unwrap();
        let kernel = module.kernel("write_words").unwrap();
        let preceding = launch(&kernel, &output);
        if limit == 1 {
            assert!(SubmissionBatch::new(&runtime, 7).is_err());
            preceding.finish().unwrap();
        } else {
            let mut batch = SubmissionBatch::new(&runtime, 7).unwrap();
            for _ in 0..7 {
                batch.push(launch(&kernel, &output)).unwrap();
                assert!(runtime.snapshot().pending_commands <= limit);
                assert!(runtime.snapshot().event_pairs <= limit);
            }
            batch.finish().unwrap();
            // Finishing later events must not consume the earlier receipt.
            assert_eq!(runtime.snapshot().pending_commands, 1);
            preceding.finish().unwrap();
        }
        let mut batch = SubmissionBatch::new(&runtime, 5).unwrap();
        for mask in 1..=5 {
            let receipt = unsafe {
                kernel.launch(
                    Launch {
                        blocks: 1,
                        threads: 32,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&output),
                        Argument::U32(17),
                        Argument::U64(mask),
                    ],
                )
            }
            .unwrap();
            batch.push(receipt).unwrap();
        }
        batch.finish().unwrap();
        let mut actual = [0; 18];
        output.read(0, &mut actual).unwrap();
        for (index, word) in actual[..17].iter().enumerate() {
            assert_eq!(*word, 5 ^ index as u64);
        }
        assert_eq!(actual[17], u64::MAX);
        assert_eq!(runtime.snapshot().pending_commands, 0);
        assert_eq!(
            runtime.snapshot().completed_commands,
            if limit == 1 { 6 } else { 13 }
        );
        drop(kernel);
        drop(module);
        drop(output);
        let retired = runtime.retire().unwrap();
        assert_eq!(retired.event_pairs, 0);
        assert!(retired.peak_event_pairs <= limit);
    }
}

#[test]
#[ignore = "requires CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_abandoned_submission_batch_invalidates_runtime_and_releases_owners() {
    let runtime = runtime(4);
    let budget = runtime.state.budget.clone();
    let uuid = runtime.identity().uuid.clone();
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    let mut batch = SubmissionBatch::new(&runtime, 3).unwrap();
    batch.push(launch(&kernel, &output)).unwrap();
    batch.push(launch(&kernel, &output)).unwrap();
    assert_eq!(runtime.snapshot().pending_commands, 2);
    drop(batch);
    assert!(runtime.finish().is_err());
    assert_eq!(runtime.snapshot().pending_commands, 0);
    drop(kernel);
    drop(module);
    drop(output);
    drop(runtime);
    assert_eq!(budget.snapshot().event_pairs, 0);
    assert_eq!(budget.snapshot().live_bytes, 0);
    assert!(crate::gpu_lease::SingleDeviceLease::acquire(&uuid).is_ok());
}

#[test]
#[ignore = "child for an intentional asynchronous fault; run only through the parent"]
fn cuda_submission_async_failure_child() {
    if std::env::var_os("LATTICA_CUDA_SUBMISSION_FAULT_CHILD").is_none() {
        return;
    }
    let runtime = runtime(2);
    let output = runtime.allocate(18).unwrap();
    let source =
        format!("{SOURCE}\nextern \"C\" __global__ void submission_fault() {{ asm(\"trap;\"); }}");
    let module = runtime.compile(&source).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    let mut batch = SubmissionBatch::new(&runtime, 2).unwrap();
    batch.push(launch(&kernel, &output)).unwrap();
    assert_eq!(runtime.snapshot().pending_commands, 1);
    eprintln!("submission_fault pending_batch_receipts=1");
    let fault = module.kernel("submission_fault").unwrap();
    let receipt = unsafe {
        fault.launch(
            Launch {
                blocks: 1,
                threads: 1,
                shared_bytes: 0,
            },
            &[],
        )
    }
    .unwrap();
    batch.push(receipt).unwrap();
    panic!("asynchronous CUDA submission fault was not detected");
}

#[test]
#[ignore = "deliberate asynchronous CUDA fault; run separately from sanitizers"]
fn cuda_submission_async_failure_requires_process_retirement() {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cuda_compute::tests::submission::cuda_submission_async_failure_child",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("LATTICA_CUDA_SUBMISSION_FAULT_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGABRT));
    let runtime = runtime(2);
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    let mut batch = SubmissionBatch::new(&runtime, 2).unwrap();
    batch.push(launch(&kernel, &output)).unwrap();
    batch.push(launch(&kernel, &output)).unwrap();
    batch.finish().unwrap();
    drop(kernel);
    drop(module);
    drop(output);
    let retired = runtime.retire().unwrap();
    assert_eq!(retired.completed_commands, 2);
    assert_eq!(retired.event_pairs, 0);
}
