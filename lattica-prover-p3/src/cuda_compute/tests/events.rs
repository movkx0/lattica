use super::*;

#[test]
#[ignore = "requires an assigned CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_event_pool_reuses_only_consumed_receipts_and_retires_cached_owners() {
    let runtime = runtime(2);
    let budget = runtime.state.budget.clone();
    let uuid = runtime.identity().uuid.clone();
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    output.write(17, &[u64::MAX]).unwrap();
    let first = launch(&kernel, &output);
    let second = launch(&kernel, &output);
    assert_eq!(runtime.snapshot().event_pairs, 2);
    assert_eq!(runtime.snapshot().event_pairs_created, 2);
    assert!(unsafe {
        kernel.launch(
            Launch {
                blocks: 1,
                threads: 32,
                shared_bytes: 0,
            },
            &[
                Argument::Buffer(&output),
                Argument::U32(17),
                Argument::U64(123),
            ],
        )
    }
    .is_err());
    // Completing the later command does not consume the earlier receipt.
    second.finish().unwrap();
    assert_eq!(runtime.snapshot().pending_commands, 1);
    assert_eq!(runtime.snapshot().event_pairs, 2);
    for mask in 1..=128 {
        unsafe {
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
        .unwrap()
        .finish()
        .unwrap();
        let mut actual = [0; 18];
        output.read(0, &mut actual).unwrap();
        for (index, value) in actual[..17].iter().enumerate() {
            assert_eq!(*value, mask ^ index as u64);
        }
        assert_eq!(actual[17], u64::MAX);
    }
    assert_eq!(runtime.snapshot().event_pairs_created, 2);
    assert_eq!(runtime.snapshot().event_pairs_reused, 128);
    assert_eq!(runtime.snapshot().pending_commands, 1);
    first.finish().unwrap();
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.completed_commands, 130);
    assert_eq!(snapshot.pending_commands, 0);
    assert_eq!(snapshot.event_pairs, 2); // idle pairs still own their allowance
    drop(output);
    drop(kernel);
    drop(module);
    let retired = runtime.retire().unwrap();
    assert_eq!(retired.event_pairs, 0);
    assert_eq!(retired.peak_event_pairs, 2);
    assert_eq!(retired.event_pairs_created, 2);
    assert_eq!(retired.event_pairs_reused, 128);
    assert_eq!(budget.snapshot().event_pairs, 0);
    assert!(crate::gpu_lease::SingleDeviceLease::acquire(&uuid).is_ok());
}

#[test]
#[ignore = "requires an assigned CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_event_pool_abandoned_reused_receipt_poisoning_releases_all_owners() {
    let runtime = runtime(2);
    let budget = runtime.state.budget.clone();
    let uuid = runtime.identity().uuid.clone();
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    let first = launch(&kernel, &output);
    let second = launch(&kernel, &output);
    first.finish().unwrap();
    second.finish().unwrap();
    assert_eq!(runtime.snapshot().event_pairs, 2);
    drop(launch(&kernel, &output));
    assert_eq!(runtime.snapshot().event_pairs_reused, 1);
    assert_eq!(runtime.snapshot().event_pairs, 1); // abandoned pair is destroyed
    assert_eq!(runtime.snapshot().pending_commands, 0);
    assert!(runtime.finish().is_err());
    assert!(runtime.allocate(1).is_err());
    drop(kernel);
    drop(module);
    drop(output);
    drop(runtime);
    assert_eq!(budget.snapshot().event_pairs, 0);
    assert_eq!(budget.snapshot().modules, 0);
    assert_eq!(budget.snapshot().live_bytes, 0);
    assert!(crate::gpu_lease::SingleDeviceLease::acquire(&uuid).is_ok());
}

#[test]
#[ignore = "deliberate asynchronous CUDA fault; run separately from sanitizers"]
fn cuda_event_pool_async_failure_child() {
    if std::env::var_os("LATTICA_CUDA_EVENT_FAULT_CHILD").is_none() {
        return;
    }
    let runtime = runtime(1);
    let output = runtime.allocate(18).unwrap();
    let source = format!(
        "{SOURCE}\nextern \"C\" __global__ void event_pool_fault() {{ asm volatile(\"trap;\"); }}"
    );
    let module = runtime.compile(&source).unwrap();
    let warm = module.kernel("write_words").unwrap();
    launch(&warm, &output).finish().unwrap();
    assert_eq!(runtime.snapshot().event_pairs, 1);
    assert_eq!(runtime.snapshot().event_pairs_created, 1);
    let fault = module.kernel("event_pool_fault").unwrap();
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
    assert_eq!(runtime.snapshot().event_pairs_reused, 1);
    eprintln!("cuda_event_pool_async_fault reused_pair=true awaiting_completion=true");
    // The asynchronous error must poison the runtime; failed cleanup aborts
    // this child rather than returning a successful completion or retirement.
    receipt.finish().unwrap();
    panic!("asynchronous CUDA fault was not detected");
}

#[test]
#[ignore = "deliberate asynchronous CUDA fault; run separately from sanitizers"]
fn cuda_event_pool_async_failure_requires_process_retirement() {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cuda_compute::tests::events::cuda_event_pool_async_failure_child",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("LATTICA_CUDA_EVENT_FAULT_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGABRT));
    // Reap the failed owner before acquiring a new lease and CUDA context.
    let runtime = runtime(1);
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    launch(&kernel, &output).finish().unwrap();
    drop(kernel);
    drop(module);
    drop(output);
    let snapshot = runtime.retire().unwrap();
    assert_eq!(snapshot.completed_commands, 1);
    assert_eq!(snapshot.event_pairs, 0);
}
