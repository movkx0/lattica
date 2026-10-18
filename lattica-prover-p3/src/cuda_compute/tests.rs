//! Explicit device tests for the experimental transport, not proof qualification.
//! Run ignored tests serially with LATTICA_GPU_DEVICE_UUID and NVRTC configured.
use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

const SOURCE: &str = r#"
extern "C" __global__ void write_words(unsigned long long* output,
    unsigned int count, unsigned long long mask) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) output[i] = mask ^ (unsigned long long)i;
}
"#;

fn runtime(max_pending: usize) -> Runtime {
    let uuid = std::env::var("LATTICA_GPU_DEVICE_UUID")
        .expect("select the test GPU explicitly with LATTICA_GPU_DEVICE_UUID");
    Runtime::new(
        &uuid,
        Limits {
            managed_bytes: 512,
            max_allocation_bytes: 256,
            max_allocations: 2,
            max_modules: 1,
            max_pending,
            ..Limits::default()
        },
    )
    .unwrap()
}

fn launch(kernel: &Kernel, output: &Buffer) -> Completion {
    // The kernel writes exactly 17 u64 words, within the 18-word allocation;
    // the final word is a guard. Scalar widths match the CUDA signature.
    unsafe {
        kernel.launch(
            Launch {
                blocks: 2,
                threads: 16,
                shared_bytes: 0,
            },
            &[
                Argument::Buffer(output),
                Argument::U32(17),
                Argument::U64(0xfedc_ba98_7654_3210),
            ],
        )
    }
    .unwrap()
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_buffer_initialization_and_transfers_complete_before_compute() {
    // Device memset, pageable HtoD and DtoD copies can be asynchronous to the
    // host even through the legacy APIs. Exercise each immediately before a
    // dependent kernel on the runtime's nonblocking stream, using large enough
    // buffers that relying on incidental DMA completion is not sufficient.
    let count = 1 << 18;
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 16 << 20,
            max_allocation_bytes: 4 << 20,
            ..Limits::default()
        },
    )
    .unwrap();
    let field = FieldProgram::new(&runtime).unwrap();
    let output = runtime.allocate(count).unwrap();
    let mut observed = vec![0; count];
    let consume = |source: &Buffer| {
        field
            .apply(
                FieldOperation::Canonicalize,
                crate::gpu_matrix::Extension::Base,
                count,
                FieldSpan {
                    buffer: source,
                    first: 0,
                },
                None,
                FieldSpan {
                    buffer: &output,
                    first: 0,
                },
            )
            .unwrap()
            .finish()
            .unwrap();
    };
    for iteration in 0..4 {
        let input = runtime.allocate(count).unwrap();
        consume(&input);
        output.read(0, &mut observed).unwrap();
        assert!(observed.iter().all(|&word| word == 0));
        let words: Vec<_> = (0..count)
            .map(|i| (i as u64 * 31337) ^ (iteration + 1))
            .collect();
        input.write(0, &words).unwrap();
        consume(&input);
        output.read(0, &mut observed).unwrap();
        assert_eq!(observed, words);
        let copied = runtime.allocate(count).unwrap();
        copied.copy_from(0, &input, 0, count).unwrap();
        consume(&copied);
        output.read(0, &mut observed).unwrap();
        assert_eq!(observed, words);
        // Both private allocations are cleared and retired before the next
        // iteration can receive the allocator's recycled storage.
    }
    drop(output);
    drop(field);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().modules, 0);
}

#[test]
#[ignore = "requires an assigned CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_runtime_buffers_modules_events_and_leases() {
    let runtime = runtime(1);
    assert!(crate::gpu_lease::SingleDeviceLease::acquire(&runtime.identity().uuid).is_err());
    assert!(runtime.allocate(0).is_err());
    assert!(runtime.allocate(33).is_err());
    assert!(runtime.allocate(usize::MAX).is_err());
    assert_eq!(runtime.snapshot().allocations, 0);
    let output = runtime.allocate(18).unwrap();
    let cloned = output.clone();
    drop(output);
    assert_eq!(runtime.snapshot().live_bytes, 18 * 8);
    let mut words = [u64::MAX; 18];
    cloned.read(0, &mut words).unwrap();
    assert_eq!(words, [0; 18]);
    const GUARD: u64 = 0xa5a5_a5a5_dead_beef;
    cloned.write(17, &[GUARD]).unwrap();
    assert!(cloned.write(18, &[1]).is_err());
    assert!(cloned.read(usize::MAX, &mut [0; 1]).is_err());
    assert!(cloned.copy_from(1, &cloned, 0, 2).is_err());
    let copied = runtime.allocate(18).unwrap();
    assert!(runtime.allocate(1).is_err());
    copied.copy_from(0, &cloned, 0, 18).unwrap();
    copied.read(0, &mut words).unwrap();
    assert_eq!(words[17], GUARD);
    drop(copied);
    assert!(runtime.compile("not valid CUDA").is_err());
    assert_eq!(runtime.snapshot().modules, 0);
    let module = runtime.compile(SOURCE).unwrap();
    assert!(module.kernel("bad\0name").is_err());
    assert!(runtime.compile(SOURCE).is_err());
    let kernel = module.kernel("write_words").unwrap();
    drop(module);
    assert_eq!(runtime.snapshot().modules, 1);
    // Rejected before enqueue, so the missing arguments cannot reach the driver.
    assert!(unsafe {
        kernel.launch(
            Launch {
                blocks: 0,
                threads: 1,
                shared_bytes: 0,
            },
            &[],
        )
    }
    .is_err());
    let receipt = launch(&kernel, &cloned);
    assert_eq!(runtime.snapshot().pending_commands, 1);
    assert!(unsafe {
        kernel.launch(
            Launch {
                blocks: 1,
                threads: 1,
                shared_bytes: 0,
            },
            &[],
        )
    }
    .is_err());
    // Last module ownership may retire before the receipt, but must drain first.
    drop(kernel);
    assert_eq!(runtime.snapshot().modules, 0);
    receipt.finish().unwrap();
    assert_eq!(runtime.snapshot().pending_commands, 0);
    assert_eq!(runtime.snapshot().completed_commands, 1);
    cloned.read(0, &mut words).unwrap();
    for (i, word) in words[..17].iter().enumerate() {
        assert_eq!(*word, 0xfedc_ba98_7654_3210 ^ i as u64);
    }
    assert_eq!(words[17], GUARD);
    drop(cloned);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().allocations, 0);
    runtime.finish().unwrap();
    let uuid = runtime.identity().uuid.clone();
    drop(runtime);
    assert!(crate::gpu_lease::SingleDeviceLease::acquire(&uuid).is_ok());
}

#[test]
#[ignore = "requires an assigned CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_runtime_abandoned_receipt_drains_and_rejects_reuse() {
    let runtime = runtime(1);
    let output = runtime.allocate(18).unwrap();
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module.kernel("write_words").unwrap();
    drop(launch(&kernel, &output));
    assert_eq!(runtime.snapshot().pending_commands, 0);
    assert_eq!(runtime.snapshot().completed_commands, 0);
    assert!(runtime.finish().is_err());
    assert!(runtime.allocate(1).is_err());
    assert!(output.write(0, &[1]).is_err());
    drop(output);
    drop(kernel);
    drop(module);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().modules, 0);
}

#[test]
#[ignore = "requires an assigned CUDA GPU and NVRTC 12.9; run serially"]
fn cuda_runtime_unwind_retires_pending_resources() {
    let runtime = runtime(1);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let output = runtime.allocate(18).unwrap();
        let module = runtime.compile(SOURCE).unwrap();
        let kernel = module.kernel("write_words").unwrap();
        let _receipt = launch(&kernel, &output);
        panic!("injected host unwind after CUDA enqueue");
    }))
    .is_err());
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.live_bytes, 0);
    assert_eq!(snapshot.modules, 0);
    assert_eq!(snapshot.pending_commands, 0);
    assert!(runtime.finish().is_err());
}

#[test]
#[ignore = "deliberately triggers a CUDA API error; run separately from memcheck"]
fn cuda_runtime_missing_kernel_rejects_lookup() {
    let runtime = runtime(1);
    let module = runtime.compile(SOURCE).unwrap();
    assert!(module.kernel("missing").is_err());
    assert!(module.kernel("write_words").is_ok());
    drop(module);
    assert_eq!(runtime.snapshot().modules, 0);
    runtime.finish().unwrap();
}
