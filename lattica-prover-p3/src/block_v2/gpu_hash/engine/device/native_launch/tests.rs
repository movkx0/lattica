use super::*;
use driver::{Api, Argument, Handles, Scope};
use std::cell::{Cell, RefCell};

#[test]
fn arithmetic_metadata_mutations_fail_before_a_driver_can_be_selected() {
    use crate::block_v2::native_gpu::operations_arithmetic::{CanonicalOperation, SignedOperation};
    let specs = [
        ArithmeticOperationSpec::canonical(CanonicalOperation::Add, 256, 167770241).unwrap(),
        ArithmeticOperationSpec::signed(SignedOperation::Subtract, 256).unwrap(),
        ArithmeticOperationSpec::ntt(
            3489661057,
            1,
            &[[0, 128, 1, 1]; 768],
            &core::array::from_fn::<_, 64, _>(|i| i as u64),
        )
        .unwrap(),
        ArithmeticOperationSpec::mul(167770241, 1, &[[1, 0]; 1024]).unwrap(),
        ArithmeticOperationSpec::automorphism(
            &core::array::from_fn::<_, 256, _>(|i| i as u64),
            &[1; 256],
        )
        .unwrap(),
    ];
    for original in specs {
        assert!(ArithmeticShape::check(&original).is_ok());
        for change in 0..6 {
            let mut altered = original.clone();
            match change {
                0 => altered.metadata[0] = u64::MAX,
                1 => altered.metadata[2] = usize::MAX as u64,
                2 => altered.metadata[3] += 1,
                3 => altered.input_words += 1,
                4 => altered.work_items += 1,
                _ => {
                    altered.metadata.pop();
                }
            }
            assert!(ArithmeticShape::check(&altered).is_err());
        }
        if original.metadata[0] == 7 {
            let mut altered = original.clone();
            altered.metadata[4] = 256;
            assert!(ArithmeticShape::check(&altered).is_err());
            let mut altered = original.clone();
            altered.metadata[3139] = altered.metadata[3138];
            assert!(ArithmeticShape::check(&altered).is_err());
        }
    }
}

#[test]
fn crypto_profiles_preserve_geometry_and_reject_counter_wrap() {
    let aes = CryptoShape::new(
        CryptoKind::Aes {
            domain: 99,
            counter: 7,
        },
        32,
        186160,
    )
    .unwrap();
    assert_eq!(aes.geometry, [0, 32, 186160, 99, 7]);
    assert_eq!(aes.words, [32, 5, 16896, 186161]);
    assert_eq!(aes.launch_count, 2);
    assert_eq!(
        aes.launches,
        [(Kernel::AesSboxes, 256), (Kernel::Aes, 11635)]
    );
    assert!(CryptoShape::new(
        CryptoKind::Aes {
            domain: 0,
            counter: u32::MAX
        },
        32,
        17
    )
    .is_err());
    assert!(CryptoShape::new(CryptoKind::SparseAlpha, 127, 256).is_ok());
    assert!(CryptoShape::new(CryptoKind::SparseX, 137, 256).is_ok());
    assert!(CryptoShape::new(CryptoKind::SparseX, 127, 256).is_err());
    assert!(CryptoShape::new(CryptoKind::Shake, usize::MAX, 1).is_err());
}

#[test]
fn typed_signatures_are_linked_to_the_actual_kernel_sources() {
    fn compact(source: &str) -> String {
        source.chars().filter(|c| !c.is_whitespace()).collect()
    }
    let arithmetic = compact(include_str!("../operations_arithmetic.cl"));
    assert!(arithmetic.contains("__kernelvoidpq_graph_arithmetic(__globalconstulong*input,__globalconstulong*metadata,__globalulong*output,__globalulong*status){"));
    let node = compact(include_str!("../pq_operations.cl"));
    assert!(node.contains("__kernelvoidpq_operation_commit_node(__globalconstulong*raw,uintkind,ulongmodulus,__globalulong*output,__globalconstulong*rci,__globalconstulong*rcp,__globalconstulong*rcf,__globalconstulong*diag){"));
    let crypto = compact(include_str!("../pq_raw_crypto.cl"));
    assert!(crypto.contains("#definePQ_RAW_ARGS__globalconstulong*input,__globalconstulong*g,__globalulong*scratch,__globalulong*output"));
    for kernel in [
        Kernel::AesSboxes,
        Kernel::Aes,
        Kernel::Shake,
        Kernel::Uniform,
        Kernel::Sparse,
    ] {
        assert!(crypto.contains(&format!("__kernelvoid{}(PQ_RAW_ARGS){{", kernel.label())));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    None,
    Queue,
    Create,
    Signature,
    Upload,
    Clear,
    Argument,
    Enqueue,
    Finish(usize),
    Status,
    Start,
    End,
    ReleaseEvent,
    ReleaseKernel,
    OwnerDrop,
}
struct Fixture {
    calls: RefCell<([Call; 128], usize)>,
    failure: Cell<Option<Phase>>,
    persistent_failure: Cell<bool>,
    wrong_signature: Cell<bool>,
    async_status: Cell<i32>,
    backwards_time: Cell<bool>,
    last_arguments: Cell<u32>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            calls: RefCell::new(([Call::None; 128], 0)),
            failure: Cell::new(None),
            persistent_failure: Cell::new(false),
            wrong_signature: Cell::new(false),
            async_status: Cell::new(0),
            backwards_time: Cell::new(false),
            last_arguments: Cell::new(4),
        }
    }
    fn log(&self, call: Call) {
        let mut log = self.calls.borrow_mut();
        let index = log.1;
        log.0[index] = call;
        log.1 += 1;
    }
    fn code(&self, phase: Phase) -> i32 {
        if self.failure.get() == Some(phase) {
            if !self.persistent_failure.get() {
                self.failure.set(None);
            }
            -42
        } else {
            0
        }
    }
    fn count(&self, call: Call) -> usize {
        let log = self.calls.borrow();
        log.0[..log.1].iter().filter(|&&v| v == call).count()
    }
    fn ordered_retirement(&self) {
        let log = self.calls.borrow();
        let calls = &log.0[..log.1];
        let first_retire = calls
            .iter()
            .position(|v| matches!(v, Call::ReleaseEvent | Call::ReleaseKernel))
            .unwrap();
        assert!(calls[..first_retire].contains(&Call::Finish(2)));
        assert!(calls[..first_retire].contains(&Call::Finish(1)));
        assert_eq!(calls.last(), Some(&Call::OwnerDrop));
    }
}
struct Probe<'a>(&'a Fixture);
impl Drop for Probe<'_> {
    fn drop(&mut self) {
        self.0.log(Call::OwnerDrop);
    }
}
struct Mock<'a>(&'a Fixture);
impl Api for Mock<'_> {
    fn queue_properties(&mut self, _: ffi::cl_command_queue) -> (u64, usize, i32) {
        self.0.log(Call::Queue);
        (ffi::CL_QUEUE_PROFILING_ENABLE, 8, self.0.code(Phase::Queue))
    }
    fn create(&mut self, _: ffi::cl_program, name: &core::ffi::CStr) -> (ffi::cl_kernel, i32) {
        self.0.log(Call::Create);
        self.0
            .last_arguments
            .set(if name == Kernel::Node.name() { 8 } else { 4 });
        (100usize as _, self.0.code(Phase::Create))
    }
    fn argument_count(&mut self, _: ffi::cl_kernel) -> (u32, usize, i32) {
        self.0.log(Call::Signature);
        (
            self.0.last_arguments.get() + u32::from(self.0.wrong_signature.get()),
            4,
            self.0.code(Phase::Signature),
        )
    }
    fn upload(&mut self, _: ffi::cl_command_queue, _: ffi::cl_mem, _: usize, _: &[u64]) -> i32 {
        self.0.log(Call::Upload);
        self.0.code(Phase::Upload)
    }
    fn clear(&mut self, _: ffi::cl_command_queue, _: ffi::cl_mem, _: usize) -> i32 {
        self.0.log(Call::Clear);
        self.0.code(Phase::Clear)
    }
    fn argument(&mut self, _: ffi::cl_kernel, _: u32, _: Argument) -> i32 {
        self.0.log(Call::Argument);
        self.0.code(Phase::Argument)
    }
    fn enqueue(
        &mut self,
        _: ffi::cl_command_queue,
        _: ffi::cl_kernel,
        _: usize,
    ) -> (ffi::cl_event, i32) {
        self.0.log(Call::Enqueue);
        (200usize as _, self.0.code(Phase::Enqueue))
    }
    fn finish(&mut self, queue: ffi::cl_command_queue) -> i32 {
        self.0.log(Call::Finish(queue as usize));
        self.0.code(if queue as usize == 2 {
            Phase::FinishCopy
        } else {
            Phase::FinishCompute
        })
    }
    fn event_status(&mut self, _: ffi::cl_event) -> (i32, usize, i32) {
        self.0.log(Call::Status);
        (
            self.0.async_status.get(),
            4,
            self.0.code(Phase::EventStatus),
        )
    }
    fn timestamp(&mut self, _: ffi::cl_event, end: bool) -> (u64, usize, i32) {
        self.0.log(if end { Call::End } else { Call::Start });
        (
            if end {
                if self.0.backwards_time.get() {
                    99
                } else {
                    150
                }
            } else {
                100
            },
            8,
            self.0.code(if end {
                Phase::ProfileEnd
            } else {
                Phase::ProfileStart
            }),
        )
    }
    fn release_event(&mut self, _: ffi::cl_event) -> i32 {
        self.0.log(Call::ReleaseEvent);
        self.0.code(Phase::ReleaseEvent)
    }
    fn release_kernel(&mut self, _: ffi::cl_kernel) -> i32 {
        self.0.log(Call::ReleaseKernel);
        self.0.code(Phase::ReleaseKernel)
    }
}
fn handles() -> Handles {
    Handles {
        program: 3usize as _,
        compute: 1usize as _,
        copy: 2usize as _,
    }
}
fn args() -> [Argument; 4] {
    [4usize, 5, 6, 7].map(|v| Argument::Memory(v as _))
}

#[test]
fn both_queues_and_real_owners_outlive_partial_launch_failure() {
    for phase in [
        Phase::Create,
        Phase::Signature,
        Phase::Argument,
        Phase::Enqueue,
        Phase::FinishCopy,
        Phase::FinishCompute,
        Phase::EventStatus,
        Phase::ProfileStart,
        Phase::ProfileEnd,
    ] {
        let fixture = Fixture::new();
        fixture.failure.set(Some(phase));
        let probe = Probe(&fixture);
        let mut api = Mock(&fixture);
        let result = {
            let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Arithmetic).unwrap();
            match scope.launch(Kernel::Arithmetic, &args(), 1) {
                Ok(()) => scope.complete(),
                Err(error) => Err(error),
            }
        };
        let failure = result.unwrap_err();
        assert_eq!(failure.phase, phase);
        assert_eq!(failure.status, -42);
        assert_eq!(fixture.count(Call::Create), 1); // no dispatch retry
        drop(probe);
        fixture.ordered_retirement();
        assert_eq!(fixture.count(Call::ReleaseKernel), 1);
        assert_eq!(
            fixture.count(Call::Enqueue),
            usize::from(!matches!(
                phase,
                Phase::Create | Phase::Signature | Phase::Argument
            ))
        );
    }
}

#[test]
fn wrong_signature_and_typed_argument_mismatch_never_enqueue() {
    let fixture = Fixture::new();
    fixture.wrong_signature.set(true);
    let probe = Probe(&fixture);
    let mut api = Mock(&fixture);
    {
        let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Arithmetic).unwrap();
        assert_eq!(
            scope
                .launch(Kernel::Arithmetic, &args(), 1)
                .unwrap_err()
                .phase,
            Phase::Signature
        );
    }
    assert_eq!(fixture.count(Call::Argument), 0);
    assert_eq!(fixture.count(Call::Enqueue), 0);
    drop(probe);
    fixture.ordered_retirement();
    let fixture = Fixture::new();
    let probe = Probe(&fixture);
    let mut api = Mock(&fixture);
    let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Arithmetic).unwrap();
    assert_eq!(
        scope
            .launch(Kernel::Arithmetic, &[Argument::Uint(1); 4], 1)
            .unwrap_err()
            .phase,
        Phase::Argument
    );
    assert_eq!(fixture.count(Call::Create), 0);
}

#[test]
fn two_native_aes_kernels_complete_before_receipts_escape() {
    let fixture = Fixture::new();
    let probe = Probe(&fixture);
    let mut api = Mock(&fixture);
    let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::AesSboxes).unwrap();
    scope.launch(Kernel::AesSboxes, &args(), 256).unwrap();
    scope.launch(Kernel::Aes, &args(), 1).unwrap();
    let complete = scope.complete().unwrap();
    assert_eq!(complete.kernels.map(|v| v.unwrap().nanoseconds), [50; 2]);
    assert_eq!(fixture.count(Call::ReleaseEvent), 2);
    assert_eq!(fixture.count(Call::ReleaseKernel), 2);
    drop(probe);
    fixture.ordered_retirement();
}

#[test]
fn asynchronous_status_and_invalid_timestamps_cannot_make_success_receipts() {
    for backwards in [false, true] {
        let fixture = Fixture::new();
        fixture.backwards_time.set(backwards);
        fixture.async_status.set(if backwards { 0 } else { -14 });
        let probe = Probe(&fixture);
        let mut api = Mock(&fixture);
        let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Shake).unwrap();
        scope.launch(Kernel::Shake, &args(), 1).unwrap();
        let failure = scope.complete().unwrap_err();
        assert_eq!(
            failure.phase,
            if backwards {
                Phase::ProfileEnd
            } else {
                Phase::EventStatus
            }
        );
        drop(probe);
        fixture.ordered_retirement();
    }
}

#[test]
fn diagnostics_preserve_signed_driver_codes_in_fixed_storage() {
    for status in [i32::MIN, -42, 0, i32::MAX] {
        let error = Failure::at(Kernel::Node, Phase::FinishCompute, u8::MAX, status);
        let text = error.diagnostic();
        assert!(text.len < text.bytes.len());
        assert!(text.to_string().contains(&format!("status={status}")));
        assert!(text.to_string().contains("pq_operation_commit_node"));
    }
}

#[test]
fn panic_during_an_active_launch_drains_before_owner_destruction() {
    let fixture = Fixture::new();
    let probe = Probe(&fixture);
    let mut api = Mock(&fixture);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Shake).unwrap();
        scope.launch(Kernel::Shake, &args(), 1).unwrap();
        panic!("injected failure after enqueue");
    }));
    assert!(panic.is_err());
    drop(probe);
    fixture.ordered_retirement();
    assert_eq!(fixture.count(Call::ReleaseEvent), 1);
    assert_eq!(fixture.count(Call::ReleaseKernel), 1);
}

#[cfg(feature = "stream")]
#[test]
fn mock_scope_and_bounded_diagnostics_make_no_rust_heap_requests() {
    let fixture = Fixture::new();
    let probe = Probe(&fixture);
    let mut api = Mock(&fixture);
    let (completion, requests) = crate::spill_alloc::allocation_requests::measure(|| {
        let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::AesSboxes).unwrap();
        scope.launch(Kernel::AesSboxes, &args(), 256).unwrap();
        scope.launch(Kernel::Aes, &args(), 1).unwrap();
        let diagnostic = Failure::at(Kernel::Node, Phase::ProfileEnd, 255, i32::MIN).diagnostic();
        assert!(diagnostic.len > 0);
        scope.complete().unwrap()
    });
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
    assert!(completion.kernels.iter().all(Option::is_some));
}

#[test]
#[ignore = "serialized child-process abort audit; no GPU; child core dumps are disabled"]
fn uncertain_cleanup_aborts_before_owners_can_retire() {
    const CHILD: &str = "LATTICA_NATIVE_LAUNCH_ABORT_AUDIT";
    if let Ok(case) = std::env::var(CHILD) {
        let phase = match case.as_str() {
            "drain" => Phase::FinishCompute,
            "event" => Phase::ReleaseEvent,
            "kernel" => Phase::ReleaseKernel,
            _ => panic!("invalid abort-audit case"),
        };
        let fixture = Fixture::new();
        let probe = Probe(&fixture);
        let mut api = Mock(&fixture);
        let mut scope = Scope::new(&probe, handles(), &mut api, Kernel::Shake).unwrap();
        scope.launch(Kernel::Shake, &args(), 1).unwrap();
        fixture.failure.set(Some(phase));
        fixture.persistent_failure.set(true);
        drop(scope);
        panic!("uncertain cleanup returned to caller");
    }
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let module = module_path!().split_once("::").unwrap().1;
    let test = format!("{module}::uncertain_cleanup_aborts_before_owners_can_retire");
    for case in ["drain", "event", "kernel"] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                &test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, case);
        // SAFETY: child pre-exec performs only the async-signal-safe setrlimit
        // syscall; no allocator, mutex, environment write or Rust formatting.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let result = command.output().unwrap();
        assert_eq!(result.status.signal(), Some(libc::SIGABRT));
        let stderr = core::str::from_utf8(&result.stderr).unwrap();
        assert!(stderr.contains("native_launch kernel=pq_raw_shake"));
        assert!(stderr.contains("status=-42"));
        assert!(!stderr.contains("uncertain cleanup returned"));
    }
}
