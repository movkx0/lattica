use super::*;
use crate::{
    cuda_compute::{Argument, Buffer, Completion, Kernel, Launch, Limits, Module},
    proving::{Capabilities, CoverageScope, Policy, Profile, Request},
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SOURCE: &str = r#"
extern "C" __global__ void receipt_write(unsigned long long* output) { output[0] = 73; }
"#;

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits::default(),
    )
    .unwrap()
}

fn run(stages: &[Stage]) -> Run {
    let mut capabilities = Capabilities::cpu(Profile::LegacyQuadratic, false, false)
        .scoped(CoverageScope::Operation, stages);
    for &stage in stages {
        capabilities.set(stage, Backend::Cuda);
    }
    Run::new(
        "cuda_receipt_test",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap()
}

fn kernel(runtime: &Runtime) -> (Module, Kernel, Buffer) {
    let module = runtime.compile(SOURCE).unwrap();
    let kernel = module
        .kernel_for_stage("receipt_write", Stage::Scalar)
        .unwrap();
    let output = runtime.allocate(1).unwrap();
    (module, kernel, output)
}

fn launch(kernel: &Kernel, output: &Buffer) -> Result<Completion> {
    // The kernel writes precisely the admitted one-word allocation.
    unsafe {
        kernel.launch(
            Launch {
                blocks: 1,
                threads: 1,
                shared_bytes: 0,
            },
            &[Argument::Buffer(output)],
        )
    }
}

#[test]
fn receipt_ledger_rejects_overflow_duplicate_and_closed_tickets() {
    let ledger = || {
        Arc::new(Ledger {
            owner: thread::current().id(),
            run: 1,
            allowed: [true; 16],
            data: Mutex::new(Data::default()),
        })
    };
    let l = ledger();
    let mut t = l.ticket(Some(Stage::Scalar)).unwrap();
    t.complete(9).unwrap();
    assert!(t.complete(9).is_err());
    assert_eq!(l.data.lock().unwrap().pending, 0);
    assert!(l.data.lock().unwrap().failed);
    let l = ledger();
    let mut t = l.ticket(Some(Stage::Scalar)).unwrap();
    l.data.lock().unwrap().stages[t.index].calls = u64::MAX;
    assert!(t.complete(1).is_err());
    drop(t);
    assert_eq!(l.data.lock().unwrap().pending, 0);
    let l = ledger();
    let mut t = l.ticket(Some(Stage::Scalar)).unwrap();
    l.data.lock().unwrap().closed = true;
    assert!(t.complete(1).is_err());
    assert!(l.ticket(Some(Stage::Scalar)).is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_match_observed_events_without_changing_unreported_callers() {
    let runtime = runtime();
    let (_module, kernel, output) = kernel(&runtime);
    let old = launch(&kernel, &output).unwrap();
    assert!(!old.is_reported());
    old.finish().unwrap();
    let run = run(&[Stage::Scalar]);
    let before = runtime.snapshot();
    let elapsed = runtime
        .reported(&run, || {
            let first = launch(&kernel, &output)?;
            assert!(first.is_reported());
            Ok(u128::from(first.finish()?) + u128::from(launch(&kernel, &output)?.finish()?))
        })
        .unwrap();
    let after = runtime.snapshot();
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let receipt = &report.observations[0];
    assert_eq!(receipt.device_calls, 2);
    assert_eq!(
        receipt.device_calls,
        after.completed_commands - before.completed_commands
    );
    assert_eq!(receipt.device_ns, elapsed);
    assert_eq!(receipt.device_ns, after.device_ns - before.device_ns);
    assert_eq!(receipt.inclusive_ns, 0);
    let mut word = [0];
    output.read(0, &mut word).unwrap();
    assert_eq!(word, [73]);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_reject_unlabelled_and_unadmitted_commands_even_if_error_is_caught() {
    let runtime = runtime();
    let (module, kernel, output) = kernel(&runtime);
    for rejected in [
        module.kernel("receipt_write").unwrap(),
        kernel.clone().with_stage(Stage::Transform),
    ] {
        let run = run(&[Stage::Scalar]);
        let before = runtime.snapshot();
        assert!(runtime
            .reported(&run, || {
                assert!(launch(&rejected, &output).is_err());
                Ok(())
            })
            .is_err());
        let report = run.finish(false).unwrap();
        assert!(report.observation_errors > 0);
        assert!(report.observations.is_empty());
        assert_eq!(runtime.snapshot(), before);
    }
    let fresh = run(&[Stage::Scalar]);
    runtime
        .reported(&fresh, || launch(&kernel, &output)?.finish())
        .unwrap();
    assert!(fresh.finish(true).unwrap().stage_coverage_complete);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_enforce_run_and_thread_binding_and_reject_nested_scopes() {
    let runtime = runtime();
    let (_module, kernel, output) = kernel(&runtime);
    let owner = run(&[Stage::Scalar]);
    let other = run(&[Stage::Scalar]);
    runtime
        .reported(&owner, || {
            assert!(runtime.reported(&owner, || Ok(())).is_err());
            assert!(runtime.reported(&other, || Ok(())).is_err());
            assert!(runtime.check_report_run(&other).is_err());
            runtime.check_report_run(&owner)?;
            let foreign = runtime.clone();
            assert!(std::thread::spawn(move || foreign.allocate(1))
                .join()
                .unwrap()
                .is_err());
            launch(&kernel, &output)?.finish()
        })
        .unwrap();
    assert!(owner.finish(true).unwrap().stage_coverage_complete);
    assert!(other.finish(true).is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_require_quiescence_and_cannot_reuse_earlier_completions() {
    let runtime = runtime();
    let (_module, kernel, output) = kernel(&runtime);
    let old = launch(&kernel, &output).unwrap();
    let attempt = run(&[Stage::Scalar]);
    assert!(runtime.reported(&attempt, || Ok(())).is_err());
    old.finish().unwrap();
    runtime.reported(&attempt, || Ok(())).unwrap();
    assert!(attempt.finish(true).is_err());
    let attempt = run(&[Stage::Scalar, Stage::Transform]);
    runtime
        .reported(&attempt, || {
            assert!(attempt
                .measure(Stage::Transform, Backend::Cpu, || ())
                .is_err());
            attempt
                .measure(Stage::Transform, Backend::Cuda, || ())
                .map_err(error)?;
            launch(&kernel, &output)?.finish()
        })
        .unwrap();
    assert!(attempt.finish(true).is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_retain_completed_work_on_error_and_unwind_and_allow_fresh_attempts() {
    let runtime = runtime();
    let (_module, kernel, output) = kernel(&runtime);
    for unwind in [false, true] {
        let attempt = run(&[Stage::Scalar]);
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.reported(&attempt, || -> Result<()> {
                launch(&kernel, &output)?.finish()?;
                if unwind {
                    panic!("injected receipt unwind");
                }
                Err("injected receipt failure".into())
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        let report = attempt.finish(false).unwrap();
        assert!(!report.stage_coverage_complete);
        assert!(report.observation_errors > 0);
        assert_eq!(report.observations[0].device_calls, 1);
        assert_eq!(runtime.snapshot().pending_commands, 0);
        let fresh = run(&[Stage::Scalar]);
        runtime
            .reported(&fresh, || launch(&kernel, &output)?.finish())
            .unwrap();
        assert!(fresh.finish(true).unwrap().stage_coverage_complete);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_receipts_poison_runtime_for_abandoned_or_escaping_commands() {
    for abandon in [false, true] {
        let runtime = runtime();
        let (_module, kernel, output) = kernel(&runtime);
        let attempt = run(&[Stage::Scalar]);
        let mut escaped = None;
        assert!(runtime
            .reported(&attempt, || {
                let command = launch(&kernel, &output)?;
                if abandon {
                    drop(command);
                } else {
                    escaped = Some(command);
                }
                Ok(())
            })
            .is_err());
        if let Some(command) = escaped {
            assert!(command.finish().is_err());
        }
        assert_eq!(runtime.snapshot().pending_commands, 0);
        assert!(runtime.allocate(1).is_err());
        assert!(attempt.finish(true).is_err());
        let fresh = run(&[Stage::Scalar]);
        assert!(runtime.reported(&fresh, || Ok(())).is_err());
        assert!(fresh.finish(true).is_err());
    }
}
