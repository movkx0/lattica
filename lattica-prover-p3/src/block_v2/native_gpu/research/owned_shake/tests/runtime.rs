//! Test-only refusal source: it cannot enter a production dispatch. The exact
//! ignored selector must run alone under the immutable native runtime guard.
use super::*;
use crate::{block_v2::native_gpu::shake_recording::ShakeRecorder, config::Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use std::panic::{catch_unwind, AssertUnwindSafe};

struct DegreeEight;
impl BaseAir<Val> for DegreeEight {
    fn width(&self) -> usize {
        census().geometry().width()
    }
    fn num_public_values(&self) -> usize {
        216
    }
    fn num_periodic_columns(&self) -> usize {
        42
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for DegreeEight {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let x: AB::Expr = main.current_slice()[0].into();
        // The actual normalized degree is eight. Fixed native metadata keeps
        // its original degree-seven hint and must reject before private trace.
        builder.assert_zero(x.square().square().square());
    }
}

fn over_degree_recording<'a>(
    preparation: &'a mut Reservation,
    ledger: &'a Ledger,
) -> PreparedShake<'a> {
    let mut recorder = ShakeRecorder::begin(census(), preparation, ledger).unwrap();
    DegreeEight.eval(recorder.builder_mut());
    for index in 0..42 {
        recorder.periodic_column_mut(index).unwrap();
    }
    recorder.finish().unwrap()
}

#[test]
#[ignore = "dedicated immutable env-clear RTX 5080 worker; fixed process/VRAM guard; coordinator only"]
fn gpu_fixed_native_rejection_retires_exact_runtime() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_NATIVE_SHAKE_REJECTION_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let ledger = ledger();
    // Fixture-only inline request/result/diagnostic owners are additive; the
    // actual recorder and configuration have their source-derived partitions.
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: 1 << 20,
                device: 0,
            },
        )
        .unwrap();
    let input = [1u8];
    let mut preparation = ledger.admit_phase(preparation_requirements()).unwrap();
    let plan = StartupPlan::new().unwrap();
    let startup = plan.footprint();
    let runtime_owner = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: startup.requested_host_bytes as u64,
                device: startup.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let verifier = ledger
        .reserve(
            Category::IndependentVerifier,
            Bytes {
                host: VERIFIER_HOST,
                device: 0,
            },
        )
        .unwrap();
    let output_plan = ShakeOutputPlan::new(census()).unwrap();
    let proof = ledger.admit_phase(output_plan.proof_requirement()).unwrap();
    let report = ledger
        .admit_phase(output_plan.report_requirement())
        .unwrap();
    let output = output_plan.claim(proof, report, &ledger).unwrap();
    // SAFETY: the coordinator launches only this exact ignored selector under
    // the immutable env-clear native device-tree process guard. No test mutates
    // environment or runs unrelated GPU work. Original owners precede inspect.
    let selection = unsafe { plan.inspect().unwrap() };
    let mut phase = unsafe {
        NativeShakePhase::new(
            census(),
            &preparation,
            &runtime_owner,
            output,
            &verifier,
            &ledger,
        )
        .unwrap()
    };
    let admitted = ledger.snapshot().current;
    assert_eq!(admitted.device, MANAGED_DEVICE);
    assert!(admitted.host <= WORKER_HOST);
    let recorded = over_degree_recording(&mut preparation, &ledger);
    // Declared after phase: runtime is retired/destroyed before every backing
    // claim on ordinary return and during unexpected unwinding.
    let mut runtime = selection.start().unwrap();
    runtime.recheck().unwrap();
    let first = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: original request, preparation, verifier and exact runtime
        // owners remain live. This fixed test recording intentionally violates
        // the closed metadata's degree bound; it must fail before private trace.
        unsafe { phase.produce(recorded, &input, &runtime, &runtime_owner, &verifier) }
    }));
    // Re-recording only gives the consumed method a valid-shaped argument: the
    // attempt flag must refuse before any second config/session/trace work.
    let retry = catch_unwind(AssertUnwindSafe(|| {
        let recorded = over_degree_recording(&mut preparation, &ledger);
        unsafe { phase.produce(recorded, &input, &runtime, &runtime_owner, &verifier) }
    }));
    let after_attempts = ledger.snapshot().current;
    // Always retire the exact runtime before inspecting either result/panic.
    // Phase, preparation, request, verifier, original runtime and output/report
    // claims remain live throughout retirement; no copied receipt replaces one.
    let retirement = runtime.retire();
    drop(runtime);
    assert_eq!(retirement.managed_live_bytes, 0);
    assert_eq!(retirement.host_tree_live_bytes, 0);
    assert!(retirement.lease_released);
    assert!(retirement.managed_peak_bytes <= MANAGED_DEVICE as usize);
    assert!(phase.attempted());
    assert!(matches!(&first, Ok(Err(Error::Normalization))));
    assert!(matches!(&retry, Ok(Err(Error::AlreadyAttempted))));
    assert_eq!(after_attempts, admitted);
    assert_eq!(ledger.snapshot().current, admitted);
    assert!(phase.output.is_some());
    assert!(phase.pcs_owner.belongs_to(&ledger));
    assert!(phase.wrappers.belongs_to(&ledger));
    assert!(preparation.belongs_to(&ledger));
    eprintln!(
        "ringct_owned_rejection managed_peak={} managed_live={} tree_live={} lease_released={}",
        retirement.managed_peak_bytes,
        retirement.managed_live_bytes,
        retirement.host_tree_live_bytes,
        retirement.lease_released
    );
    drop(first);
    drop(retry);
    drop(phase);
    drop(verifier);
    drop(runtime_owner);
    drop(preparation);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
