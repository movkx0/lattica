use super::*;
use crate::block_v2::machine::symbolic;

#[cfg(feature = "gpu-cuda")]
#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_symbolic_constraints_match_cpu_fingerprints_degrees_and_lookup_layouts() {
    use crate::cuda_compute::{Limits, PublicArithmetic, Runtime};
    use crate::proving::Policy;
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits::default(),
    )
    .unwrap();
    let context = PublicArithmetic::new(&runtime, 1 << 16).unwrap();
    let run = Run::new(
        "cuda_symbolic_conformance",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        PublicArithmetic::capabilities(Stage::Preprocessing).unwrap(),
    )
    .unwrap();
    let before = runtime.snapshot();
    let (_, report) = operate_cuda_in(&context, run, Stage::Preprocessing, |derive| {
        symbolic::reject_geometry(derive.compiler_constants());
        assert_eq!(runtime.snapshot(), before);
        symbolic::conformance(derive.compiler_constants());
        Ok(())
    })
    .unwrap();
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let observation = &report.observations[0];
    assert_eq!(observation.stage, Stage::Preprocessing);
    assert_eq!(observation.backend, Backend::Cuda);
    assert_eq!(
        observation.completed_calls,
        runtime.snapshot().completed_commands - before.completed_commands
    );
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_symbolic_constraints_match_cpu_fingerprints_degrees_and_lookup_layouts() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let (result, report) = operate_reported(
        Request::compatible(),
        "symbolic_conformance",
        Stage::Preprocessing,
        |derive| {
            symbolic::conformance(derive.compiler_constants());
            Err::<(), Error>("injected failure after symbolic construction".into())
        },
    )
    .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected failure after symbolic construction"
    );
    assert!(!report.succeeded && !report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let o = &report.observations[0];
    assert_eq!(o.stage, Stage::Preprocessing);
    assert_eq!(o.backend, Backend::OpenCl);
    assert_eq!(o.calls, o.completed_calls);
    assert!(o.completed_calls > 0 && o.device_ns > 0);
    assert_eq!(o.inclusive_ns, 0);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_symbolic_geometry_and_policy_reject_without_allocating_or_falling_back() {
    use crate::block_v2::{
        gpu_hash,
        machine::{compiler_constants::Constants, programs},
    };
    use crate::proving::{Capabilities, Policy, Profile};
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let (result, report) = operate_reported(
        Request::compatible(),
        "symbolic_admission",
        Stage::Preprocessing,
        |derive| {
            let before = gpu_hash::report("symbolic before admission").unwrap();
            symbolic::reject_geometry(derive.compiler_constants());
            let after = gpu_hash::report("symbolic after admission").unwrap();
            assert_eq!(before.allocations, after.allocations);
            assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
            Ok(())
        },
    )
    .unwrap();
    result.unwrap();
    assert!(report.observations.is_empty());
    let session = gpu_hash::device::DeviceSession::new().unwrap();
    let run = Run::new(
        "symbolic_policy",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        Capabilities::cpu(Profile::BlockV2Cubic, true, true),
    )
    .unwrap();
    let air = programs::shape(64).unwrap();
    let before = gpu_hash::report("symbolic before policy").unwrap();
    assert!(symbolic::prepare_machine(&air, Constants::device(&session, &run)).is_err());
    let after = gpu_hash::report("symbolic after policy").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    assert!(run.finish(false).unwrap().observations.is_empty());
}
