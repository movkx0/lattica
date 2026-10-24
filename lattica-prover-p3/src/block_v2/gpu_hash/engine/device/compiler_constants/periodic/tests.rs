use super::*;

#[test]
fn periodic_geometry_and_full_workspace_are_admitted_before_allocation() {
    for log_n in 0..=MAX_PERIOD.ilog2() as usize {
        let n = 1usize << log_n;
        for height in [log_n, 32] {
            let plan = PeriodicPlan::new(n, height, n).unwrap();
            let specs = plan.specs().unwrap();
            let bytes = specs.iter().map(|s| s.bytes()).sum::<usize>();
            assert!(bytes as u64 <= PERIODIC_WORKSPACE_BYTES);
            assert!(specs
                .iter()
                .all(|s| s.bytes() as u64 <= PERIODIC_MAX_ALLOCATION_BYTES));
            let allocation_limit = PERIODIC_MAX_ALLOCATION_BYTES as usize;
            assert!(MemoryPlan::new(&specs, 0, bytes, allocation_limit).is_ok());
            assert!(MemoryPlan::new(&specs, 0, bytes - 1, allocation_limit).is_err());
            assert!(MemoryPlan::new(&specs, bytes, bytes, allocation_limit).is_err());
        }
    }
    let maximum = PeriodicPlan::new(MAX_PERIOD, 16, MAX_PERIOD)
        .unwrap()
        .specs()
        .unwrap();
    assert_eq!(
        maximum.iter().map(|s| s.bytes() as u64).sum::<u64>(),
        PERIODIC_WORKSPACE_BYTES
    );
    assert_eq!(PERIODIC_WORKSPACE_BYTES, 786448);
    assert!(PERIODIC_WORKSPACE_BYTES <= 2 << 20);
    for (n, height, output) in [
        (0, 0, 0),
        (3, 2, 3),
        (MAX_PERIOD * 2, 17, MAX_PERIOD * 2),
        (8, 2, 8),
        (8, 33, 8),
        (8, 3, 7),
    ] {
        assert!(PeriodicPlan::new(n, height, output).is_err());
    }
}

#[cfg(feature = "gpu")]
fn compiler_run() -> Run {
    use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, true, false)
        .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
    caps.set(Stage::Preprocessing, Backend::OpenCl);
    Run::new(
        "gpu_periodic_ntt_test",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        caps,
    )
    .unwrap()
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires OpenCL GPU; coordinator must run serially in a bounded service"]
fn gpu_periodic_ntt_matches_cpu_coefficients_and_retires_workspace() {
    use crate::block_v2::{gpu_hash, machine::compiler_constants::Constants};
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_quotient_test_engine(super::super::super::super::Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let live = || {
        session
            .with_engine(|engine| Ok(engine.accounting.lock().unwrap().live))
            .unwrap()
    };
    let before = live();
    for log_n in 0..=MAX_PERIOD.ilog2() as usize {
        let n = 1usize << log_n;
        let mut state = 0x1382_7f21_a941_d603u64;
        let mut column = (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                Val::new(state)
            })
            .collect::<Vec<_>>();
        // Include representatives above the modulus as well as sparse/constant inputs.
        column[0] = Val::new(u64::MAX);
        for kind in 0..3 {
            if kind == 1 {
                column.fill(Val::ONE);
            }
            if kind == 2 {
                column.fill(Val::ZERO);
                column[n / 2] = -Val::ONE;
            }
            let mut expected = vec![Val::ZERO; n];
            Constants::cpu()
                .periodic_into(&column, log_n, &mut expected)
                .unwrap();
            for height in [log_n, 32] {
                let run = compiler_run();
                let transfers = session.stats();
                let mut actual = vec![-Val::ONE; n];
                session
                    .compiler_periodic_into(&column, height, &mut actual, &run)
                    .unwrap();
                assert_eq!(actual, expected, "n={n}, kind={kind}, height={height}");
                assert_eq!(live(), before, "temporary compiler allocations must retire");
                let after = session.stats();
                assert_eq!(
                    after.uploaded_bytes - transfers.uploaded_bytes,
                    n as u64 * 8
                );
                assert_eq!(
                    after.downloaded_bytes - transfers.downloaded_bytes,
                    n as u64 * 8
                );
                let report = run.finish(true).unwrap();
                assert!(report.stage_coverage_complete && report.observation_errors == 0);
                assert_eq!(report.observations.len(), 1);
                let observation = &report.observations[0];
                let commands = if n == 1 { 2 } else { log_n as u64 + 3 };
                assert_eq!(observation.device_calls, commands);
                assert_eq!(observation.completed_calls, commands);
            }
        }
    }
    let run = compiler_run();
    let before_stats = session.stats();
    assert!(session
        .compiler_periodic_into(&[Val::ONE; 3], 2, &mut [Val::ZERO; 3], &run)
        .is_err());
    assert_eq!(session.stats(), before_stats);
    assert_eq!(live(), before);
    assert!(run.finish(false).unwrap().observations.is_empty());
}
