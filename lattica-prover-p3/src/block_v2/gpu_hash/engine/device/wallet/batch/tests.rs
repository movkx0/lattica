use super::*;
use crate::batch_htlc_air as batch_htlc;
use crate::batch_joinsplit_air as batch_js;
use crate::block_v2::gpu_hash;
use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
use p3_field::PrimeField64;

const HOST: usize = 512 << 20;

fn check_trace(actual: &[u64], expected: &[crate::config::Val]) {
    assert_eq!(actual.len(), expected.len());
    let mismatch = actual
        .iter()
        .zip(expected)
        .position(|(&a, b)| a != b.as_canonical_u64());
    assert_eq!(mismatch, None, "GPU batch trace differs from the CPU trace");
}

fn run() -> Run {
    let mut caps = Capabilities::cpu(Profile::LegacyQuadratic, false, false).scoped(
        CoverageScope::Operation,
        &[Stage::WitnessTrace, Stage::PublicValues],
    );
    caps.set(Stage::WitnessTrace, Backend::OpenCl);
    caps.set(Stage::PublicValues, Backend::OpenCl);
    Run::new(
        "gpu_legacy_batch_trace",
        Request {
            policy: Policy::GpuRequired,
            emit_report: true,
        },
        caps,
    )
    .unwrap()
}

#[test]
fn batch_geometry_and_aggregate_plan_reject_invalid_shapes_and_counts() {
    for count in [0usize, 1, 3, MAX_BATCH_TILES] {
        let plan = BatchPlan::new(
            batch_js::device_batch_geometry(),
            count,
            Plan::new(HOST).unwrap(),
            HOST,
        )
        .unwrap();
        assert_eq!(plan.tiles, count.max(1).next_power_of_two());
        assert_eq!(
            plan.trace.words(),
            plan.tiles * js::HEIGHT * batch_js::device_batch_geometry().batch_width
        );
        let plan = BatchPlan::new(
            batch_htlc::device_batch_geometry(),
            count,
            super::super::htlc::plan(HOST).unwrap(),
            HOST,
        )
        .unwrap();
        assert_eq!(plan.tiles, count.max(1).next_power_of_two());
    }
    assert!(BatchPlan::new(
        batch_js::device_batch_geometry(),
        usize::MAX,
        Plan::new(HOST).unwrap(),
        HOST
    )
    .is_err());
    assert!(BatchPlan::new(
        batch_js::device_batch_geometry(),
        1,
        Plan::new(HOST).unwrap(),
        1
    )
    .is_err());
    let mut layout = batch_js::device_batch_geometry();
    let mut chunks = layout.chunks.to_vec();
    chunks[0][0] = Some(layout.batch_width);
    layout.chunks = &chunks;
    assert!(BatchPlan::new(layout, 1, Plan::new(HOST).unwrap(), HOST).is_err());
    assert!(BatchPlan::new(
        batch_js::device_batch_geometry(),
        1,
        super::super::htlc::plan(HOST).unwrap(),
        HOST
    )
    .is_err());
}

#[test]
fn batch_staging_requires_the_combined_host_allowance_before_materialization() {
    let mut admission_host = 0;
    for (layout, single) in [
        (batch_js::device_batch_geometry(), Plan::new(HOST).unwrap()),
        (
            batch_htlc::device_batch_geometry(),
            super::super::htlc::plan(HOST).unwrap(),
        ),
    ] {
        let host = (11 + 4 * layout.chunks.len()) * 8 + single.staging_bytes().unwrap();
        admission_host = admission_host.max(host);
        for count in [0, 1, 3, MAX_BATCH_TILES] {
            // One byte below the complete staging shape must fail, even though
            // the individual wallet input buffer fits.
            assert!(BatchPlan::new(layout, count, single, host - 1).is_err());
            let plan = BatchPlan::new(layout, count, single, host).unwrap();
            let words = plan.words().unwrap();
            assert_eq!(words.len(), plan.geometry.words());
            assert_eq!(words.capacity(), words.len());
            assert_eq!(words[8], count.max(1).next_power_of_two() as u64);
        }
    }
    assert!(admission_extra(admission_host - 1).is_err());
    assert!(admission_extra(admission_host).is_ok());
}

#[test]
#[ignore = "requires selected OpenCL GPU and bounded zero-swap service"]
fn gpu_legacy_batch_traces_and_roots_match_cpu_with_device_padding() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    let columns = vec![
        vec![9],
        vec![1, crate::config::Val::ORDER_U64 - 1],
        vec![3, 4, 5, 6],
    ];
    for log_rows in [2u32, 5] {
        let before = session.stats();
        let matrix = session.periodic_matrix(log_rows, &columns, HOST).unwrap();
        assert_eq!(
            session.stats().uploaded_bytes - before.uploaded_bytes,
            13 * 8
        );
        assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
        let actual = session.read(&matrix, HOST).unwrap();
        let expected: Vec<_> = (0..(1usize << log_rows))
            .flat_map(|row| columns.iter().map(move |c| c[row % c.len()]))
            .collect();
        assert_eq!(actual, expected);
    }
    let before_periodic = gpu_hash::report("periodic_admission_before").unwrap();
    for invalid in [
        Vec::new(),
        vec![vec![0; 3]],
        vec![vec![0; 8]],
        vec![vec![u64::MAX]],
    ] {
        assert!(session.periodic_matrix(2, &invalid, HOST).is_err());
    }
    assert!(session.periodic_matrix(2, &columns, 1).is_err());
    let after_periodic = gpu_hash::report("periodic_admission_after").unwrap();
    assert_eq!(before_periodic.allocations, after_periodic.allocations);
    assert_eq!(
        before_periodic.uploaded_bytes,
        after_periodic.uploaded_bytes
    );
    eprintln!("legacy_batch_periodic_cpu_matched cases=2 invalid=5 expanded_upload_bytes=0");
    let invalid: Vec<_> = (0..=MAX_BATCH_TILES)
        .map(|_| batch_js::dummy_witness())
        .collect();
    let before = session.stats();
    let before_allocations = gpu_hash::report("batch_admission_before")
        .unwrap()
        .allocations;
    let joinsplit_host = (11 + 4 * batch_js::device_batch_geometry().chunks.len()) * 8
        + Plan::new(HOST).unwrap().staging_bytes().unwrap();
    let htlc_host = (11 + 4 * batch_htlc::device_batch_geometry().chunks.len()) * 8
        + super::super::htlc::plan(HOST)
            .unwrap()
            .staging_bytes()
            .unwrap();
    assert!(session
        .joinsplit_batch_witness(&[], joinsplit_host - 1, &run())
        .is_err());
    assert!(session
        .htlc_batch_witness(&[], htlc_host - 1, &run())
        .is_err());
    assert!(session
        .joinsplit_batch_witness(&invalid, HOST, &run())
        .is_err());
    assert!(session.joinsplit_batch_witness(&[], 1, &run()).is_err());
    assert_eq!(
        gpu_hash::report("batch_admission_after")
            .unwrap()
            .allocations,
        before_allocations
    );
    assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
    for count in [0usize, 1, 3, 4, MAX_BATCH_TILES] {
        let witnesses: Vec<_> = (0..count)
            .map(|i| {
                let mut w = js::demo_witness();
                w.mint = i as u64;
                w.outputs[0].value += i as u64;
                w
            })
            .collect();
        let run = run();
        let before = session.stats();
        let frame = session
            .joinsplit_batch_witness(&witnesses, joinsplit_host, &run)
            .unwrap();
        let generated = session.stats();
        let padded = batch_js::padded_tiles(count);
        let generated_tiles = count + usize::from(count < padded);
        assert_eq!(
            generated.downloaded_bytes - before.downloaded_bytes,
            generated_tiles as u64 * 8
        );
        let (trace, public) = frame.readback(&session, HOST).unwrap();
        let reference = batch_js::build_batch_trace(&witnesses);
        check_trace(&trace, &reference.values);
        assert_eq!(
            public,
            batch_js::batch_root(&witnesses).map(|v| v.as_canonical_u64())
        );
        assert!(run.finish(true).unwrap().stage_coverage_complete);
        eprintln!("legacy_batch_trace_cpu_matched kind=joinsplit count={count} padded={padded} intermediate_trace_readback_bytes=0");
    }
    for count in [0usize, 1, 3, 4, MAX_BATCH_TILES] {
        let witnesses: Vec<_> = (0..count)
            .map(|i| {
                let mut w = crate::htlc_air::demo_witness();
                w.fee += i as u64;
                w.outputs[0].value -= i as u64;
                w
            })
            .collect();
        let run = run();
        let before = session.stats();
        let frame = session
            .htlc_batch_witness(&witnesses, htlc_host, &run)
            .unwrap();
        let generated = session.stats();
        let padded = batch_js::padded_tiles(count);
        assert_eq!(
            generated.downloaded_bytes - before.downloaded_bytes,
            (count + usize::from(count < padded)) as u64 * 8
        );
        let (trace, public) = frame.readback(&session, HOST).unwrap();
        let reference = batch_htlc::build_batch_trace(&witnesses);
        check_trace(&trace, &reference.values);
        assert_eq!(
            public,
            batch_htlc::batch_root(&witnesses).map(|v| v.as_canonical_u64())
        );
        assert!(run.finish(true).unwrap().stage_coverage_complete);
        eprintln!("legacy_batch_trace_cpu_matched kind=htlc count={count} padded={padded} intermediate_trace_readback_bytes=0");
    }
    drop(session);
    gpu_hash::shutdown().unwrap();
}
