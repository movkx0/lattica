use super::*;
use crate::block_v2::machine::ProgramBuilder;

#[test]
#[ignore = "requires OpenCL GPU; serial <=3 GiB zero-swap service"]
fn gpu_schedule_rejection_precedes_upload_and_preserves_session_reuse() {
    use crate::block_v2::gpu_hash::{self as engine, device::DeviceSession, Limits};
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let mut builder = ProgramBuilder::new(0).unwrap();
    for _ in 0..1000 {
        builder.input();
    }
    let source = builder.finish(None).unwrap();
    let mut program = WitnessProgram::compile(&source, 1 << 20).unwrap();
    program.schedule_host_bytes = WitnessSchedule::storage_bound(program.waves.len()).unwrap() - 1;
    let before = session.stats();
    let error = session.prepare_witness(Arc::new(program)).err().unwrap();
    assert!(error.contains("GPU witness schedule: TooLarge"));
    assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(session.stats().witness_programs, before.witness_programs);
    let restored = WitnessProgram::compile(&source, 1 << 20).unwrap();
    let expected = restored.words.len() * 8;
    let prepared = session.prepare_witness(Arc::new(restored)).unwrap();
    assert_eq!(
        session.stats().uploaded_bytes - before.uploaded_bytes,
        expected as u64
    );
    assert_eq!(
        session.stats().witness_programs - before.witness_programs,
        1
    );
    drop(prepared);
    drop(session);
    eprintln!("gpu_schedule_admission rejected_before_upload=true session_reused=true");
}

#[test]
fn witness_plan_accounts_for_output_inputs_wires_status_and_persistent_metadata() {
    let mut builder = ProgramBuilder::new(64).unwrap();
    for _ in 0..1000 {
        builder.input();
    }
    let program = WitnessProgram::compile(&builder.finish(Some(1024)).unwrap(), 1 << 20).unwrap();
    let live = program.words.len() * 8 + 4096;
    let schedule = WitnessSchedule::try_new(&program, program.schedule_host_bytes).unwrap();
    assert_eq!(&*schedule.waves, program.waves.as_slice());
    assert_eq!(schedule.preprocessing_width, program.preprocessing_width());
    assert!(
        std::mem::size_of::<WitnessSchedule>() + std::mem::size_of_val(&*schedule.waves)
            <= program.host_peak_bytes - program.words.len() * 8
    );
    drop(program);
    let program = schedule;
    let plan = Plan::new(&program, live, 64 << 20, 32 << 20, 1 << 20).unwrap();
    assert_eq!(
        plan.peak,
        live + plan.trace.bytes() + plan.scratch.iter().sum::<usize>() * 8
    );
    assert_eq!(plan.scratch, [1064, 1064, 1]);
    assert!(Plan::new(&program, live, plan.peak - 1, 32 << 20, 1 << 20).is_err());
    assert!(Plan::new(&program, live, 64 << 20, plan.trace.bytes() - 1, 1 << 20).is_err());
    assert!(Plan::new(&program, live, 64 << 20, 32 << 20, 1064 * 8 + 7).is_err());
    assert!(Plan::new(&program, live, plan.peak, plan.trace.bytes(), 1064 * 8 + 8).is_ok());
}
