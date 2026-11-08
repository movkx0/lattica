use super::super::*;
use crate::block_v2::machine::{gpu_program::WitnessProgram, MachineAir, ProgramBuilder};
use crate::config::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

#[test]
#[ignore = "requires OpenCL GPU; run serially under the zero-swap resource guard"]
fn gpu_fused_witness_matches_cpu_and_preserves_errors_across_wide_boundaries() {
    let _shutdown = TestShutdownGuard;
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    let mut narrow = [input; 8];
    for _ in 0..40 {
        narrow = builder.poseidon(narrow);
    }
    let wide: Vec<_> = (0..513)
        .map(|i| {
            let c = builder.constant(Val::from_usize(i));
            builder.add(narrow[0], c)
        })
        .collect();
    let mut last = wide[512];
    for _ in 0..65 {
        last = builder.mul(last, input);
    }
    // A failing lane returns from the instruction helper, not the barrier loop.
    builder.assert_bool(input);
    builder.assert_equal(input, public);
    let _ = builder.add(last, input);
    let program = builder.finish(None).unwrap();
    let air = MachineAir::new(program.clone());
    let compiled = Arc::new(WitnessProgram::compile(&program, 64 << 20).unwrap());
    assert!(compiled.waves.iter().any(|w| w.len() > 256));
    assert!(compiled.waves.len() > 32);
    let session = device::DeviceSession::new().unwrap();
    let prepared = session.prepare_witness(compiled).unwrap();
    for fusion in [false, true] {
        ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .tuning
            .witness = fusion;
        for (repetition, word) in [0u64, 1, 0, 1].into_iter().enumerate() {
            let expected = air
                .trace(&[Val::from_u64(word)], &[Val::from_u64(word)])
                .unwrap();
            let started = std::time::Instant::now();
            let trace = prepared
                .trace(&session, &[word], &[word], 64 << 20)
                .unwrap();
            let wall_ns = started.elapsed().as_nanos();
            assert_eq!(
                session.read(&trace, trace.spec().bytes()).unwrap(),
                expected
                    .values
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
            );
            println!(
                "GPU_WITNESS_FUSION_SCREEN {}",
                serde_json::json!({"fused":fusion,"repetition":repetition,"trace_wall_ns":wall_ns,"verified":true,"complete_aggregation":false})
            );
        }
        let expected = program
            .evaluate(&[Val::from_u64(2)], &[Val::from_u64(2)])
            .err()
            .unwrap();
        assert_eq!(
            prepared
                .trace(&session, &[2], &[2], 64 << 20)
                .err()
                .unwrap(),
            device::WitnessError::Execution(expected)
        );
        assert!(prepared.trace(&session, &[1], &[1], 64 << 20).is_ok());
    }
}
