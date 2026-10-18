use super::*;
use crate::{
    config::Val,
    cuda_compute::{Limits, Runtime},
};
use p3_field::PrimeField64;
use rand::{RngExt, SeedableRng};

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 4 << 20,
            max_allocation_bytes: 2 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn expected(rng: &mut ChaCha20Rng, count: usize) -> Vec<u64> {
    (0..count)
        .map(|_| rng.random::<Val>().as_canonical_u64())
        .collect()
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_proof_rng_activation_preserves_cursors_and_retires_all_group_handles() {
    let runtime = runtime();
    let engine = Randoms::new(&runtime).unwrap();
    let failure = Failure::default();
    let streams: Vec<_> = [41, 43, 47]
        .into_iter()
        .map(|seed| {
            let rng = ProofRng::new(ChaCha20Rng::from_seed([seed; 32]));
            rng.activate_cuda(&engine, &failure).unwrap();
            rng
        })
        .collect();
    let before = runtime.snapshot();
    for rng in &streams {
        assert!(rng.lock().is_err());
        assert!(rng.is_device().unwrap());
        assert!(rng.activate_cuda(&engine, &failure).is_err());
        assert!(rng
            .with_cuda(|r| r.preflight_fields(&[usize::MAX], &[]))
            .is_err());
        assert!(rng
            .with_cuda(|r| r.preflight_fields(&[8], &[usize::MAX]))
            .is_err());
    }
    assert_eq!(runtime.snapshot(), before);
    let shared = streams[0].clone();
    let snapshot = streams[0].snapshot().unwrap();
    let escaped = streams[1].with_cuda(|r| Ok(r.clone())).unwrap();
    assert_eq!(runtime.snapshot(), before);
    let mut cpu = ChaCha20Rng::from_seed([41; 32]);
    let mut fork_cpu = cpu.clone();
    for rng in [&streams[0], &shared] {
        assert_eq!(
            rng.with_cuda(|r| r.sample_fields(37)?.read_for_test(296))
                .unwrap(),
            expected(&mut cpu, 37)
        );
    }
    assert_eq!(
        snapshot
            .with_cuda(|r| r.sample_fields(74)?.read_for_test(592))
            .unwrap(),
        expected(&mut fork_cpu, 74)
    );
    streams[0].begin().unwrap().complete();
    let failed: Result<(), String> = (|| {
        let _attempt = streams[2].begin()?;
        let _samples = streams[2].with_cuda(|r| r.sample_fields(19))?;
        Err("injected proof failure after CUDA randomness".into())
    })();
    assert!(failed.is_err());
    let before = runtime.snapshot();
    for rng in streams.iter().chain([&shared, &snapshot]) {
        assert!(rng.is_device().is_err());
        assert!(rng.snapshot().is_err());
        assert!(rng.begin().is_err());
        assert!(rng.with_cuda(|r| r.sample_fields(1)).is_err());
        assert!(rng.lock().is_err());
    }
    assert!(
        escaped.sample_fields(1).is_err(),
        "escaped device aliases share the proof group's failure flag"
    );
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_proof_rng_failed_import_cannot_revert_to_cpu() {
    let runtime = runtime();
    let engine = Randoms::new(&runtime).unwrap();
    let failure = Failure::default();
    let rng = ProofRng::new(ChaCha20Rng::from_seed([53; 32]));
    let a = runtime.allocate((2 << 20) / 8).unwrap();
    let b = runtime.allocate((2 << 20) / 8).unwrap();
    let before = runtime.snapshot();
    assert!(rng.activate_cuda(&engine, &failure).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(rng.lock().is_err());
    assert!(rng.snapshot().is_err());
    drop((a, b));
    assert!(rng.activate_cuda(&engine, &failure).is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rng.with(|r| r.next_u64())))
            .is_err()
    );
}
