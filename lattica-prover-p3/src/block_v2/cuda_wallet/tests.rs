use super::*;

thread_local! {
    static BOUNDARY: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
pub(crate) struct Boundary;
impl Boundary {
    pub(crate) fn new() -> Self {
        BOUNDARY.with(|n| n.set(Some(0)));
        Self
    }
    pub(crate) fn calls(&self) -> usize {
        BOUNDARY.with(|n| n.get().unwrap())
    }
}
impl Drop for Boundary {
    fn drop(&mut self) {
        BOUNDARY.with(|n| n.set(None));
    }
}
pub(crate) fn private_input_boundary() {
    BOUNDARY.with(|n| {
        if let Some(calls) = n.get() {
            assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 1);
            assert_eq!(crate::native_gpu::lattica_gpu_drain(), 1);
            // Private decoding already has exclusive ownership and a live
            // context. Another caller cannot decode alongside this one.
            assert!(std::thread::spawn(|| abi_admission().is_err())
                .join()
                .unwrap());
            n.set(Some(calls + 1));
        }
    });
}

pub(crate) fn output_boundary() {
    BOUNDARY.with(|n| {
        if n.get().is_some() {
            assert_eq!(crate::native_gpu::lattica_gpu_shutdown(), 1);
            assert_eq!(crate::native_gpu::lattica_gpu_drain(), 1);
        }
    });
}

pub(crate) fn snapshot() -> crate::cuda_compute::Snapshot {
    let state = STATE.lock().unwrap();
    let State::Ready(session) = &*state else {
        panic!("missing CUDA wallet context")
    };
    session.runtime.snapshot()
}

#[test]
fn nested_admission_keeps_other_threads_out_until_final_release() {
    let mut owner = Owner::default();
    let current = std::thread::current().id();
    let other = std::thread::spawn(|| std::thread::current().id())
        .join()
        .unwrap();
    owner.acquire(current).unwrap();
    owner.acquire(current).unwrap();
    assert!(owner.acquire(other).is_err());
    owner.release(current);
    assert!(owner.acquire(other).is_err());
    owner.release(current);
    owner.acquire(other).unwrap();
    owner.release(other);
    assert_eq!(owner.depth, 0);
    assert!(owner.thread.is_none());
}

#[test]
fn wallet_profiles_advertise_only_native_arithmetic() {
    for profile in [Profile::LegacyQuadratic, Profile::BlockV2Cubic] {
        let capabilities = capabilities(profile);
        Request {
            policy: crate::proving::Policy::GpuRequired,
            emit_report: false,
        }
        .admit(&capabilities)
        .unwrap();
        assert_eq!(capabilities.stages().len(), 14);
        assert!(capabilities
            .stages()
            .iter()
            .all(|s| s.backend == crate::proving::Backend::Cuda));
    }
}

#[test]
fn public_assignment_cannot_admit_private_wallets_under_compatible_policy() {
    const CHILD: &str = "LATTICA_CUDA_WALLET_PUBLIC_REJECTION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = format!(
            "{}::public_assignment_cannot_admit_private_wallets_under_compatible_policy",
            module_path!().split_once("::").unwrap().1
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("LATTICA_V2_WORKER_BUDGET", "/invalid-public-assignment")
            .env("LATTICA_PROVING_POLICY", "compatible")
            .env_remove(wallet_worker::ENV)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
        return;
    }
    assert!(!has_context());
    let witness = crate::joinsplit_air::demo_witness();
    let before = crate::proving::cpu_witness_oracle_calls();
    assert!(crate::wallet_abi_admission().is_none());
    assert!(crate::batch_abi_admission(crate::batch_common::BatchKind::JoinSplit, 1).is_none());
    assert!(crate::tree_abi_admission(1).is_none());
    let request = Request::from_env().unwrap();
    assert!(super::super::leaf::admit_wallet_request(request).is_err());
    assert!(crate::joinsplit_air::prove_to_bytes_with_request(&witness, request).is_err());
    assert!(crate::joinsplit_air::prove_verify(&witness).is_err());
    assert_eq!(crate::native_gpu::lattica_gpu_initialize_from_env(), 1);
    assert!(!has_context());
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
}
