use super::*;

#[test]
fn public_service_pointer_and_length_contracts_reject_before_startup() {
    let input = b"{}";
    unsafe {
        assert_eq!(
            lattica_gpu_public_worker_serve(0, input.as_ptr(), input.len(), std::ptr::null_mut()),
            REJECTED
        );
        for (fd, pointer, length) in [
            (-1, input.as_ptr(), input.len()),
            (0, std::ptr::null(), input.len()),
            (0, input.as_ptr(), 0),
            (0, input.as_ptr(), PUBLIC_WORKER_BOOTSTRAP_MAX_BYTES + 1),
        ] {
            let mut completed = 123;
            assert_eq!(
                lattica_gpu_public_worker_serve(fd, pointer, length, &mut completed),
                REJECTED
            );
            assert_eq!(completed, 0);
        }
    }
}

#[test]
fn panic_boundary_keeps_lifecycle_usable() {
    assert_eq!(call(|| panic!("native lifecycle fixture")), REJECTED);
    assert_eq!(call(|| Ok(())), OK);
    assert_eq!(call(|| Err("rejected fixture".into())), REJECTED);
}

#[cfg(not(all(feature = "block-v2", feature = "gpu")))]
#[test]
fn unavailable_backend_exports_reject_explicitly() {
    assert_eq!(lattica_gpu_initialize_from_env(), UNAVAILABLE);
    assert_eq!(lattica_gpu_drain(), UNAVAILABLE);
    assert_eq!(lattica_gpu_shutdown(), UNAVAILABLE);
}

#[cfg(not(all(
    feature = "block-v2",
    feature = "gpu",
    feature = "stream",
    target_os = "linux"
)))]
#[test]
fn unavailable_public_worker_startup_rejects_explicitly() {
    assert_eq!(lattica_gpu_public_worker_initialize_from_env(), UNAVAILABLE);
    let mut completed = 123;
    #[cfg(not(all(
        feature = "block-v2",
        feature = "gpu-cuda",
        feature = "stream",
        target_os = "linux"
    )))]
    assert_eq!(
        unsafe { lattica_gpu_public_worker_serve(0, b"{}".as_ptr(), 2, &mut completed) },
        UNAVAILABLE
    );
    #[cfg(all(
        feature = "block-v2",
        feature = "gpu-cuda",
        feature = "stream",
        target_os = "linux"
    ))]
    assert_eq!(
        unsafe { lattica_gpu_public_worker_serve(0, b"{}".as_ptr(), 2, &mut completed) },
        REJECTED
    );
    assert_eq!(completed, 0);
}

#[cfg(all(feature = "block-v2", feature = "gpu"))]
mod opencl {
    use super::*;
    use crate::block_v2::gpu_hash::{self, device::DeviceSession};

    struct Env(&'static str, Option<std::ffi::OsString>);

    impl Env {
        fn set(name: &'static str, value: &str) -> Self {
            let before = Self(name, std::env::var_os(name));
            std::env::set_var(name, value);
            before
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            match &self.1 {
                Some(value) => std::env::set_var(self.0, value),
                None => std::env::remove_var(self.0),
            }
        }
    }

    #[test]
    #[ignore = "requires isolated OpenCL process, explicit laptop UUID and bounded service"]
    fn lifecycle_admission_recovery_and_retained_session() {
        let _shutdown = gpu_hash::TestShutdownGuard;
        let _policy = Env::set(
            "LATTICA_PROVING_POLICY",
            if cfg!(debug_assertions) {
                "compatible"
            } else {
                "gpu-required"
            },
        );
        assert_eq!(lattica_gpu_shutdown(), OK);
        assert_eq!(lattica_gpu_drain(), REJECTED);
        for (name, value) in [
            ("LATTICA_V2_GPU_HASH", "0"),
            ("LATTICA_V2_GPU_TRANSCRIPT", "invalid"),
            ("LATTICA_GPU_DEVICE_UUID", ""),
            ("LATTICA_V2_GPU_MANAGED_BYTES", "0"),
            ("LATTICA_V2_GPU_MANAGED_BYTES", "invalid"),
            ("LATTICA_V2_GPU_COMPACT_PROVER_DATA", "invalid"),
            ("LATTICA_V2_HOST_OUTPUT_BYTES", "invalid"),
            ("LATTICA_V2_HOST_OUTPUT_BYTES", "0"),
            ("LATTICA_PROVING_POLICY", "invalid"),
            ("LATTICA_PROVING_POLICY", "cpu-required"),
            ("LATTICA_V2_WORKER_BUDGET", "invalid"),
        ] {
            let _invalid = Env::set(name, value);
            assert_eq!(lattica_gpu_initialize_from_env(), REJECTED, "{name}");
            assert!(gpu_hash::report("native_rejected_before_initialization").is_none());
        }
        for panic in [false, true] {
            assert_eq!(
                call(|| crate::block_v2::native_gpu::reject_after_engine_for_test(panic)),
                REJECTED
            );
            assert!(gpu_hash::report("native_startup_rollback").is_none());
        }
        assert_eq!(lattica_gpu_initialize_from_env(), OK);
        let before = gpu_hash::report("native_first_initialization").unwrap();
        assert_eq!(lattica_gpu_initialize_from_env(), OK);
        let after = gpu_hash::report("native_repeated_initialization").unwrap();
        assert_eq!(before.allocations, after.allocations);
        assert_eq!(before.managed_live_bytes, after.managed_live_bytes);
        for (name, value) in [
            (
                "LATTICA_GPU_DEVICE_UUID",
                "GPU-00000000-0000-0000-0000-000000000000",
            ),
            ("LATTICA_V2_GPU_DEVICE", "18446744073709551615"),
        ] {
            let _changed = Env::set(name, value);
            assert_eq!(lattica_gpu_initialize_from_env(), REJECTED);
            assert_eq!(lattica_gpu_drain(), OK);
            let live = gpu_hash::report("native_rejected_device_change").unwrap();
            assert_eq!(before.allocations, live.allocations);
            assert_eq!(before.managed_live_bytes, live.managed_live_bytes);
        }
        for panic in [false, true] {
            assert_eq!(
                call(|| crate::block_v2::native_gpu::reject_after_engine_for_test(panic)),
                REJECTED
            );
            assert_eq!(lattica_gpu_drain(), OK);
        }
        {
            let _changed = Env::set("LATTICA_V2_GPU_MANAGED_BYTES", "536870912");
            assert_eq!(lattica_gpu_initialize_from_env(), REJECTED);
            assert_eq!(lattica_gpu_drain(), OK);
        }
        let session = DeviceSession::new().unwrap();
        assert_eq!(lattica_gpu_drain(), OK);
        assert_eq!(lattica_gpu_shutdown(), REJECTED);
        assert_eq!(lattica_gpu_initialize_from_env(), OK);
        drop(session);
        assert_eq!(lattica_gpu_shutdown(), OK);
        assert_eq!(lattica_gpu_shutdown(), OK);
        assert_eq!(lattica_gpu_drain(), REJECTED);
        assert_eq!(lattica_gpu_initialize_from_env(), OK);
        assert_eq!(lattica_gpu_shutdown(), OK);
        eprintln!("native_gpu_lifecycle_matched rejected_initializations=11 startup_rollbacks=2 borrowed_engine_preserved=2 changed_device_rejected=2 retained_session_protected=true reinitialized=true");
    }
}
