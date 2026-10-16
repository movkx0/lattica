//! Test-only observation at actual decode/preparation boundaries. No production
//! hook, environment switch or additional device work is introduced.
use crate::block_v2::{gpu_hash, leaf, legacy_wallet, quotient_pcs};

thread_local! {
    static PROBE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) struct PrivateInputProbe;

impl PrivateInputProbe {
    pub(crate) fn start() -> Self {
        PROBE.with(|probe| assert_eq!(probe.replace(Some(0)), None));
        Self
    }

    pub(crate) fn finish(self, expected: u64) {
        PROBE.with(|probe| assert_eq!(probe.get(), Some(expected)));
    }
}

impl Drop for PrivateInputProbe {
    fn drop(&mut self) {
        PROBE.with(|probe| probe.set(None));
    }
}

fn shutdown_must_refuse() {
    let result = std::thread::spawn(gpu_hash::shutdown).join().unwrap();
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("still live")),
        "an admitted request must retain the engine against concurrent shutdown: {result:?}"
    );
}

pub(crate) fn private_input_boundary() {
    PROBE.with(|probe| {
        if let Some(calls) = probe.get() {
            shutdown_must_refuse();
            probe.set(Some(calls + 1));
        }
    });
}

struct Environment(&'static str, Option<std::ffi::OsString>);
impl Drop for Environment {
    fn drop(&mut self) {
        match &self.1 {
            Some(value) => std::env::set_var(self.0, value),
            None => std::env::remove_var(self.0),
        }
    }
}

pub(crate) fn denied_resources(check: impl Fn()) {
    for (key, value) in [
        (
            "LATTICA_V2_WORKER_BUDGET",
            "public-worker-cannot-admit-private-input",
        ),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "4096"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "invalid"),
        (
            "LATTICA_WALLET_WORKER_BUDGET",
            "not-an-absolute-wallet-assignment",
        ),
    ] {
        let _restore = Environment(key, std::env::var_os(key));
        std::env::set_var(key, value);
        check();
    }
}

#[test]
#[ignore = "requires a complete OpenCL engine in the bounded serial GPU worker"]
fn gpu_request_admission_retains_context_and_releases_on_rejection_and_unwind() {
    assert!(!cfg!(debug_assertions));
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let request = crate::proving::Request::from_env().unwrap();
    assert_eq!(request.policy, crate::proving::Policy::GpuRequired);

    denied_resources(|| assert!(leaf::admit_wallet_request(request).is_err()));
    let outer = leaf::admit_wallet_request(request).unwrap();
    shutdown_must_refuse();
    let inner = legacy_wallet::abi_admission().unwrap();
    drop(outer);
    shutdown_must_refuse();
    drop(inner);

    // A guard must also release its context during unwinding on another thread.
    assert!(std::thread::spawn(move || {
        let _admission = leaf::admit_wallet_request(request).unwrap();
        panic!("intentional admitted-request unwind");
    })
    .join()
    .is_err());
    // A bounded tree rejection happens after admission and must release its guard.
    assert!(legacy_wallet::tree_abi_admission(0).is_err());
    gpu_hash::shutdown().unwrap();
    assert!(leaf::admit_wallet_request(request).is_err());
    assert!(legacy_wallet::abi_admission().is_err());
    assert!(gpu_hash::report("wallet_admission_after_shutdown").is_none());
}
