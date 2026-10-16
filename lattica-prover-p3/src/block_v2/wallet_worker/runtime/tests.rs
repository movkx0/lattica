use super::*;

fn budget() -> Budget {
    Budget {
        schema: "lattica-wallet-local-gpu-v1".into(),
        service: "lattica-wallet-runtime-test.service".into(),
        gpu_uuid: "GPU-00000000-0000-0000-0000-000000000000".into(),
        host_bytes: 3 << 30,
        threads: 4,
        managed_gpu_bytes: 1 << 30,
        context_gpu_bytes: 4 << 30,
        host_output_bytes: 1 << 30,
    }
}

#[test]
fn private_request_partition_keeps_stacks_retention_and_mappings_outside_ceiling() {
    let mut budget = budget();
    let limits = Limits::for_budget(&budget).unwrap();
    let stacks =
        worker_budget::rayon_stack_host_bytes(4).unwrap() + worker_budget::CALLER_STACK_HOST_BYTES;
    assert_eq!(
        limits.system as u64 + stacks + crate::host_memory::RETAINED_SYSTEM_HOST_BYTES,
        budget.host_bytes
    );
    assert_eq!(
        limits.host as u64 + crate::host_memory::GPU_MAPPED_HOST_BYTES,
        limits.system as u64
    );
    budget.host_output_bytes = limits.host as u64;
    budget.validate().unwrap();
    budget.host_output_bytes += 1;
    assert!(budget.validate().is_err());
    budget.host_output_bytes = 192 << 20;
    budget.host_bytes = stacks
        + crate::host_memory::RETAINED_SYSTEM_HOST_BYTES
        + crate::host_memory::GPU_MAPPED_HOST_BYTES
        + budget.host_output_bytes;
    budget.validate().unwrap();
    budget.host_bytes -= 1;
    assert!(budget.validate().is_err());
}

#[test]
fn private_request_partition_rejects_overflow_and_impossible_thread_counts() {
    let mut budget = budget();
    for threads in [0, 257, u32::MAX] {
        budget.threads = threads;
        assert!(budget.validate().is_err());
    }
    budget.threads = 4;
    for bytes in [0, 512 << 20, u64::MAX] {
        budget.host_bytes = bytes;
        assert!(budget.validate().is_err());
    }
}

#[cfg(all(target_os = "linux", feature = "stream"))]
#[test]
#[ignore = "fresh process in its bounded private-wallet service; no GPU required"]
fn assigned_runtime_installs_once_and_bounds_heap_and_full_spill_requests() {
    use crate::block_v2::{gpu_hash, wallet_worker};
    use crate::proving::{Policy, Request};
    assert!(!gpu_hash::is_enabled());
    let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
    let before = tasks();
    let prepared = wallet_worker::prepare().unwrap();
    assert_eq!(
        tasks(),
        before,
        "assignment parsing must not initialize Rayon"
    );
    assert!(crate::spill_alloc::system_budget::snapshot()
        .limit_bytes
        .is_none());
    let limits = Limits::for_budget(&prepared.0.as_ref().unwrap().budget).unwrap();
    prepared.initialize_runtime().unwrap();
    prepared.initialize_runtime().unwrap();
    check_ready(prepared.0.as_ref()).unwrap();
    assert!(!gpu_hash::is_enabled());
    let system = crate::spill_alloc::system_budget::snapshot();
    let host = crate::spill_alloc::host_budget::snapshot();
    assert_eq!(system.limit_bytes, Some(limits.system));
    assert_eq!(host.limit_bytes, Some(limits.host));
    let mut heap = Vec::<u8>::new();
    assert!(heap.try_reserve_exact(limits.system + 1).is_err());
    assert!(heap.try_reserve_exact(limits.host + 1).is_err());
    assert_eq!(
        crate::spill_alloc::system_budget::snapshot().reserved_request_bytes,
        system.reserved_request_bytes
    );
    assert_eq!(
        crate::spill_alloc::host_budget::snapshot().reserved_request_bytes,
        host.reserved_request_bytes
    );
    let spill_before = crate::spill_alloc::spill_stats();
    {
        let _scope = crate::spill_alloc::SpillScope::arm();
        assert!(heap.try_reserve_exact(limits.host + 1).is_err());
    }
    assert_eq!(crate::spill_alloc::spill_stats(), spill_before);
    assert!(crate::spill_alloc::system_budget::snapshot().accounting_valid);
    assert!(crate::spill_alloc::host_budget::snapshot().accounting_valid);
    assert_eq!(heap.capacity(), 0);
    let original = std::env::var_os(wallet_worker::ENV).unwrap();
    unsafe { std::env::remove_var(wallet_worker::ENV) };
    assert!(wallet_worker::is_assigned());
    assert!(wallet_worker::prepare().is_err());
    assert!(Request {
        policy: Policy::CpuRequired,
        emit_report: false
    }
    .admit(&crate::proving::legacy_cpu())
    .is_err());
    unsafe { std::env::set_var(wallet_worker::ENV, original) };
    prepared.initialize_runtime().unwrap();
    assert!(!gpu_hash::is_enabled());
    eprintln!("wallet_runtime_qualified parse_started_no_threads=true limits_survive_reinitialization=true oversized_heap_and_spill_rejected=true failed_reservations_released=true policy_downgrade_rejected=true gpu_initialized=false");
}

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "stream"))]
#[test]
#[ignore = "fresh process with deliberately oversized existing heap; no GPU required"]
fn existing_heap_pressure_rejects_runtime_before_threads_or_gpu_and_cannot_retry() {
    use crate::block_v2::{gpu_hash, wallet_worker};
    assert!(!gpu_hash::is_enabled());
    let prepared = wallet_worker::prepare().unwrap();
    let mut pressure = Vec::<u8>::new();
    pressure.try_reserve_exact(600 << 20).unwrap();
    assert!(std::hint::black_box(&pressure).capacity() >= 600 << 20);
    let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
    let error = prepared.initialize_runtime().unwrap_err();
    assert!(
        error.contains("cold allocator backing exceeds retained System reservation"),
        "{error}"
    );
    assert_eq!(
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        threads
    );
    assert!(!gpu_hash::is_enabled());
    drop(pressure);
    assert!(prepared.initialize_runtime().is_err());
    unsafe { std::env::remove_var(wallet_worker::ENV) };
    assert!(wallet_worker::is_assigned());
    assert!(wallet_worker::prepare().is_err());
    assert!(!gpu_hash::is_enabled());
    eprintln!("wallet_runtime_pressure_rejected before_threads=true before_gpu=true retry_rejected=true assignment_removal_rejected=true");
}

#[cfg(all(target_os = "linux", feature = "stream"))]
#[test]
#[ignore = "fresh process with an oversized existing Rayon pool; no GPU required"]
fn oversized_existing_rayon_stacks_reject_and_leave_limits_pinned() {
    use crate::block_v2::{gpu_hash, wallet_worker};
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .stack_size(3 << 20)
        .build_global()
        .unwrap();
    let prepared = wallet_worker::prepare().unwrap();
    let limits = Limits::for_budget(&prepared.0.as_ref().unwrap().budget).unwrap();
    let error = prepared.initialize_runtime().unwrap_err();
    assert!(
        error.contains("actual thread stack exceeds admitted backing"),
        "{error}"
    );
    assert!(!gpu_hash::is_enabled());
    assert_eq!(
        crate::spill_alloc::system_budget::snapshot().limit_bytes,
        Some(limits.system)
    );
    assert_eq!(
        crate::spill_alloc::host_budget::snapshot().limit_bytes,
        Some(limits.host)
    );
    assert_eq!(prepared.initialize_runtime().unwrap_err(), error);
    unsafe { std::env::remove_var(wallet_worker::ENV) };
    assert!(wallet_worker::is_assigned());
    assert!(wallet_worker::prepare().is_err());
    assert!(crate::proving::Request::compatible()
        .admit(&crate::proving::legacy_cpu())
        .is_err());
    assert!(!gpu_hash::is_enabled());
    eprintln!("wallet_runtime_stack_rejected after_limits=true before_gpu=true retry_rejected=true assignment_removal_rejected=true");
}

#[cfg(all(target_os = "linux", not(feature = "stream")))]
#[test]
#[ignore = "fresh assigned process built without the stream allocator; no GPU required"]
fn assigned_runtime_without_stream_rejects_before_gpu_and_cannot_downgrade() {
    use crate::block_v2::{gpu_hash, wallet_worker};
    let prepared = wallet_worker::prepare().unwrap();
    let error = prepared.initialize_runtime().unwrap_err();
    assert!(
        error.contains("requires Linux and the stream allocator"),
        "{error}"
    );
    assert!(!gpu_hash::is_enabled());
    assert_eq!(prepared.initialize_runtime().unwrap_err(), error);
    unsafe { std::env::remove_var(wallet_worker::ENV) };
    assert!(wallet_worker::is_assigned());
    assert!(wallet_worker::prepare().is_err());
    assert!(crate::proving::Request::compatible()
        .admit(&crate::proving::legacy_cpu())
        .is_err());
    eprintln!("wallet_runtime_without_stream_rejected before_gpu=true retry_rejected=true assignment_removal_rejected=true");
}

#[cfg(all(target_os = "linux", feature = "stream"))]
#[test]
#[ignore = "fresh process with an injected startup panic after installing limits; no GPU required"]
fn panicking_installation_keeps_limits_and_failure_pinned() {
    use crate::block_v2::{gpu_hash, wallet_worker};
    let prepared = wallet_worker::prepare().unwrap();
    let limits = Limits::for_budget(&prepared.0.as_ref().unwrap().budget).unwrap();
    let error = initialize_with(prepared.0.as_ref(), |assignment| {
        install(assignment)?;
        panic!("wallet runtime fixture after allocator installation");
    })
    .unwrap_err();
    assert_eq!(error, "wallet runtime admission panicked");
    assert_eq!(
        crate::spill_alloc::system_budget::snapshot().limit_bytes,
        Some(limits.system)
    );
    assert_eq!(
        crate::spill_alloc::host_budget::snapshot().limit_bytes,
        Some(limits.host)
    );
    assert_eq!(prepared.initialize_runtime().unwrap_err(), error);
    assert!(!gpu_hash::is_enabled());
    unsafe { std::env::remove_var(wallet_worker::ENV) };
    assert!(wallet_worker::is_assigned());
    assert!(wallet_worker::prepare().is_err());
    assert!(crate::proving::Request::compatible()
        .admit(&crate::proving::legacy_cpu())
        .is_err());
    eprintln!("wallet_runtime_panic_rejected after_limits=true before_gpu=true retry_rejected=true assignment_removal_rejected=true");
}
