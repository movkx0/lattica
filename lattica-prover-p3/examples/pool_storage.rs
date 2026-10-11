//! Production-layout probe for shared pool metadata; no GPU or proof creation.

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
use lattica_prover_p3::block_v2::execution::{
    artifact_store::StoreLimits, dag::Limits, journal::JournalLimits, pool::PoolStorage,
    resources::Resources,
};

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
fn main() {
    for (name, jobs, candidates, attempts, artifact_bytes, entries, snapshot_bytes) in [
        ("cli", 256, 8, 256, 256 << 20, 512, 1 << 20),
        ("hard", 4096, 256, 16384, 512 << 20, 16384, 8 << 20),
    ] {
        let durable = JournalLimits { snapshot_bytes }
            .durable_storage(
                Limits {
                    jobs,
                    candidates,
                    attempts,
                    artifact_bytes,
                    recovery_window_ms: 1000,
                    workers: Resources {
                        ram_bytes: 3 << 30,
                        vram_bytes: 7 << 30,
                        scratch_bytes: 1 << 30,
                        threads: 4,
                    },
                },
                StoreLimits {
                    bytes: artifact_bytes as u64,
                    entries,
                },
            )
            .unwrap();
        let plan = PoolStorage::new(durable).unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        let bookkeeping = plan.bookkeeping;
        println!(
            "production_pool_storage profile={name} durable_bytes={} bookkeeping_retained_bytes={} bookkeeping_transition_bytes={} scheduler_retained_bytes={} scheduler_selection_bytes={} registry_bytes={} total_bytes={total}",
            plan.durable.total_bytes().unwrap(), bookkeeping.retained_bytes,
            bookkeeping.transition_bytes, bookkeeping.scheduler.retained_bytes,
            bookkeeping.scheduler.selection_bytes, plan.registry_bytes
        );
    }
}

#[cfg(not(all(feature = "block-v2", feature = "stream", target_os = "linux")))]
fn main() {
    eprintln!("pool storage probe requires block-v2 and stream on Linux");
    std::process::exit(2);
}
