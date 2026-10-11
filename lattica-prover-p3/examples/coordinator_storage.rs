//! Production-layout probe: no proof generation and no device initialization.
#[cfg(all(feature = "block-v2", target_os = "linux"))]
use lattica_prover_p3::block_v2::execution::{
    artifact_store::StoreLimits, dag::Limits, journal::JournalLimits, resources::Resources,
};
#[cfg(all(feature = "block-v2", target_os = "linux"))]
fn main() {
    for (name, jobs, candidates, attempts, artifact_bytes, entries, snapshot_bytes) in [
        ("cli", 256, 8, 256, 256 << 20, 512, 1 << 20),
        ("hard", 4096, 256, 16384, 512 << 20, 16384, 8 << 20),
    ] {
        let graph = Limits {
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
        };
        let plan = JournalLimits { snapshot_bytes }
            .durable_storage(
                graph,
                StoreLimits {
                    bytes: artifact_bytes as u64,
                    entries,
                },
            )
            .unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        println!("production_durable_storage profile={name} graph_bytes={} transition_bytes={} store_bytes={} owner_bytes={} path_bytes={} total_bytes={total}",
            plan.graph.total_bytes().unwrap(), plan.transitions.total_bytes().unwrap(), plan.store.total_bytes().unwrap(),
            plan.owner_metadata_bytes, plan.path_work_bytes);
    }
}

#[cfg(not(all(feature = "block-v2", target_os = "linux")))]
fn main() {
    eprintln!("coordinator_storage requires Linux and the block-v2 feature");
    std::process::exit(2);
}
