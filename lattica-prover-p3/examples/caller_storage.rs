//! Production-layout probe for one caller selection plus shared pool storage.

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
use lattica_prover_p3::block_v2::execution::{
    artifact_store::StoreLimits, dag::Limits, journal::JournalLimits, pool::PoolStorage,
    resources::Resources, selection::Selection,
};

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
fn main() {
    let selection = Selection::storage_plan().unwrap();
    let selection_bytes = selection.total_bytes().unwrap();
    selection.admit(selection_bytes).unwrap();
    assert!(selection.admit(selection_bytes - 1).is_err());
    println!(
        "production_selection_storage metadata_bytes={} proof_bytes={} construction_bytes={} input_conversion_bytes={} admission_bytes={} total_bytes={selection_bytes}",
        selection.metadata_bytes, selection.proof_bytes, selection.construction_bytes,
        selection.input_conversion_bytes, selection.admission_bytes
    );
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
        let pool = PoolStorage::new(durable).unwrap();
        let pool_bytes = pool.total_bytes().unwrap();
        pool.admit(pool_bytes).unwrap();
        assert!(pool.admit(pool_bytes - 1).is_err());
        println!(
            "production_caller_storage profile={name} pool_bytes={pool_bytes} registry_bytes={} selection_bytes={selection_bytes} total_bytes={}",
            pool.registry_bytes, pool_bytes.checked_add(selection_bytes).unwrap()
        );
    }
}

#[cfg(not(all(feature = "block-v2", feature = "stream", target_os = "linux")))]
fn main() {
    eprintln!("caller storage probe requires block-v2 and stream on Linux");
    std::process::exit(2);
}
