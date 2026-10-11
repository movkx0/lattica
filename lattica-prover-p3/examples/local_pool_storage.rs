//! Production layouts for local launch, process and observation storage.

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
use lattica_prover_p3::block_v2::execution::{
    launch::LaunchLimits, os_worker, pool::local::LocalPoolStorage,
    worker::typed::process::ProcessWorker,
};

#[cfg(all(feature = "block-v2", feature = "stream", target_os = "linux"))]
fn main() {
    let preparation =
        lattica_prover_p3::block_v2::execution::selection::PreparationStorage::new().unwrap();
    println!("production_preparation_lists input_list_bytes={} policy_list_bytes={} temporary_registry_bytes={} registry_conversion_bytes={} total_bytes={}",
        preparation.input_list_bytes, preparation.policy_list_bytes, preparation.temporary_registry_bytes,
        preparation.registry_conversion_bytes, preparation.total_bytes().unwrap());
    let output = lattica_prover_p3::block_v2::execution::pool::PoolOutputStorage::new().unwrap();
    println!(
        "production_pool_outputs accepted_bytes={} failure_bytes={} root_bytes={} total_bytes={}",
        output.accepted_bytes,
        output.failure_bytes,
        output.root_bytes,
        output.total_bytes().unwrap()
    );
    let process = ProcessWorker::storage_plan().unwrap();
    let observation = os_worker::observation_storage().unwrap();
    println!(
        "production_persistent_process retained_bytes={} control_bytes={}",
        process.retained_bytes, process.control_bytes
    );
    println!(
        "production_os_observation identity_heap_bytes={} control_bytes={}",
        observation.identity_heap_bytes, observation.control_bytes
    );
    for (profile, records) in [("cli", 256), ("pool", 16384)] {
        let plan = LaunchLimits { records }.storage_plan().unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        println!("production_launch_storage profile={profile} owner_bytes={} retained_records_bytes={} refresh_records_bytes={} control_bytes={} total_bytes={total}",
            plan.owner_bytes, plan.retained_records_bytes, plan.refresh_records_bytes, plan.control_bytes);
    }
    for workers in [1, 16] {
        let plan = LocalPoolStorage::new(LaunchLimits { records: 16384 }, workers).unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        println!("production_local_pool workers={workers} launch_bytes={} endpoint_bytes={} control_bytes={} total_bytes={total}",
            plan.launch.total_bytes().unwrap(), plan.endpoint_bytes, plan.control_bytes);
    }
}

#[cfg(not(all(feature = "block-v2", feature = "stream", target_os = "linux")))]
fn main() {
    eprintln!("local pool storage probe requires block-v2 and stream on Linux");
    std::process::exit(2);
}
