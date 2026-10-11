use super::*;
use crate::block_v2::{
    machine::{backend::RegisteredProgram, MachineAir},
    profile,
    recursive::{self, ProverSession, WrapperConstruction},
};
use crate::config::Val;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

#[test]
#[ignore = "fresh legacy CPU session and worker proofs under an explicit budget"]
fn fresh_legacy_sessions_and_workers_obey_assigned_memory_and_keep_verification() {
    let height = 1024;
    let budget = 512 << 20;
    let mut registry = Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let compiled = programs::empty(height, &registry.caps).unwrap();
    let registered = RegisteredProgram::new_with_memory_budget(
        MachineAir::new(compiled.program.pad_to(height).unwrap()),
        budget - recursive::storage::SESSION_HOST_BYTES,
    )
    .unwrap();
    registry.caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    let profile_id = registry.id().unwrap();
    let pin = RegistryPin::new(&registry, profile_id, WrapperConstruction::SingleWallet).unwrap();
    let mut session =
        ProverSession::new_with_memory_budget(registry.clone(), profile_id, budget).unwrap();
    assert_eq!(session.memory_budget_bytes(), budget);
    let first = session.empty(recursive::DEMO_CHAIN, 0).unwrap();
    let mut second = session.empty(recursive::DEMO_CHAIN, 0).unwrap();
    assert_eq!(session.stats(), CacheStats { setups: 1, hits: 1 });
    registry.verify(profile_id, &first, &first.public).unwrap();
    registry
        .verify(profile_id, &second, &second.public)
        .unwrap();
    let mut changed_public = first.public;
    changed_public[programs::ROOT] += Val::ONE;
    assert!(registry
        .verify(profile_id, &first, &changed_public)
        .is_err());
    second.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    assert!(registry
        .verify(profile_id, &second, &second.public)
        .is_err());
    drop(session);
    let worker = CpuWorker::new(registry.clone(), pin).unwrap();
    let job = Job::empty(pin, recursive::DEMO_CHAIN, 0, 0).unwrap();
    let (bad, rejected) = measure(|| {
        worker.prove(
            Inputs::Empty,
            job.expected(),
            job.operation(),
            recursive::storage::STARTUP_HOST_BYTES - 1,
        )
    });
    assert!(bad.is_err());
    assert!(!rejected.overflow && rejected.bytes <= 1024 + core::mem::size_of::<String>());
    let (bytes, _, _, stats) = worker
        .prove(Inputs::Empty, job.expected(), job.operation(), budget)
        .unwrap();
    assert_eq!(stats, CacheStats { setups: 1, hits: 0 });
    VerifiedNode::verify(&job, &registry, &bytes).unwrap();
    eprintln!("legacy_session_fresh cpu_proofs=3 height={height} assigned_bytes={budget} active_bytes={} cache_setups=1 cache_hits=1 short_worker_rejected=true public_mutation_rejected=true opening_mutation_rejected=true worker_proof_verified=true", budget - recursive::storage::SESSION_HOST_BYTES);
}
