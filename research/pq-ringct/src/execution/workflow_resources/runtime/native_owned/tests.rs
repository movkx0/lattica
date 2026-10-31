use super::*;

fn scratch(host: u64) -> Requirements {
    Requirements::single(Category::PhaseScratch, Bytes { host, device: 0 })
}

#[test]
fn terminal_no_start_restores_all_five_backend_and_both_output_originals() {
    use super::super::super::owners::SlotPool;
    use crate::execution::workflow_resources::{SlotId, SlotSpec};
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut output = Requirements::single(Category::NativeProof, Bytes { host: 64, device: 0 });
    output.add(Category::Report, Bytes { host: 32, device: 0 }).unwrap();
    let required = combine(combine(scratch(512), output).unwrap(),
        SlotPool::bookkeeping_requirements(1).unwrap()).unwrap();
    let mut phase = capability.admit_owned(required).unwrap();
    let pool = SlotPool::new(&mut phase, &[SlotSpec { requirements: output }]).unwrap();
    pool.begin().unwrap();
    let mut claim = pool.claim(SlotId::new(0)).unwrap();
    let proof = claim.split(Requirements::single(Category::NativeProof, Bytes { host: 64, device: 0 })).unwrap();
    let report = claim.split(Requirements::single(Category::Report, Bytes { host: 32, device: 0 })).unwrap();
    let before = ledger.snapshot();
    let mut partition = phase.partition_originals(scratch(400)).unwrap();
    let originals = core::array::from_fn(|_| partition.split(scratch(80)).unwrap());
    restore::all(partition, originals, &mut claim, Some((proof, report))).unwrap();
    assert_eq!(ledger.snapshot(), before);
    drop(claim);
    assert!(!pool.is_available(SlotId::new(0)));
    phase.cleanup_between_operations().unwrap();
    pool.after_cleanup().unwrap();
    assert!(pool.is_available(SlotId::new(0)));
    pool.retire().unwrap();
    drop(pool);
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[cfg(not(debug_assertions))]
#[test]
fn native_host_tree_profile_reduces_pcs_inside_one_unchanged_backend() {
    use crate::graph_crypto::OwnedShakeNativeSource;
    let request = crate::graph_crypto::owned_test_requests::shake_partition();
    let source = OwnedShakeNativeSource::new(&request, 0).unwrap();
    let limits = crate::opencl::Limits { host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20 };
    let backend = Bytes { host: 24 << 30, device: 8 << 30 };
    let plan = NativePartitionPlan::new(&source, limits, backend).unwrap();
    assert!(plan.startup.get(Category::PhaseScratch).host >= 8 << 30);
    assert!(plan.pcs.get(Category::PhaseScratch).host < 16 << 30);
    assert_eq!(combine(combine(plan.startup, plan.wrappers).unwrap(), plan.pcs)
        .unwrap().total().unwrap(), backend);
    assert!(plan.complete.get(Category::SymbolicCompiler).host > 0);
    assert_eq!(plan.complete.get(Category::IndependentVerifier).host, 64 << 20);
    assert!(NativePartitionPlan::new(&source, limits, Bytes { host: 8 << 30, ..backend }).is_err());
    assert!(NativePartitionPlan::new(&source, limits, Bytes { host: (24 << 30) + 1, ..backend }).is_err());
    assert!(NativePartitionPlan::new(&source, limits, Bytes { device: (8 << 30) - 1, ..backend }).is_err());
    assert!(NativePartitionPlan::new(&source, crate::opencl::Limits { max_rows: 1, ..limits }, backend).is_err());
}
