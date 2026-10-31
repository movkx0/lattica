use super::*;

#[test]
fn raw_epoch_startup_host_is_additive_and_device_is_not_double_charged() {
    let startup = WorkflowRuntimePlan::outer_host_v1_requirement().unwrap();
    let backend = Bytes { host: 80 << 10, device: MAX_DEVICE_BYTES };
    let plan = GroupPartitionPlan::new(startup, backend).unwrap();
    let bytes = startup.get(Category::PhaseScratch);
    assert!(bytes.host >= 8 << 30);
    assert_eq!(plan.complete.total().unwrap(), Bytes { host: bytes.host + backend.host, device: MAX_DEVICE_BYTES });
    assert!(bytes.device > 0 && bytes.device < MAX_DEVICE_BYTES);
    assert_eq!(plan.operation.total().unwrap(), Bytes {
        host: backend.host, device: MAX_DEVICE_BYTES - bytes.device,
    });
    let scratch = group_issuer_scratch_requirements().unwrap();
    assert!(scratch.get(Category::PhaseScratch).host > bytes.host);
    assert_eq!(scratch.total().unwrap().device, 0);
    assert!(GroupPartitionPlan::new(startup, Bytes { host: 0, ..backend }).is_err());
    assert!(GroupPartitionPlan::new(startup, Bytes { device: MAX_DEVICE_BYTES - 1, ..backend }).is_err());
    assert!(GroupPartitionPlan::new(startup, Bytes { host: MAX_NATIVE_BYTES, ..backend }).is_err());
    for device in [0, MAX_DEVICE_BYTES + 1] {
        let invalid = Requirements::single(Category::PhaseScratch, Bytes { device, ..bytes });
        assert!(GroupPartitionPlan::new(invalid, backend).is_err());
    }
    let wrong_category = Requirements::single(Category::SymbolicCompiler, bytes);
    assert!(GroupPartitionPlan::new(wrong_category, backend).is_err());
}

#[test]
fn raw_epoch_restores_only_its_original_claims_without_new_credit() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let startup = Requirements::single(Category::PhaseScratch, Bytes { host: 64, device: 0 });
    let raw = Requirements::single(Category::PhaseScratch, Bytes { host: 32, device: 0 });
    let complete = combine(startup, raw).unwrap();
    let mut phase = capability.admit_owned(complete).unwrap();
    let before = ledger.snapshot();
    let mut partition = phase.partition_originals(complete).unwrap();
    let originals = [partition.split(startup).unwrap(), partition.split(raw).unwrap()];
    restore(partition, originals).unwrap();
    assert_eq!(ledger.snapshot(), before);
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
