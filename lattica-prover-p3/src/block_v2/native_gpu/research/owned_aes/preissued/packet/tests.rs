use super::*;
use crate::ringct_research_quota::WorkerAllowance;
fn source() -> AesPreparationPlan { AesPreparationPlan::new(crate::block_v2::native_gpu::AesTraceSpec { domain: 17, start_counter: u32::MAX, output_len: 1024, first_block: 0, blocks: 1 }).unwrap() }
fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE }) }

#[test]
fn source_packet_metadata_census_is_pure_and_additive() {
    let (bytes, allocations) = crate::spill_alloc::allocation_requests::measure(||
        NativeAesReservationPlan::preissue_metadata_host_bytes().unwrap());
    assert_eq!((allocations.calls, allocations.bytes, allocations.overflow), (0, 0, false));
    assert!(bytes > 8 * size_of::<PreissuedNativeAesPlan>());
}

#[test]
fn refused_source_packet_borrows_every_original_without_releasing_credit() {
    for foreign_preparation in [false, true] {
        let ledger = ledger();
        let foreign = self::ledger();
        let plan = NativeAesReservationPlan::outer_host_v1(source(), 1 << 30).unwrap();
        let preparation = if foreign_preparation { &foreign } else { &ledger }
            .admit_phase(plan.preparation_requirement().unwrap()).unwrap();
        let startup = ledger.admit_phase(plan.startup_requirement()).unwrap();
        let verifier = ledger.admit_phase(plan.verifier_requirement()).unwrap();
        let mut wrapper = plan.wrapper_requirement().get(Category::PhaseScratch);
        if !foreign_preparation { wrapper.host -= 1; }
        let wrappers = ledger.reserve(Category::PhaseScratch, wrapper).unwrap();
        let pcs = ledger.admit_phase(plan.pcs_requirement()).unwrap();
        let before = (ledger.snapshot().current, foreign.snapshot().current);
        // Invalid originals refuse before environment/device inspection or any
        // native/Runtime attempt. Borrowing cannot split/drop/reissue credit.
        let result = unsafe { plan.preissue_from_originals(&preparation, &startup,
            &verifier, &wrappers, &pcs, &ledger) };
        assert!(matches!(result, Err(Error::Authority)));
        assert_eq!((ledger.snapshot().current, foreign.snapshot().current), before);
        drop((result, preparation, startup, verifier, wrappers, pcs));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
}
