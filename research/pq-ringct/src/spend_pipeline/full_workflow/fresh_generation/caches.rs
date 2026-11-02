//! One original funds the fixed FreshOnly counter Arc before allocation.
//! Empty cache paths allocate no storage and all proof-payload I/O is disabled.
use super::{FreshGenerationBatch, FreshGenerationError, FreshLedgerObservation, Result};
use crate::{execution::retained_resources::{Bytes, Category, Requirements, Reservation, Snapshot},
    graph_crypto::{ProofCache, OuterProofCache}, proof_cache_policy::{Control, FamilyStatistics, ProofCachePolicy}};
use crate::spend_pipeline::full_workflow::driver::case_report::CompletedCaseSummary;
use core::mem::size_of;
use std::time::Instant;
pub(crate) struct FreshProofCaches {
    pub(crate) native: ProofCache,
    pub(crate) outer: OuterProofCache,
    control: Control,
    original: Reservation,
}
impl FreshProofCaches {
    fn requirements() -> Result<Requirements> {
        use crate::spend_pipeline::full_workflow::metadata_planning::MetadataPlanningStage;
        use crate::spend_pipeline::full_workflow::driver::metadata_driver::DriverStage;
        use crate::execution::workflow_resources::WorkflowError;
        let frames = [size_of::<DriverStage>(), size_of::<&mut DriverStage>(),
            size_of::<WorkflowError>(), size_of::<(DriverStage, WorkflowError)>(),
            size_of::<core::result::Result<CompletedCaseSummary, WorkflowError>>(),
            size_of::<FreshGenerationError>(), size_of::<MetadataPlanningStage>(), size_of::<&mut MetadataPlanningStage>(), size_of::<Self>(), size_of::<Result<Self>>(), size_of::<Control>(),
            size_of::<ProofCache>(), size_of::<OuterProofCache>(), size_of::<Reservation>(),
            size_of::<Requirements>(), size_of::<[FamilyStatistics; 5]>(),
            size_of::<CompletedCaseSummary>(), size_of::<Result<CompletedCaseSummary>>(),
            size_of::<FreshLedgerObservation>(), size_of::<Result<FreshLedgerObservation>>(),
            size_of::<Snapshot>(), size_of::<Result<Snapshot>>(),
            size_of::<(CompletedCaseSummary, FreshLedgerObservation, Instant)>(),
            size_of::<Result<(CompletedCaseSummary, FreshLedgerObservation, Instant)>>(),
            size_of::<[[u8; 32]; 4]>(), size_of::<Instant>(),
            size_of::<[usize; 16]>(), size_of::<[&(); 16]>(),
        ].into_iter().try_fold(0usize, |a, b| a.checked_add(b))
            .and_then(|n| n.checked_mul(8)).and_then(|n| n.checked_add(Control::retained_host_bytes()))
            .ok_or(FreshGenerationError::Resource("fresh cache control census overflow"))?;
        Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
            host: u64::try_from(frames).map_err(|_| FreshGenerationError::Resource("fresh cache control width"))?, device: 0 }))
    }
    pub(crate) fn new<const N: usize>(batch: &FreshGenerationBatch<N>) -> Result<Self> {
        let original = batch.claim_source_descriptor(Self::requirements()?)?;
        let control = Control::new(ProofCachePolicy::FreshOnly);
        let native = ProofCache::fresh_without_storage(&control);
        let outer = OuterProofCache::fresh_without_storage(&control);
        Ok(Self { native, outer, control, original })
    }
    #[cfg(test)]
    pub(crate) fn for_fixture(ledger: &crate::execution::retained_resources::Ledger) -> Result<Self> {
        let original = ledger.admit_phase(Self::requirements()?).map_err(|_| FreshGenerationError::Resource("fixture cache admission"))?;
        let control = Control::new(ProofCachePolicy::FreshOnly);
        Ok(Self { native: ProofCache::fresh_without_storage(&control), outer: OuterProofCache::fresh_without_storage(&control), control, original })
    }
    pub(crate) fn statistics(&self) -> [FamilyStatistics; 5] { self.control.fixed_statistics() }
}
