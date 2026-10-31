//! Named constructor bridge from the authenticated source metadata envelope.
//! Constructors consume the original split once; an inner error is retained
//! intact by the caller's case slot and permanently poisons this installation.
use super::WorkflowPlanning;
use crate::{execution::{retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::WorkflowError},
    spend_pipeline::full_workflow::metadata_planning::{MetadataMember, ProducerFamily,
        SourceMetadataPlanningPlan}};
use core::mem::size_of;

mod native;
mod compile;
mod outer;
mod frames;
mod graph;
mod crypto;
mod final_aggregation;
mod complete;
pub(crate) use complete::{CompleteSlotFailure, CompleteSlotResult};
pub(crate) use final_aggregation::{FinalContractResult, FinalContractTable, FinalContractFailure, OwnedFinalContract};

const COMPILED: [ProducerFamily; 7] = [ProducerFamily::Source, ProducerFamily::Affine,
    ProducerFamily::Ntt, ProducerFamily::Mul, ProducerFamily::GBound,
    ProducerFamily::Permutation, ProducerFamily::LinearMap];
const FAMILIES: [ProducerFamily; 16] = [ProducerFamily::Source, ProducerFamily::Uniform,
    ProducerFamily::Sparse, ProducerFamily::Transcript, ProducerFamily::Affine,
    ProducerFamily::Ntt, ProducerFamily::Mul, ProducerFamily::GBound,
    ProducerFamily::Permutation, ProducerFamily::LinearMap, ProducerFamily::Fixed,
    ProducerFamily::Parameters, ProducerFamily::Auxiliary, ProducerFamily::Equality,
    ProducerFamily::Shake, ProducerFamily::Aes];

// Crypto stage 1 is source endpoint completion, never a second constructor.
// A raw successful constructor creates exactly one pending endpoint operation.
pub(super) fn crypto_endpoints_complete(constructors: &[usize; 48]) -> bool {
    [ProducerFamily::Shake, ProducerFamily::Aes].into_iter().all(|family| {
        let index = (family as usize) * 3;
        constructors[index] == constructors[index + 1]
    })
}

fn pending_crypto_endpoint(constructors: &[usize; 48], family: ProducerFamily,
    position: usize) -> Result<usize, WorkflowError>
{
    let other = match family {
        ProducerFamily::Shake => ProducerFamily::Aes,
        ProducerFamily::Aes => ProducerFamily::Shake,
        _ => return Err(WorkflowError::Identity),
    };
    let next = position.checked_add(1).ok_or(WorkflowError::Overflow)?;
    let index = (family as usize) * 3;
    let other_index = (other as usize) * 3;
    if constructors[index] != next || constructors[index + 1] != position
        || constructors[other_index] != constructors[other_index + 1]
    { return Err(WorkflowError::Sequence); }
    Ok(index + 1)
}

fn sum(mut a: Requirements, b: Requirements) -> Result<Requirements, WorkflowError> {
    for category in Category::ALL { a.add(category, b.get(category))?; }
    Ok(a)
}
fn scratch_frames(parts: &[usize]) -> Result<Requirements, WorkflowError> {
    let count = parts.iter().try_fold(0usize, |sum, part| sum.checked_add(*part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(count).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

pub(crate) fn producer_constructor_retained_requirements() -> Result<Requirements, WorkflowError> {
    let mut total = final_aggregation::retained_requirements()?;
    let driver = super::super::runtime::driver_retained_requirements()?;
    for category in Category::ALL { total.add(category, driver.get(category))?; }
    total = sum(total, crate::spend_pipeline::full_workflow::driver::crypto_runtime::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::final_runtime::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::runtime_inputs::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::native_runtime::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::graph_runtime::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::runtime_dispatch::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::execution::retained_requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::metadata_driver::retained_requirements()?)?;
    Ok(total)
}

pub(crate) fn producer_constructor_requirements(plan: &SourceMetadataPlanningPlan<'_>)
    -> Result<Requirements, WorkflowError>
{
    let mut total = scratch_frames(&[size_of::<RecordingOriginal<'static>>(),
        size_of::<[Requirements; 8]>(), size_of::<[Reservation; 4]>(),
        size_of::<[usize; 16]>(), size_of::<MetadataMember<'static, 'static>>(),
        size_of::<Result<(), WorkflowError>>(), size_of::<Result<usize, WorkflowError>>(),
        size_of::<Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<Result<Reservation, (crate::execution::retained_resources::Error, Reservation, Reservation)>>(),
        size_of::<[ProducerFamily; 16]>(), size_of::<Ledger>()])?;
    total = sum(total, frames::producer_native_constructor_frame_requirements(plan)?)?;
    total = sum(total, graph::requirements()?)?;
    total = sum(total, crypto::requirements()?)?;
    total = sum(total, final_aggregation::requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::native_layers::requirements()?)?;
    total = sum(total, crate::spend_pipeline::full_workflow::driver::graph_layers::requirements()?)?;
    sum(total, complete::requirements()?)
}

impl WorkflowPlanning<'_> {
    pub(super) fn begin_metadata_constructor<'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        family: ProducerFamily, ordinal: usize, stage: usize) -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan);
        self.failed = true;
        checked?;
        if stage > 2 || (stage != 0 && !COMPILED.contains(&family)) {
            return Err(WorkflowError::Planning);
        }
        let position = plan.source_position(member, family, ordinal)
            .map_err(|_| WorkflowError::Identity)?;
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        let index = (family as usize) * 3 + stage;
        if installed.constructors[index] != position
            || (stage != 0 && installed.constructors[index - 1] <= position)
        { return Err(WorkflowError::Identity); }
        installed.constructors[index] = position.checked_add(1).ok_or(WorkflowError::Overflow)?;
        Ok(())
    }

    pub(super) fn finish_metadata_constructor_success(&mut self) { self.failed = false; }

    /// Enter only the one pending crypto source, while its original Session is
    /// live. The concrete endpoint gate must then authenticate the installed
    /// typed table and borrow its actual plan; no caller-supplied plan is used.
    pub(in crate::execution::workflow_resources) fn begin_metadata_endpoint<'a>(
        &mut self, plan: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        family: ProducerFamily, ordinal: usize,
        case: &crate::spend_pipeline::full_workflow::fresh_generation::case_lifetime::CaseRetirementState,
    ) -> Result<usize, WorkflowError> {
        let checked = self.check_metadata_identity(plan);
        self.failed = true;
        checked?;
        if !self.metadata_case_matches(case)
            || !self.original.belongs_to(self.capability.ledger())
            || !self.scratch.belongs_to(self.capability.ledger())
            || !super::super::types::contains(self.scratch.requirements(), plan.planning_scratch_requirements())
            || !super::super::types::contains(self.scratch.requirements(), crypto::requirements()?)
        { return Err(WorkflowError::Identity); }
        let position = plan.source_position(member, family, ordinal)
            .map_err(|_| WorkflowError::Identity)?;
        let installed = self.producer_metadata.as_ref().ok_or(WorkflowError::Planning)?;
        pending_crypto_endpoint(&installed.constructors, family, position)?;
        Ok(position)
    }

    /// Called only after endpoint publication and the actual source cleanup
    /// barrier succeed. Error and unwind paths leave both the pending count
    /// and failed flag intact, retaining the plan in its case slot.
    pub(in crate::execution::workflow_resources) fn finish_metadata_endpoint(
        &mut self, family: ProducerFamily, position: usize,
    ) -> Result<(), WorkflowError> {
        if !self.failed || self.capability.status() != crate::execution::phase_lifecycle::Status::Ready {
            return Err(WorkflowError::Poisoned);
        }
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        let index = pending_crypto_endpoint(&installed.constructors, family, position)?;
        installed.constructors[index] = position.checked_add(1).ok_or(WorkflowError::Overflow)?;
        self.failed = false;
        Ok(())
    }


    fn metadata_leaves_complete(&self, plan: &SourceMetadataPlanningPlan<'_>) -> bool {
        let Some(installed) = &self.producer_metadata else { return false; };
        crypto_endpoints_complete(&installed.constructors) && FAMILIES.into_iter().all(|family| {
            let count = plan.counts().family(family);
            installed.constructors[(family as usize) * 3] == count
                && (!COMPILED.contains(&family) || (1..=2).all(|stage|
                    installed.constructors[(family as usize) * 3 + stage] == count))
        })
    }

    pub(super) fn begin_metadata_parent(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        level: usize, ordinal: usize) -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan);
        self.failed = true;
        checked?;
        if !self.metadata_leaves_complete(plan) { return Err(WorkflowError::Planning); }
        let expected = plan.counts().parent_level(level).filter(|count| *count != 0)
            .ok_or(WorkflowError::Planning)?;
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        if ordinal >= expected || installed.parents[level] != ordinal
            || (level != 0 && installed.parents[level - 1]
                != plan.counts().parent_level(level - 1).ok_or(WorkflowError::Planning)?)
        { return Err(WorkflowError::Identity); }
        installed.parents[level] = ordinal.checked_add(1).ok_or(WorkflowError::Overflow)?;
        Ok(())
    }

    pub(super) fn begin_metadata_final(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        stage: usize) -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan);
        self.failed = true;
        checked?;
        if !self.metadata_leaves_complete(plan) { return Err(WorkflowError::Planning); }
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        if !(0..32).all(|level| plan.counts().parent_level(level) == Some(installed.parents[level])) {
            return Err(WorkflowError::Planning);
        }
        match stage {
            0 if !installed.final_source && !installed.final_plan && !installed.closed => installed.final_source = true,
            1 if installed.final_source && !installed.final_plan && !installed.closed => installed.final_plan = true,
            2 if installed.final_source && installed.final_plan && !installed.closed => installed.closed = true,
            _ => return Err(WorkflowError::Planning),
        }
        Ok(())
    }

    /// The verifier recording consumes an exact sub-split of the admitted
    /// scratch. RAII reunites it with the same original on return or unwind.
    pub(super) fn with_metadata_recording<T>(&mut self, requirements: Requirements,
        construct: impl FnOnce(&mut Reservation, &Reservation, &Ledger) -> T)
        -> Result<T, WorkflowError>
    {
        if !self.failed { return Err(WorkflowError::Planning); }
        let recording = self.scratch.split(requirements)?;
        let mut guard = RecordingOriginal { remainder: &mut self.scratch, recording: Some(recording) };
        let result = construct(guard.recording.as_mut().ok_or(WorkflowError::Planning)?,
            guard.remainder, self.capability.ledger());
        if let Err(error) = guard.restore() {
            // An impossible reunion failure may not drop a newly constructed
            // owner behind the caller's back. Retain its original and payload
            // conservatively; the installation stays permanently poisoned.
            core::mem::forget(result);
            return Err(error);
        }
        Ok(result)
    }
}

struct RecordingOriginal<'a> {
    remainder: &'a mut Reservation,
    recording: Option<Reservation>,
}
impl RecordingOriginal<'_> {
    fn restore(&mut self) -> Result<(), WorkflowError> {
        let Some(recording) = self.recording.take() else { return Ok(()); };
        let remaining = match self.remainder.split(self.remainder.requirements()) {
            Ok(remaining) => remaining,
            Err(error) => { core::mem::forget(recording); return Err(error.into()); }
        };
        match remaining.reunite(recording) {
            Ok(whole) => { *self.remainder = whole; Ok(()) }
            Err((error, remaining, recording)) => {
                core::mem::forget(remaining);
                core::mem::forget(recording);
                Err(error.into())
            }
        }
    }
}
impl Drop for RecordingOriginal<'_> {
    fn drop(&mut self) { let _ = self.restore(); }
}

#[cfg(test)]
mod tests;
