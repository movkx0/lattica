//! Original adapter admission before a native attempt. The opaque metadata
//! owner and its existing source census are reused without another wrapper.
use super::*;

impl<'request> MetadataOwner<'request> {
    /// Pure source requirement, not a claim or permission to dispatch. The
    /// corresponding original owner must still be reserved before proving.
    pub(crate) fn source_requirement(
        owner: &'request ReservedShakeRequest,
        index: usize,
    ) -> Result<Requirements> {
        Ok(AttachmentPlan::new(owner, index)?.requirements)
    }

    /// Issue and retain the original adapter claim before native dispatch.
    /// Key and shape construction occur only after this exact same-ledger
    /// admission. This does not admit compiler, runtime or recursive phases.
    pub(crate) fn reserve_before_native(
        owner: &'request ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        if !owner.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let plan = AttachmentPlan::new(owner, index)?;
        let original = ledger
            .admit_phase(plan.requirements)
            .map_err(|_| Error::Admission)?;
        let pending = plan.claim_for(owner, index, original, ledger)?;
        pending.prepare_metadata()
    }

    pub(crate) fn is_for(
        &self,
        owner: &ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> bool {
        core::ptr::eq(self.owner, owner)
            && self.index == index
            && owner.belongs_to(ledger)
            && self.original.belongs_to(ledger)
            && requirements().is_ok_and(|expected| self.original.requirements() == expected)
    }

    /// Consume the exact preissued owner and the intact original native output.
    /// This path performs no ledger admission, token reconstruction, proof copy
    /// or key construction after proving. Source proof-shape auditing and final
    /// independent compiler verification remain required by the existing child.
    pub(crate) fn attach(
        self,
        produced: VerifiedNativeSingleton<'request>,
        ledger: &Ledger,
    ) -> Result<ReservedNativeChild<'request>> {
        self.finish(produced, ledger)
    }
}

#[cfg(test)]
mod tests;
