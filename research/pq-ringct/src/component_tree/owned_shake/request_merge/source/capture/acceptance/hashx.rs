//! Acceptance from the dedicated opaque native-to-first-paired-leaf producer.
use super::*;
use crate::component_tree::owned_shake::{
    outer_producer::{RetiredHashxLeafAttempt, RetiredHashxLeafOriginals},
    source_shape::GroupSourceBound,
    GroupCompilePlan, ShakeWrapperLayout,
};

/// This owner contains no compiler/Program/witness borrow. The first leaf is
/// authenticated; the full request, parent graph and transaction remain gated.
pub(in crate::component_tree::owned_shake) struct AcceptedHashxLeafCompletion<
    'bound,
    'source,
    'request,
> {
    leaf: AcceptedLeaf<'bound, 'source, 'request>,
    originals: RetiredHashxLeafOriginals<'request>,
}

impl PreissuedLeafAcceptance<'_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn check_first_hashx_source(
        &self,
        source: &GroupSourceBound<'_>,
        group: &GroupCompilePlan<'_>,
        request: &crate::graph_crypto::ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<()> {
        let original = self.cap.source.request.sources[0]
            .as_ref()
            .ok_or(Error::Source)?;
        if self.cap.index != 0
            || group.ordinal != 0
            || group.layout != ShakeWrapperLayout::PairedV1
            || group.span.first_segment != 0
            || group.span.segment_count != 2
            || group.span.first_unit != 0
            || group.span.units != 32
            || !core::ptr::eq(original, source)
            || !core::ptr::eq(group.request, request.request())
            || !core::ptr::eq(self.cap.source.request.owner, request)
            || !self.cap.source.is_for(self.cap.source.request, ledger)
            || !source.is_for(group, ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != whole_requirement(self.cpu)?
            || !self.cap.original.belongs_to(ledger)
            || self.cap.original.requirements() != super::super::requirements()?
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

pub(in crate::component_tree::owned_shake) fn authenticate_retired_hashx_leaf<
    'bound,
    'source,
    'request,
>(
    attempt: RetiredHashxLeafAttempt<'_, 'bound, 'source, 'request>,
) -> Result<AcceptedHashxLeafCompletion<'bound, 'source, 'request>> {
    let (captured, output, originals, ledger) = attempt.into_original_parts();
    let retirement = originals
        .source_authentication_retirement(&ledger)
        .map_err(|_| Error::Source)?;
    let leaf = finish_source_acceptance(captured, output, retirement, &ledger)?;
    Ok(AcceptedHashxLeafCompletion { leaf, originals })
}

impl<'bound, 'source, 'request> AcceptedHashxLeafCompletion<'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn into_parts(
        self,
    ) -> (
        AcceptedLeaf<'bound, 'source, 'request>,
        RetiredHashxLeafOriginals<'request>,
    ) {
        (self.leaf, self.originals)
    }
}

#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod qualification;
