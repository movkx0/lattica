//! Complete-driver constructor variants return the original input owners on
//! refusal. No phase starts here, and no raw proof or replacement claim escapes.
use super::*;

type GroupInputs<'a> = [Option<RetainedNative<PairedNativeOutput<'a>>>; 2];
type GroupRefusal<'a> = (PairedFailure, GroupInputs<'a>);
type MergeRefusal<'a> = (PairedFailure, Retained<PairedNode<'a>>, Retained<PairedNode<'a>>);
type OuterRefusal<'a> = (PairedFailure, Retained<PairedCompiled<'a>>);

impl<'request> PairedRequestPlan<'request> {
    pub(crate) fn group_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        endpoints: &'plan Retained<PairedEndpoints<'request>>,
        children: GroupInputs<'request>,
    ) -> core::result::Result<PairedGroupOperation<'plan, 'request>, GroupRefusal<'request>> {
        let checked = (|| {
            let RequestStepKind::Group { node } = self.steps.get(ordinal)
                .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
            Ok((node, self.binding(ordinal, RequestStepKind::Group { node })?))
        })();
        match checked {
            Ok((node, binding)) => Ok(PairedGroupOperation { plan: self, node, endpoints, children, binding }),
            Err(error) => Err((error, children)),
        }
    }

    pub(crate) fn merge_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        left: Retained<PairedNode<'request>>, right: Retained<PairedNode<'request>>,
    ) -> core::result::Result<PairedMergeOperation<'plan, 'request>, MergeRefusal<'request>> {
        let checked = (|| {
            let kind @ RequestStepKind::Merge { node, left: left_id, right: right_id } =
                self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind
                else { return Err(PairedFailure::Order); };
            Ok((node, left_id, right_id, self.binding(ordinal, kind)?))
        })();
        match checked {
            Ok((node, left_id, right_id, binding)) => Ok(PairedMergeOperation {
                plan: self, node, left_id, right_id, left, right, binding,
            }),
            Err(error) => Err((error, left, right)),
        }
    }

    pub(crate) fn outer_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        compiled: Retained<PairedCompiled<'request>>, cache: &'plan OuterProofCache,
    ) -> core::result::Result<PairedOuterOperation<'plan, 'request>, OuterRefusal<'request>> {
        let checked = (|| {
            let RequestStepKind::Outer { node } = self.steps.get(ordinal)
                .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
            Ok((node, self.binding(ordinal, RequestStepKind::Outer { node })?))
        })();
        match checked {
            Ok((node, binding)) => Ok(PairedOuterOperation { plan: self, node, compiled, cache, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}

/// Charged to each immutable request's original planning metadata before any
/// driver constructor can move an input. Counts cover caller/result forwarding.
pub(in crate::graph_crypto::prover::paired) fn forwarding_bytes() -> Result<usize> {
    use core::mem::size_of;
    [
        size_of::<GroupInputs<'static>>(), size_of::<GroupRefusal<'static>>(),
        size_of::<MergeRefusal<'static>>(), size_of::<OuterRefusal<'static>>(),
        size_of::<core::result::Result<PairedGroupOperation<'static, 'static>, GroupRefusal<'static>>>(),
        size_of::<core::result::Result<PairedMergeOperation<'static, 'static>, MergeRefusal<'static>>>(),
        size_of::<core::result::Result<PairedOuterOperation<'static, 'static>, OuterRefusal<'static>>>(),
        size_of::<Result<(usize, PhaseBinding)>>(),
        size_of::<Result<(usize, usize, usize, PhaseBinding)>>(),
    ].into_iter().try_fold(0usize, |sum, part| add(sum, part.checked_mul(8).ok_or(PairedFailure::Overflow)?))
}
