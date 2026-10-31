//! Concrete AES counterparts to the input-preserving SHAKE constructors.
use super::*;

type CompileRefusal<'a> = (PairedFailure, RetainedNative<OwnedAesNativeOutput<'a>>);
type MergeRefusal<'a> = (PairedFailure, Retained<PairedNode<'a>>, Retained<PairedNode<'a>>);
type OuterRefusal<'a> = (PairedFailure, Retained<PairedCompiled<'a>>);

impl<'request> OwnedAesRequestPlan<'request> {
    pub(crate) fn compile_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        endpoints: &'plan Retained<OwnedAesEndpoints<'request>>,
        child: RetainedNative<OwnedAesNativeOutput<'request>>,
    ) -> core::result::Result<OwnedAesCompileOperation<'plan, 'request>, CompileRefusal<'request>> {
        let checked = (|| {
            let OwnedAesStepKind::Compile { node } = self.steps.get(ordinal)
                .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
            Ok((node, self.binding(ordinal, OwnedAesStepKind::Compile { node })?))
        })();
        match checked {
            Ok((node, binding)) => Ok(OwnedAesCompileOperation { plan: self, node, endpoints, child, binding }),
            Err(error) => Err((error, child)),
        }
    }

    pub(crate) fn merge_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        left: Retained<PairedNode<'request>>, right: Retained<PairedNode<'request>>,
    ) -> core::result::Result<OwnedAesMergeOperation<'plan, 'request>, MergeRefusal<'request>> {
        let checked = (|| {
            let kind @ OwnedAesStepKind::Merge { node, left: left_id, right: right_id } =
                self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind
                else { return Err(PairedFailure::Order); };
            Ok((node, left_id, right_id, self.binding(ordinal, kind)?))
        })();
        match checked {
            Ok((node, left_id, right_id, binding)) => Ok(OwnedAesMergeOperation {
                plan: self, node, left_id, right_id, left, right, binding,
            }),
            Err(error) => Err((error, left, right)),
        }
    }

    pub(crate) fn outer_operation_retaining<'plan>(
        &'plan self, ordinal: usize,
        compiled: Retained<PairedCompiled<'request>>, cache: &'plan OuterProofCache,
    ) -> core::result::Result<OwnedAesOuterOperation<'plan, 'request>, OuterRefusal<'request>> {
        let checked = (|| {
            let OwnedAesStepKind::Outer { node } = self.steps.get(ordinal)
                .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
            Ok((node, self.binding(ordinal, OwnedAesStepKind::Outer { node })?))
        })();
        match checked {
            Ok((node, binding)) => Ok(OwnedAesOuterOperation { plan: self, node, compiled, cache, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}

pub(in crate::graph_crypto::prover::owned_aes) fn forwarding_bytes() -> Result<usize> {
    use core::mem::size_of;
    [
        size_of::<CompileRefusal<'static>>(), size_of::<MergeRefusal<'static>>(),
        size_of::<OuterRefusal<'static>>(),
        size_of::<core::result::Result<OwnedAesCompileOperation<'static, 'static>, CompileRefusal<'static>>>(),
        size_of::<core::result::Result<OwnedAesMergeOperation<'static, 'static>, MergeRefusal<'static>>>(),
        size_of::<core::result::Result<OwnedAesOuterOperation<'static, 'static>, OuterRefusal<'static>>>(),
        size_of::<Result<(usize, PhaseBinding)>>(),
        size_of::<Result<(usize, usize, usize, PhaseBinding)>>(),
    ].into_iter().try_fold(0usize, |sum, part| add(sum, part.checked_mul(8).ok_or(PairedFailure::Overflow)?))
}
