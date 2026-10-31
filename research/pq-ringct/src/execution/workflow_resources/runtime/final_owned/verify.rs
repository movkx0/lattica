//! Separate final expected-statement and independent CPU proof verification.
use super::*;

pub(crate) fn final_verify_issuer_requirements() -> Result<Requirements, WorkflowError> {
    let frames = [
        size_of::<FinalVerifyOperation<'static, 'static, 'static>>(),
        size_of::<FinalVerification<'static, 'static>>(),
        size_of::<Result<FinalVerification<'static, 'static>, FinalFailure>>(),
        size_of::<Result<Retained<FinalVerification<'static, 'static>>, PhaseFailure<FinalFailure>>>(),
        size_of::<StageEntry<'static>>(), size_of::<FinalReport>(),
    ].into_iter().try_fold(0usize, |sum, next| sum.checked_add(next))
        .and_then(|sum| sum.checked_mul(8))
        .and_then(|sum| sum.checked_add(final_report_transport_host_bytes()))
        .ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(frames).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn verify_final<'root, 'source>(self,
        operation: FinalVerifyOperation<'root, '_, 'source>)
        -> Result<Retained<FinalVerification<'root, 'source>>, PhaseFailure<FinalFailure>>
    {
        let inputs = preflight::inputs(self.admission.plan, self.step).map_err(PhaseFailure::Admission)?;
        let binding = operation.binding();
        if self.step.binding != binding || binding.kind() != PhaseKind::FinalVerify
            || self.step.backend != Bytes::ZERO || self.step.input_count != 1
            || self.step.consume_count != 0 || inputs != [operation.input_slot()]
            || !contains(binding.facts().scratch,
                final_verify_issuer_requirements().map_err(PhaseFailure::Admission)?)
            || !self.admission.retired_context.belongs_to(self.admission.context) {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        self.execute(binding, |access| {
            let verified = operation.execute(access)?;
            emit_stage(binding.ordinal(), Stage::Verify, &verified.report())?;
            Ok(verified)
        })
    }
}
