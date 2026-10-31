//! Original output/key/verifier claims issued before any native attempt.
use super::super::{source_shape::GroupSourceBound, GroupCompilePlan};
use super::*;
use lattica_prover_p3::block_v2::machine::{
    backend::RegisteredVerificationFailure, OuterSourceShape,
};
use p3_field::PrimeCharacteristicRing;

pub(in crate::component_tree::owned_shake) struct PreissuedOutput<'source, 'owner, 'request> {
    source: &'source GroupSourceBound<'request>,
    request: &'owner ReservedShakeRequest,
    storage: Storage,
    original: Reservation,
}

/// Separate original scratch for fixed post-production acceptance/mutations.
/// No cloned proof or caller-selected verifier is accepted or allocated.
pub(in crate::component_tree::owned_shake) struct OutputRecheck<'owner> {
    request: &'owner ReservedShakeRequest,
    requirement: Requirements,
    original: Reservation,
}

fn mutation_caller_host_bytes() -> Result<u64, Error> {
    let parts = [
        u64::try_from(RegisteredVerifier::classified_call_extra_bytes())
            .map_err(|_| Error::Overflow)?,
        bytes::<RegisteredVerificationFailure>(8)?,
        bytes::<Result<(), RegisteredVerificationFailure>>(8)?,
        bytes::<Result<(), Error>>(8)?,
        bytes::<Result<OutputRecheck<'static>, Error>>(8)?,
        bytes::<OutputRecheck<'static>>(8)?,
        bytes::<[Val; HEADER + 8]>(8)?,
        bytes::<&RegisteredVerifier>(8)?,
        bytes::<&NodeProof>(8)?,
        bytes::<&[Val]>(8)?,
        bytes::<String>(8)?,
        bytes::<usize>(8)?,
        bytes::<u64>(8)?,
        bytes::<Requirements>(8)?,
        bytes::<Result<u64, Error>>(8)?,
    ];
    let helper = u64::try_from(core::mem::size_of_val(&parts))
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(Error::Overflow)?;
    parts.into_iter().try_fold(helper, add)
}

fn require_relation_rejection(
    outcome: Result<(), RegisteredVerificationFailure>,
) -> Result<(), Error> {
    match outcome {
        Err(RegisteredVerificationFailure::RelationRejected(_)) => Ok(()),
        Ok(())
        | Err(RegisteredVerificationFailure::Admission(_))
        | Err(RegisteredVerificationFailure::Configuration(_))
        | Err(RegisteredVerificationFailure::Allocation(_)) => Err(Error::Verification),
    }
}

fn verify_public_probe(
    verifier: &RegisteredVerifier,
    proof: &NodeProof,
    index: usize,
) -> Result<(), Error> {
    if proof.public.len() != HEADER + 8 || index >= HEADER + 8 {
        return Err(Error::Authority);
    }
    // This bounded public-only copy is precharged. The retained output remains
    // unchanged on returned errors and unwinding; no proof is cloned.
    let mut changed = [Val::ZERO; HEADER + 8];
    changed.copy_from_slice(&proof.public);
    changed[index] += Val::ONE;
    let outcome = verifier.verify_classified(&proof.proof, &changed);
    changed[index] = proof.public[index];
    // Restore the probe before classifying. Diagnostics never earn credit;
    // only the numerical verifier's typed rejection is a successful negative.
    require_relation_rejection(outcome)
}

impl<'owner> OutputRecheck<'owner> {
    pub(in crate::component_tree::owned_shake) fn reserve_before_native(
        source: &GroupSourceBound<'_>,
        group: &GroupCompilePlan<'_>,
        request: &'owner ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !source.is_for(group, ledger) || !core::ptr::eq(group.request, request.request()) {
            return Err(Error::Authority);
        }
        let geometry = source.geometry();
        let output = OuterSourceShape::owned_shake(
            geometry.operations,
            geometry.wires_upper_bound,
            geometry.input_values,
            geometry.selection_hint_words_upper_bound,
        )
        .and_then(OuterSourceShape::output_footprint)
        .map_err(|_| Error::Source)?;
        let host = add(
            add(output.verifier_lifecycle_peak_host_bytes, bytes::<Self>(2)?)?,
            mutation_caller_host_bytes()?,
        )?;
        let requirement =
            Requirements::single(Category::IndependentVerifier, Bytes { host, device: 0 });
        let original = ledger
            .admit_phase(requirement)
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            request,
            requirement,
            original,
        })
    }

    pub(in crate::component_tree::owned_shake) fn verify_mutations(
        self,
        output: &mut RetainedNodeOutput<'_>,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        if !self.original.belongs_to(ledger)
            || self.original.requirements() != self.requirement
            || !output.belongs_to(ledger)
            || !core::ptr::eq(self.request, output.request)
            || !output.report.independent_verification_complete
        {
            return Err(Error::Authority);
        }
        output
            .key
            .verifier
            .verify(&output.proof.proof, &output.proof.public)
            .map_err(|_| Error::Verification)?;
        for index in [0, crate::component_tree::CONTEXT] {
            verify_public_probe(&output.key.verifier, &output.proof, index)?;
        }
        output
            .key
            .verifier
            .verify(&output.proof.proof, &output.proof.public)
            .map_err(|_| Error::Verification)
    }
}

#[cfg(test)]
mod tests;

impl<'source, 'owner, 'request> PreissuedOutput<'source, 'owner, 'request> {
    pub(in crate::component_tree::owned_shake) fn reserve(
        source: &'source GroupSourceBound<'request>,
        group: &GroupCompilePlan<'request>,
        request: &'owner ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !source.is_for(group, ledger)
            || !request.belongs_to(ledger)
            || !core::ptr::eq(group.request, request.request())
        {
            return Err(Error::Authority);
        }
        let geometry = source.geometry();
        let shape = OuterSourceShape::owned_shake(
            geometry.operations,
            geometry.wires_upper_bound,
            geometry.input_values,
            geometry.selection_hint_words_upper_bound,
        )
        .map_err(|_| Error::Source)?;
        let footprint = shape.output_footprint().map_err(|_| Error::Profile)?;
        let mut storage = Storage::new(footprint, 2 * (HEADER + 8))?;
        let extra = add(
            bytes::<Self>(2)?,
            add(
                bytes::<Result<Self, Error>>(2)?,
                bytes::<OuterSourceShape>(2)?,
            )?,
        )?;
        storage
            .requirements
            .add(
                Category::Report,
                Bytes {
                    host: extra,
                    device: 0,
                },
            )
            .map_err(|_| Error::Overflow)?;
        storage.report.report_host_bytes = add(storage.report.report_host_bytes, extra)?;
        storage.report.total_claimed_host_bytes =
            add(storage.report.total_claimed_host_bytes, extra)?;
        let original = ledger
            .admit_phase(storage.requirements)
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            source,
            request,
            storage,
            original,
        })
    }

    /// Transform the original token only. No output allocation, key creation,
    /// new reservation or capacity shrink occurs at this boundary.
    pub(in crate::component_tree::owned_shake) fn attach<'compiled>(
        self,
        compiled: &'compiled OwnedCompiledShake<'request>,
        ledger: &Ledger,
    ) -> Result<OutputClaim<'compiled, 'owner, 'request>, Error> {
        if !self.request.belongs_to(ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != self.storage.requirements
            || !compiled.is_for(self.request.request())
        {
            return Err(Error::Authority);
        }
        self.source
            .check_compiled(compiled, ledger)
            .map_err(|_| Error::Source)?;
        Ok(OutputClaim {
            compiled,
            request: self.request,
            storage: self.storage,
            token: self.original,
        })
    }
}
