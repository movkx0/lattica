//! Consuming, same-Component final-root public checks. The output adapter may
//! borrow the actual key/proof only through the sealed action constructed here.
use super::super::super::super::CpuEnvelope;
use super::*;
use crate::component_tree::{
    commitment, words, Contract, EndpointContext, Kind, Spec, CONTEXT, CONTRACT_DOMAIN, COUNT,
    DESCRIPTOR, EXPECTED_INPUT, EXPECTED_OUTPUT, FIRST, HEADER, KIND, LEVEL, REQUEST, STATEMENT,
    TOTAL,
};
use lattica_prover_p3::block_v2::machine::backend::RegisteredVerificationFailure;
use p3_field::PrimeCharacteristicRing;

mod claims;
use claims::requirements;

// Separate inactive opening probe. The B065 public-only entry and its
// immutable adapter remain unchanged; no driver selects this extension.
mod opening;
pub(in crate::component_tree::owned_shake) use opening::{
    RootOpeningMeasurements, RootOpeningRecheckAction,
};
pub(super) use opening::{PreissuedRootOpening, RetainedRootOpeningReport};

type RecheckResult<T> = core::result::Result<T, ParentCompileError>;
const PUBLICS: usize = HEADER + 8;
const ROOT_ORDINAL: usize = PARENTS - 1;

pub(super) struct PreissuedRootRecheck<'bound, 'source, 'request> {
    source: &'bound ParentSourceBound<'source, 'request>,
    spec: Spec,
    header: [Val; HEADER],
    cpu: CpuEnvelope,
    original: Reservation,
}

#[derive(Clone, Copy)]
pub(super) struct RootRecheckPlanReport {
    pub(super) cpu_heights: usize,
    pub(super) verifier_host_bytes: u64,
    pub(super) caller_host_bytes: u64,
    pub(super) total_host_bytes: u64,
    pub(super) planned_public_probes: usize,
}

#[derive(Clone, Copy)]
pub(in crate::component_tree::owned_shake) struct RootPublicRecheckReport {
    pub(in crate::component_tree::owned_shake) cpu_heights: usize,
    pub(in crate::component_tree::owned_shake) positive_checks: usize,
    pub(in crate::component_tree::owned_shake) public_probes: usize,
    pub(in crate::component_tree::owned_shake) positive_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) mutation_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) elapsed_ns: u128,
}

// No constructor, callback, Clone, root/key/proof getter or continuation exists
// outside this private module. It borrows the child moved from one Component
// while that same Component's actual originals/support/caller remain held.
pub(in crate::component_tree::owned_shake) struct RootPublicRecheckAction<
    'phase,
    'bound,
    'source,
    'request,
> {
    child: &'phase AcceptedChild<'bound, 'source, 'request>,
    recheck: &'phase PreissuedRootRecheck<'bound, 'source, 'request>,
    ledger: &'phase Ledger,
}

// Same maintained header semantics using fixed arrays. This exact request is
// already source-constrained; no Vec/header/proof clone is allocated here.
fn source_header(spec: &Spec, context: &EndpointContext) -> RecheckResult<[Val; HEADER]> {
    let Kind::Shake(descriptor) = &spec.contract.kind else {
        return Err(ParentCompileError::Source);
    };
    if descriptor.input_len != 16_416
        || descriptor.output_len != 137
        || spec.first != 0
        || spec.count != 122
        || spec.level != 3
        || spec.contract.total != 122
    {
        return Err(ParentCompileError::Source);
    }
    let descriptor_fields = [
        spec.contract.tag(),
        u64::from(spec.contract.total),
        u64::try_from(descriptor.input_len).map_err(|_| ParentCompileError::Overflow)?,
        u64::try_from(descriptor.output_len).map_err(|_| ParentCompileError::Overflow)?,
    ];
    let descriptor = commitment::hash_fields(CONTRACT_DOMAIN, &descriptor_fields)
        .map_err(|_| ParentCompileError::Source)?
        .map(Val::from_u64);
    let mut header = [Val::ZERO; HEADER];
    header[..8].copy_from_slice(&words(&spec.contract.profile));
    header[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&context.context));
    for (offset, values) in [
        (STATEMENT, context.statement),
        (EXPECTED_INPUT, context.input),
        (EXPECTED_OUTPUT, context.output),
    ] {
        header[offset..offset + 4].copy_from_slice(&values);
    }
    for (offset, value) in [
        (KIND, spec.contract.tag()),
        (REQUEST, u64::from(spec.contract.request)),
        (FIRST, u64::from(spec.first)),
        (COUNT, u64::from(spec.count)),
        (TOTAL, u64::from(spec.contract.total)),
        (LEVEL, u64::from(spec.level)),
    ] {
        header[offset] = Val::from_u64(value);
    }
    header[DESCRIPTOR..DESCRIPTOR + 4].copy_from_slice(&descriptor);
    Ok(header)
}

impl<'bound, 'source, 'request> PreissuedRootRecheck<'bound, 'source, 'request> {
    pub(super) fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        ledger: &Ledger,
    ) -> RecheckResult<Self> {
        source.check_original_request(source.request.owner, ledger)?;
        let cpu = CpuEnvelope::source()?;
        let original = ledger
            .admit_phase(requirements(cpu)?)
            .map_err(|_| ParentCompileError::Capacity)?;
        // All fixed source/header/hash-helper storage is now backed, before
        // any request PCS/native capacity is assigned by the later Attempt.
        let (_, expected) = super::super::super::specs(source, ROOT_ORDINAL)?;
        let [_, _, spec] = expected;
        let header = source_header(&spec, &source.request.context)?;
        Ok(Self {
            source,
            spec,
            header,
            cpu,
            original,
        })
    }

    fn check(&self, ledger: &Ledger) -> RecheckResult<()> {
        self.source
            .check_original_request(self.source.request.owner, ledger)?;
        if self.cpu.heights != 18
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != requirements(self.cpu)?
            || (self.spec.first, self.spec.count, self.spec.level) != (0, 122, 3)
        {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    pub(super) fn plan_report(&self, ledger: &Ledger) -> RecheckResult<RootRecheckPlanReport> {
        self.check(ledger)?;
        let requirements = self.original.requirements();
        Ok(RootRecheckPlanReport {
            cpu_heights: self.cpu.heights,
            verifier_host_bytes: requirements.get(Category::IndependentVerifier).host,
            caller_host_bytes: requirements.get(Category::PhaseScratch).host,
            total_host_bytes: requirements
                .total()
                .map_err(|_| ParentCompileError::Overflow)?
                .host,
            planned_public_probes: PUBLICS,
        })
    }
}

impl<'bound, 'source, 'request> Component<'bound, 'source, 'request> {
    // This consuming entry is private to the same sequence. It accepts no
    // externally paired root/originals; they are the fields of one Component.
    pub(super) fn recheck_root(
        self,
        recheck: PreissuedRootRecheck<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> RecheckResult<RootPublicRecheckReport> {
        recheck.check(ledger)?;
        let retirement = self
            .originals
            .check(recheck.source.request.owner, ledger)
            .map_err(|_| ParentCompileError::Authority)?;
        let accepted = self.root.report();
        if !self.caller.belongs_to(ledger)
            || self.report.native_proofs != NATIVE
            || self.report.leaf_proofs != LEAVES
            || self.report.parent_proofs != PARENTS
            || self.report.workflow_admitted
            || self
                .originals
                .outer_step()
                .map_err(|_| ParentCompileError::Authority)?
                != HashxOuterStep::Parent3
            || accepted.parent != ROOT_ORDINAL
            || accepted.retirement != retirement
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err(ParentCompileError::Authority);
        }
        let child = AcceptedChild::Parent(self.root);
        child.check_original(
            recheck.source,
            super::super::super::SourceNode::Parent(ROOT_ORDINAL),
            ledger,
        )?;
        let action = RootPublicRecheckAction {
            child: &child,
            recheck: &recheck,
            ledger,
        };
        // On success or any returned error, action/result diagnostics finish
        // before local child destruction. The partial Component keeps its own
        // originals/support/caller until after those locals and recheck drop.
        child.output().recheck_root_publics(&action)
    }
}

fn require_relation_rejection(
    outcome: core::result::Result<(), RegisteredVerificationFailure>,
) -> RecheckResult<()> {
    match outcome {
        Err(RegisteredVerificationFailure::RelationRejected(_)) => Ok(()),
        Ok(())
        | Err(RegisteredVerificationFailure::Admission(_))
        | Err(RegisteredVerificationFailure::Configuration(_))
        | Err(RegisteredVerificationFailure::Allocation(_)) => Err(ParentCompileError::Source),
    }
}

impl RootPublicRecheckAction<'_, '_, '_, '_> {
    // Only the immutable output adapter supplies its own original fields.
    // This returns fixed diagnostics, never a key/proof/acceptance capability.
    pub(in crate::component_tree::owned_shake) fn verify_original(
        &self,
        owner: &output::RetainedNodeOutput<'_>,
        key: &NodeKey,
        proof: &NodeProof,
        request: &ReservedShakeRequest,
    ) -> RecheckResult<RootPublicRecheckReport> {
        self.recheck.check(self.ledger)?;
        if !core::ptr::eq(owner, self.child.output())
            || !core::ptr::eq(self.child.source(), self.recheck.source)
            || !core::ptr::eq(request, self.recheck.source.request.owner)
            || !owner.belongs_to(self.ledger)
            || key.spec != self.recheck.spec
            || key.height != self.child.height()
            || key.cap.as_slice() != &self.child.cap()[..]
            || key.cap.capacity() != super::super::super::super::ROOTS
            || proof.public.len() != PUBLICS
            || proof.public[..HEADER] != self.recheck.header
        {
            return Err(ParentCompileError::Source);
        }
        let started = std::time::Instant::now();
        let positive_started = std::time::Instant::now();
        key.verifier
            .verify_classified(&proof.proof, &proof.public)
            .map_err(|_| ParentCompileError::Source)?;
        let mut positive_verification_ns = positive_started.elapsed().as_nanos();
        let mutation_started = std::time::Instant::now();
        let mut public_probes = 0;
        for index in 0..PUBLICS {
            let mut changed = [Val::ZERO; PUBLICS];
            changed.copy_from_slice(&proof.public);
            changed[index] += Val::ONE;
            // No source-header comparison is applied to the mutation: only
            // the actual numerical verifier can earn a negative-probe count.
            let outcome = key.verifier.verify_classified(&proof.proof, &changed);
            changed[index] = proof.public[index];
            require_relation_rejection(outcome)?;
            public_probes += 1;
        }
        let mutation_verification_ns = mutation_started.elapsed().as_nanos();
        let positive_started = std::time::Instant::now();
        key.verifier
            .verify_classified(&proof.proof, &proof.public)
            .map_err(|_| ParentCompileError::Source)?;
        positive_verification_ns = positive_verification_ns
            .checked_add(positive_started.elapsed().as_nanos())
            .ok_or(ParentCompileError::Overflow)?;
        Ok(RootPublicRecheckReport {
            cpu_heights: self.recheck.cpu.heights,
            positive_checks: 2,
            public_probes,
            positive_verification_ns,
            mutation_verification_ns,
            elapsed_ns: started.elapsed().as_nanos(),
        })
    }
}

#[cfg(test)]
mod tests;
