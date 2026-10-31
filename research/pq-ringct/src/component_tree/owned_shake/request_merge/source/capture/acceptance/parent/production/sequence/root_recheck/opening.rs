//! One actual root opening probe under its own pre-native original claim.
//! No driver, CLI, raw-proof getter, clone or wider mutation success exists.
use super::*;
use lattica_prover_p3::block_v2::profile::{Challenge, Config};
use p3_batch_stark::BatchProof;

mod claims;
mod mutation;
use claims::additional_requirement;
use mutation::OpeningMutation;

const ROOTS: usize = super::super::super::super::super::ROOTS;

pub(in super::super) struct PreissuedRootOpening<'bound, 'source, 'request> {
    base: PreissuedRootRecheck<'bound, 'source, 'request>,
    additional: Reservation,
}

#[derive(Clone, Copy)]
pub(in super::super) struct RootOpeningPlanReport {
    pub(in super::super) cpu_heights: usize,
    pub(in super::super) verifier_host_bytes: u64,
    pub(in super::super) caller_host_bytes: u64,
    pub(in super::super) total_host_bytes: u64,
    pub(in super::super) planned_opening_probes: usize,
}

pub(in crate::component_tree::owned_shake) struct RootOpeningMeasurements {
    pub(in crate::component_tree::owned_shake) cpu_heights: usize,
    pub(in crate::component_tree::owned_shake) positive_checks: usize,
    pub(in crate::component_tree::owned_shake) opening_probes: usize,
    pub(in crate::component_tree::owned_shake) positive_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) mutation_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) elapsed_ns: u128,
    pub(in crate::component_tree::owned_shake) retained_output_restored: bool,
}

// Diagnostics retain their own original backing through their last use. This
// owner holds no root, proof, key, continuation or acceptance capability.
pub(in super::super) struct RetainedRootOpeningReport<'bound, 'source, 'request> {
    report: RootOpeningMeasurements,
    original: PreissuedRootOpening<'bound, 'source, 'request>,
}

// Constructed only while one consumed Component still holds its own actual
// Parent3 originals/support/caller. The address is compared, never dereferenced
// or serialized; it gives no raw access. Moving the output would refuse.
pub(in crate::component_tree::owned_shake) struct RootOpeningRecheckAction<
    'phase,
    'bound,
    'source,
    'request,
> {
    original: &'phase PreissuedRootOpening<'bound, 'source, 'request>,
    owner_address: *const (),
    height: usize,
    cap: [[Val; 4]; ROOTS],
    ledger: &'phase Ledger,
}

impl<'bound, 'source, 'request> PreissuedRootOpening<'bound, 'source, 'request> {
    // A future reviewed driver must call this before Attempt construction.
    // Source+Ledger do not enforce phase order: this inactive prerequisite is
    // not a temporal admission token or permission to upgrade a running path.
    pub(in super::super) fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        ledger: &Ledger,
    ) -> RecheckResult<Self> {
        let additional = ledger
            .admit_phase(additional_requirement()?)
            .map_err(|_| ParentCompileError::Capacity)?;
        let base = PreissuedRootRecheck::reserve_before_native(source, ledger)?;
        Ok(Self { base, additional })
    }

    fn check(&self, ledger: &Ledger) -> RecheckResult<()> {
        self.base.check(ledger)?;
        if !self.additional.belongs_to(ledger)
            || self.additional.requirements() != additional_requirement()?
        {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    pub(in super::super) fn plan_report(
        &self,
        ledger: &Ledger,
    ) -> RecheckResult<RootOpeningPlanReport> {
        self.check(ledger)?;
        let base = self.base.original.requirements();
        let additional = self.additional.requirements();
        let caller = base.get(Category::PhaseScratch).host
            .checked_add(additional.get(Category::PhaseScratch).host)
            .ok_or(ParentCompileError::Overflow)?;
        let verifier = base.get(Category::IndependentVerifier).host;
        let total = caller.checked_add(verifier).ok_or(ParentCompileError::Overflow)?;
        Ok(RootOpeningPlanReport {
            cpu_heights: self.base.cpu.heights,
            verifier_host_bytes: verifier,
            caller_host_bytes: caller,
            total_host_bytes: total,
            planned_opening_probes: 1,
        })
    }
}

impl RetainedRootOpeningReport<'_, '_, '_> {
    pub(in super::super) fn report(&self, ledger: &Ledger) -> RecheckResult<&RootOpeningMeasurements> {
        self.original.check(ledger)?;
        Ok(&self.report)
    }
}

impl<'bound, 'source, 'request> Component<'bound, 'source, 'request> {
    pub(in super::super) fn recheck_root_opening(
        self,
        original: PreissuedRootOpening<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> RecheckResult<RetainedRootOpeningReport<'bound, 'source, 'request>> {
        original.check(ledger)?;
        let retirement = self.originals
            .check(original.base.source.request.owner, ledger)
            .map_err(|_| ParentCompileError::Authority)?;
        let accepted = self.root.report();
        if !self.caller.belongs_to(ledger)
            || self.report.native_proofs != NATIVE
            || self.report.leaf_proofs != LEAVES
            || self.report.parent_proofs != PARENTS
            || self.report.workflow_admitted
            || self.originals.outer_step().map_err(|_| ParentCompileError::Authority)?
                != HashxOuterStep::Parent3
            || accepted.parent != ROOT_ORDINAL
            || accepted.retirement != retirement
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err(ParentCompileError::Authority);
        }
        let mut child = AcceptedChild::Parent(self.root);
        child.check_original(
            original.base.source,
            super::super::super::super::SourceNode::Parent(ROOT_ORDINAL),
            ledger,
        )?;
        let action = RootOpeningRecheckAction {
            original: &original,
            owner_address: core::ptr::from_ref(child.output()).cast(),
            height: child.height(),
            cap: *child.cap(),
            ledger,
        };
        let report = child.recheck_root_opening(&action)?;
        drop(action);
        // Restore/verify/classify precedes this actual proof destruction. The
        // partial Component still keeps its own originals/support/caller.
        drop(child);
        Ok(RetainedRootOpeningReport { report, original })
    }
}

impl RootOpeningRecheckAction<'_, '_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn check_owner(
        &self,
        owner: &output::RetainedNodeOutput<'_>,
    ) -> RecheckResult<()> {
        self.original.check(self.ledger)?;
        if core::ptr::from_ref(owner).cast::<()>() != self.owner_address
            || !owner.belongs_to(self.ledger)
        {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    // Only the sealed original output adapter supplies its own key/proof and
    // request, immediately after checking that exact output's address.
    pub(in crate::component_tree::owned_shake) fn verify_original(
        &self,
        key: &NodeKey,
        proof: &mut NodeProof,
        request: &ReservedShakeRequest,
    ) -> RecheckResult<RootOpeningMeasurements> {
        self.original.check(self.ledger)?;
        let base = &self.original.base;
        if !core::ptr::eq(request, base.source.request.owner)
            || key.spec != base.spec
            || key.height != self.height
            || key.cap.as_slice() != &self.cap[..]
            || key.cap.capacity() != ROOTS
            || proof.public.len() != PUBLICS
            || proof.public[..HEADER] != base.header
        {
            return Err(ParentCompileError::Source);
        }
        let started = std::time::Instant::now();
        let positive_started = std::time::Instant::now();
        key.verifier.verify_classified(&proof.proof, &proof.public)
            .map_err(|_| ParentCompileError::Source)?;
        let mut positive_verification_ns = positive_started.elapsed().as_nanos();

        let mutation_started = std::time::Instant::now();
        let guard = OpeningMutation::new(&mut proof.proof)?;
        let saved = guard.original();
        let outcome = key.verifier.verify_classified(guard.proof(), &proof.public);
        // The guard restores before a returned result is classified, and its
        // Drop performs the same restoration on unwind. No catch/retry exists.
        drop(guard);
        if proof.proof.opened_values.instances[0].permutation_local[0] != saved {
            return Err(ParentCompileError::Source);
        }
        require_relation_rejection(outcome)?;
        let mutation_verification_ns = mutation_started.elapsed().as_nanos();

        let positive_started = std::time::Instant::now();
        key.verifier.verify_classified(&proof.proof, &proof.public)
            .map_err(|_| ParentCompileError::Source)?;
        positive_verification_ns = positive_verification_ns
            .checked_add(positive_started.elapsed().as_nanos())
            .ok_or(ParentCompileError::Overflow)?;
        Ok(RootOpeningMeasurements {
            cpu_heights: base.cpu.heights,
            positive_checks: 2,
            opening_probes: 1,
            positive_verification_ns,
            mutation_verification_ns,
            elapsed_ns: started.elapsed().as_nanos(),
            retained_output_restored: true,
        })
    }
}

#[cfg(test)]
mod tests;
