//! One original Leaf0 opening probe before the same Attempt consumes Parent0.
//! The complete extra owner survives success/failure reports and destruction.
use super::*;
use super::super::super::{specs, SourceNode};
use super::super::super::super::CpuEnvelope;
use crate::component_tree::{
    commitment, words, EndpointContext, Kind, Spec, CONTEXT, CONTRACT_DOMAIN, COUNT,
    DESCRIPTOR, EXPECTED_INPUT, EXPECTED_OUTPUT, FIRST, HEADER, KIND, LEVEL, REQUEST,
    STATEMENT, TOTAL,
};
use lattica_prover_p3::block_v2::{
    machine::backend::RegisteredVerificationFailure,
    profile::{Challenge, Config},
};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;

pub(super) mod claims;
mod mutation;
use mutation::OpeningMutation;

type InteriorResult<T> = core::result::Result<T, ParentCompileError>;
pub(super) fn common_forwarding_host_bytes() -> InteriorResult<usize> {
    claims::common_forwarding_host_bytes()
}

const PUBLICS: usize = HEADER + 8;
const ROOTS: usize = super::super::super::super::ROOTS;

pub(super) struct PreissuedInteriorChildOpening<'bound, 'source, 'request> {
    source: &'bound ParentSourceBound<'source, 'request>,
    spec: Spec,
    header: [Val; HEADER],
    retained: RetainedInteriorOpening,
}

// No Copy/Clone, source storage credit or detached report constructor. Fixed
// diagnostics die before both complete independently admitted originals.
pub(super) struct RetainedInteriorOpening {
    report: Option<InteriorOpeningMeasurements>,
    cpu: CpuEnvelope,
    verifier: Reservation,
    caller: Reservation,
}

pub(super) struct InteriorOpeningPlanReport {
    pub(super) cpu_heights: usize,
    pub(super) verifier_host_bytes: u64,
    pub(super) caller_host_bytes: u64,
    pub(super) total_host_bytes: u64,
    pub(super) planned_opening_probes: usize,
}

pub(in crate::component_tree::owned_shake) struct InteriorOpeningMeasurements {
    pub(in crate::component_tree::owned_shake) cpu_heights: usize,
    pub(in crate::component_tree::owned_shake) positive_checks: usize,
    pub(in crate::component_tree::owned_shake) opening_probes: usize,
    pub(in crate::component_tree::owned_shake) positive_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) mutation_verification_ns: u128,
    pub(in crate::component_tree::owned_shake) elapsed_ns: u128,
    pub(in crate::component_tree::owned_shake) retained_output_restored: bool,
    pub(in crate::component_tree::owned_shake) parent0_child_consumed: bool,
}

// Constructed only inside the selected State's exact Parent0 hook. The address
// is compared, never dereferenced or serialized. No external callback exists.
pub(in crate::component_tree::owned_shake) struct InteriorOpeningAction<
    'phase, 'bound, 'source, 'request,
> {
    original: &'phase PreissuedInteriorChildOpening<'bound, 'source, 'request>,
    owner_address: *const (),
    height: usize,
    cap: [[Val; 4]; ROOTS],
    ledger: &'phase Ledger,
}

fn source_header(spec: &Spec, context: &EndpointContext) -> InteriorResult<[Val; HEADER]> {
    let Kind::Shake(descriptor) = &spec.contract.kind else {
        return Err(ParentCompileError::Source);
    };
    if descriptor.input_len != 16_416 || descriptor.output_len != 137
        || (spec.first, spec.count, spec.level, spec.contract.total) != (0, 32, 0, 122)
    {
        return Err(ParentCompileError::Source);
    }
    let fields = [spec.contract.tag(), u64::from(spec.contract.total),
        u64::try_from(descriptor.input_len).map_err(|_| ParentCompileError::Overflow)?,
        u64::try_from(descriptor.output_len).map_err(|_| ParentCompileError::Overflow)?];
    let descriptor = commitment::hash_fields(CONTRACT_DOMAIN, &fields)
        .map_err(|_| ParentCompileError::Source)?.map(Val::from_u64);
    let mut header = [Val::ZERO; HEADER];
    header[..8].copy_from_slice(&words(&spec.contract.profile));
    header[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&context.context));
    for (offset, values) in [(STATEMENT, context.statement), (EXPECTED_INPUT, context.input),
        (EXPECTED_OUTPUT, context.output)] {
        header[offset..offset + 4].copy_from_slice(&values);
    }
    for (offset, value) in [(KIND, spec.contract.tag()), (REQUEST, u64::from(spec.contract.request)),
        (FIRST, u64::from(spec.first)), (COUNT, u64::from(spec.count)),
        (TOTAL, u64::from(spec.contract.total)), (LEVEL, u64::from(spec.level))] {
        header[offset] = Val::from_u64(value);
    }
    header[DESCRIPTOR..DESCRIPTOR + 4].copy_from_slice(&descriptor);
    Ok(header)
}

impl<'bound, 'source, 'request> PreissuedInteriorChildOpening<'bound, 'source, 'request> {
    fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>, ledger: &Ledger,
    ) -> InteriorResult<Self> {
        let caller = ledger.admit_phase(claims::caller_requirement()?)
            .map_err(|_| ParentCompileError::Capacity)?;
        source.check_original_request(source.request.owner, ledger)?;
        let cpu = CpuEnvelope::source()?;
        let verifier = ledger.admit_phase(claims::verifier_requirement(cpu)?)
            .map_err(|_| ParentCompileError::Capacity)?;
        let (edges, expected) = specs(source, 0)?;
        let [spec, sibling, parent] = expected;
        if edges != [SourceNode::Leaf(0), SourceNode::Leaf(1)]
            || (sibling.first, sibling.count, sibling.level) != (32, 32, 0)
            || (parent.first, parent.count, parent.level) != (0, 64, 1)
        {
            return Err(ParentCompileError::Source);
        }
        let header = source_header(&spec, &source.request.context)?;
        Ok(Self { source, spec, header,
            retained: RetainedInteriorOpening { report: None, cpu, verifier, caller } })
    }

    fn check(&self, ledger: &Ledger) -> InteriorResult<()> {
        self.source.check_original_request(self.source.request.owner, ledger)?;
        self.retained.check(ledger)?;
        if (self.spec.first, self.spec.count, self.spec.level) != (0, 32, 0) {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    pub(super) fn into_retained(self) -> RetainedInteriorOpening {
        self.retained
    }
}

impl RetainedInteriorOpening {
    fn check(&self, ledger: &Ledger) -> InteriorResult<()> {
        if self.cpu.heights != 18 || self.cpu.bytes == 0
            || !self.caller.belongs_to(ledger) || !self.verifier.belongs_to(ledger)
            || self.caller.requirements() != claims::caller_requirement()?
            || self.verifier.requirements() != claims::verifier_requirement(self.cpu)?
        {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    fn plan_report(&self, ledger: &Ledger) -> InteriorResult<InteriorOpeningPlanReport> {
        self.check(ledger)?;
        let caller = self.caller.requirements().total().map_err(|_| ParentCompileError::Overflow)?.host;
        let verifier = self.verifier.requirements().total().map_err(|_| ParentCompileError::Overflow)?.host;
        Ok(InteriorOpeningPlanReport { cpu_heights: self.cpu.heights,
            verifier_host_bytes: verifier, caller_host_bytes: caller,
            total_host_bytes: caller.checked_add(verifier).ok_or(ParentCompileError::Overflow)?,
            planned_opening_probes: 1 })
    }

    pub(super) fn report(&self, ledger: &Ledger) -> InteriorResult<&InteriorOpeningMeasurements> {
        self.check(ledger)?;
        let measured = self.report.as_ref().ok_or(ParentCompileError::Authority)?;
        check_measurements(measured)?;
        if !measured.parent0_child_consumed {
            return Err(ParentCompileError::Authority);
        }
        Ok(measured)
    }
}

impl<'group, 'bound, 'source, 'request> Attempt<'group, 'bound, 'source, 'request> {
    // This closed constructor creates the extra originals before the existing
    // constructor can assign PendingNative capacity. No running path upgrades.
    pub(super) fn reserve_interior_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        groups: [&'group GroupCompilePlan<'request>; LEAVES], ledger: &Ledger,
    ) -> Result<Self> {
        let interior = PreissuedInteriorChildOpening::reserve_before_native(source, ledger)
            .map_err(|_| Error::Authority)?;
        let mut attempt = Self::reserve_before_native(source, groups, ledger)?;
        if attempt.state.interior.is_some() { return Err(Error::Authority); }
        attempt.state.interior = Some(interior);
        Ok(attempt)
    }

    pub(super) fn interior_plan(&self, ledger: &Ledger) -> InteriorResult<InteriorOpeningPlanReport> {
        let original = self.state.interior.as_ref().ok_or(ParentCompileError::Authority)?;
        original.check(ledger)?;
        if !self.caller.belongs_to(ledger) || self.state.next != 0 || original.retained.report.is_some() {
            return Err(ParentCompileError::Authority);
        }
        original.retained.plan_report(ledger)
    }
}

impl Component<'_, '_, '_> {
    pub(super) fn interior_report(&self, ledger: &Ledger) -> InteriorResult<&InteriorOpeningMeasurements> {
        if !self.caller.belongs_to(ledger) || self.report.native_proofs != NATIVE
            || self.report.leaf_proofs != LEAVES || self.report.parent_proofs != PARENTS
            || self.report.workflow_admitted
        { return Err(ParentCompileError::Authority); }
        self.interior.as_ref().ok_or(ParentCompileError::Authority)?.report(ledger)
    }
}

fn same_acceptance(a: &LeafAcceptanceReport, b: &LeafAcceptanceReport) -> bool {
    a.leaf == b.leaf && a.height == b.height && a.cpu_heights_admitted == b.cpu_heights_admitted
        && a.cpu_reserved_bytes == b.cpu_reserved_bytes
        && a.independent_verification_ns == b.independent_verification_ns
        && a.retirement == b.retirement && a.source_key_authenticated == b.source_key_authenticated
        && a.transaction_context_authenticated == b.transaction_context_authenticated
        && a.workflow_admitted == b.workflow_admitted
}

fn check_measurements(measured: &InteriorOpeningMeasurements) -> InteriorResult<()> {
    let sum = measured.positive_verification_ns.checked_add(measured.mutation_verification_ns)
        .ok_or(ParentCompileError::Overflow)?;
    if measured.cpu_heights != 18 || measured.positive_checks != 2 || measured.opening_probes != 1
        || !measured.retained_output_restored || measured.positive_verification_ns == 0
        || measured.mutation_verification_ns == 0 || measured.elapsed_ns == 0 || sum > measured.elapsed_ns
    { return Err(ParentCompileError::Source); }
    Ok(())
}

pub(super) fn probe_before_parent(
    state: &mut State<'_, '_, '_, '_>, ordinal: usize,
    left: &mut AcceptedChild<'_, '_, '_>, right: &AcceptedChild<'_, '_, '_>,
) -> Result<()> {
    if state.interior.is_none() { return Ok(()); }
    if ordinal != 0 {
        return state.interior.as_ref().ok_or(Error::Authority)?.retained
            .report(&state.ledger).map(|_| ()).map_err(|_| Error::Authority);
    }
    let checked = probe_original_parent0(state, left, right);
    checked.map_err(|_| Error::Authority)
}

fn probe_original_parent0(
    state: &mut State<'_, '_, '_, '_>, left: &mut AcceptedChild<'_, '_, '_>,
    right: &AcceptedChild<'_, '_, '_>,
) -> InteriorResult<()> {
    if state.next != 2 || ORDER[state.next] != Phase::Parent(0)
        || state.report.native_proofs != NATIVE || state.report.leaf_proofs != 2
        || state.report.parent_proofs != 0 || state.bank.is_none()
    { return Err(ParentCompileError::Authority); }
    state.source.check_original_request(state.request, &state.ledger)?;
    let originals = state.originals.as_ref().ok_or(ParentCompileError::Authority)?;
    let current = originals.check(state.request, &state.ledger).map_err(|_| ParentCompileError::Authority)?;
    if originals.outer_step().map_err(|_| ParentCompileError::Authority)? != HashxOuterStep::Leaf1 {
        return Err(ParentCompileError::Authority);
    }
    left.check_original(state.source, SourceNode::Leaf(0), &state.ledger)?;
    right.check_original(state.source, SourceNode::Leaf(1), &state.ledger)?;
    let (AcceptedChild::Leaf(selected), AcceptedChild::Leaf(sibling)) = (&*left, right) else {
        return Err(ParentCompileError::Source);
    };
    let saved_left = state.report.leaf_acceptance[0].as_ref().ok_or(ParentCompileError::Authority)?;
    let saved_right = state.report.leaf_acceptance[1].as_ref().ok_or(ParentCompileError::Authority)?;
    if !same_acceptance(&selected.report, saved_left) || !same_acceptance(&sibling.report, saved_right)
        || sibling.report.retirement != current
        || selected.height != state.report.leaf_compilation[0].as_ref().ok_or(ParentCompileError::Authority)?.padded_rows
        || sibling.height != state.report.leaf_compilation[1].as_ref().ok_or(ParentCompileError::Authority)?.padded_rows
    { return Err(ParentCompileError::Authority); }
    // Historical Leaf0 acceptance is compared only with its matching State
    // record. The current opaque originals belong to Leaf1, never to Leaf0.
    let original = state.interior.as_mut().ok_or(ParentCompileError::Authority)?;
    original.check(&state.ledger)?;
    if !core::ptr::eq(original.source, state.source) || original.retained.report.is_some() {
        return Err(ParentCompileError::Authority);
    }
    let action = InteriorOpeningAction { original, owner_address: core::ptr::from_ref(left.output()).cast(),
        height: left.height(), cap: *left.cap(), ledger: &state.ledger };
    let measured = left.recheck_interior_opening(&action)?;
    drop(action);
    check_measurements(&measured)?;
    if measured.parent0_child_consumed { return Err(ParentCompileError::Source); }
    original.retained.report = Some(measured);
    // The original remains in State on success, every returned error, and
    // unwinding. Never take it into a local that could die before the children.
    emit_scope(original.retained.report.as_ref().ok_or(ParentCompileError::Authority)?);
    Ok(())
}

pub(super) fn parent_completed(state: &mut State<'_, '_, '_, '_>, ordinal: usize) -> Result<()> {
    if ordinal != 0 || state.interior.is_none() { return Ok(()); }
    if state.next != 3 || state.accepted_parents[0].is_none() || state.bank.is_none()
        || state.report.parent_proofs != 1
    { return Err(Error::Authority); }
    let original = state.interior.as_mut().ok_or(Error::Authority)?;
    original.check(&state.ledger).map_err(|_| Error::Authority)?;
    let measured = original.retained.report.as_mut().ok_or(Error::Authority)?;
    check_measurements(measured).map_err(|_| Error::Authority)?;
    if measured.parent0_child_consumed { return Err(Error::Authority); }
    measured.parent0_child_consumed = true;
    Ok(())
}

pub(super) fn require_completed(state: &State<'_, '_, '_, '_>) -> Result<()> {
    if let Some(original) = &state.interior {
        original.check(&state.ledger).map_err(|_| Error::Authority)?;
        original.retained.report(&state.ledger).map_err(|_| Error::Authority)?;
    }
    Ok(())
}

fn require_relation_rejection(outcome: core::result::Result<(), RegisteredVerificationFailure>) -> InteriorResult<()> {
    match outcome {
        Err(RegisteredVerificationFailure::RelationRejected(_)) => Ok(()),
        Ok(()) | Err(RegisteredVerificationFailure::Admission(_))
        | Err(RegisteredVerificationFailure::Configuration(_))
        | Err(RegisteredVerificationFailure::Allocation(_)) => Err(ParentCompileError::Source),
    }
}

impl InteriorOpeningAction<'_, '_, '_, '_> {
    pub(in crate::component_tree::owned_shake) fn check_owner(&self, owner: &output::RetainedNodeOutput<'_>) -> InteriorResult<()> {
        self.original.check(self.ledger)?;
        if core::ptr::from_ref(owner).cast::<()>() != self.owner_address || !owner.belongs_to(self.ledger) {
            return Err(ParentCompileError::Authority);
        }
        Ok(())
    }

    pub(in crate::component_tree::owned_shake) fn verify_original(
        &self, key: &NodeKey, proof: &mut NodeProof, request: &ReservedShakeRequest,
    ) -> InteriorResult<InteriorOpeningMeasurements> {
        self.original.check(self.ledger)?;
        if !core::ptr::eq(request, self.original.source.request.owner)
            || key.spec != self.original.spec || key.height != self.height
            || key.cap.as_slice() != &self.cap[..] || key.cap.capacity() != ROOTS
            || proof.public.len() != PUBLICS || proof.public[..HEADER] != self.original.header
        { return Err(ParentCompileError::Source); }
        let started = std::time::Instant::now();
        let positive_started = std::time::Instant::now();
        key.verifier.verify_classified(&proof.proof, &proof.public).map_err(|_| ParentCompileError::Source)?;
        let mut positive_verification_ns = positive_started.elapsed().as_nanos();
        let mutation_started = std::time::Instant::now();
        let guard = OpeningMutation::new(&mut proof.proof)?;
        let saved = guard.original();
        let outcome = key.verifier.verify_classified(guard.proof(), &proof.public);
        drop(guard);
        if proof.proof.opened_values.instances[0].permutation_local[0] != saved {
            return Err(ParentCompileError::Source);
        }
        require_relation_rejection(outcome)?;
        let mutation_verification_ns = mutation_started.elapsed().as_nanos();
        let positive_started = std::time::Instant::now();
        key.verifier.verify_classified(&proof.proof, &proof.public).map_err(|_| ParentCompileError::Source)?;
        positive_verification_ns = positive_verification_ns.checked_add(positive_started.elapsed().as_nanos())
            .ok_or(ParentCompileError::Overflow)?;
        Ok(InteriorOpeningMeasurements { cpu_heights: self.original.retained.cpu.heights,
            positive_checks: 2, opening_probes: 1, positive_verification_ns,
            mutation_verification_ns, elapsed_ns: started.elapsed().as_nanos(),
            retained_output_restored: true, parent0_child_consumed: false })
    }
}

fn emit_scope(measured: &InteriorOpeningMeasurements) {
    // Filled from the independently frozen exact C field contract. No report
    // or proof ownership escapes, and the original remains held by State.
    eprintln!(
        "ringct_hashx_interior_opening_scope artifact_roundtrip_complete=false child_first_unit=0 child_kind=leaf child_level=0 child_ordinal=0 child_side=left child_units=32 complete_ringct_workflow=false cpu_heights=18 disk_artifact_roundtrip_complete=false execution_point=before-parent0-compiler interior_mutation_checks_complete=false mutation_checks_complete=false numerical_positive_checks=2 opening_scope=single-interior-parent0-left-leaf0-first-local-permutation-opening parent0_child_consumed=false parent_boundary_mutation_checks_complete=false parent_first_unit=0 parent_level=1 parent_ordinal=0 parent_units=64 provisional=true raw_proof_mutation_checks_complete=false retained_output_restored=true sibling_first_unit=32 sibling_level=0 sibling_ordinal=1 sibling_units=32 source_key_authenticated=true terminal_cleanup_complete=false timing_scope=within-component-preparation transaction_context_authenticated=false typed_opening_relation_rejections=1 whole_graph_mutation_checks_complete=false positive_verification_ns={} mutation_verification_ns={} opening_action_ns={}",
        measured.positive_verification_ns, measured.mutation_verification_ns, measured.elapsed_ns
    );
}

#[cfg(test)]
mod tests;
