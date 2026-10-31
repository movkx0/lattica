//! Private original compiler storage. This is not an attempt lineage token.
//!
//! The future combined sequence must construct this bank before native work and
//! keep it together with its actual producer, children and A continuation. No
//! external bank/compiler pair, retired-original argument or raw token escape
//! exists here. Full-request dispatch remains closed.

use super::*;
use crate::component_tree::owned_shake::{
    CompilationFailure, CompilerAdmission, GroupCompilePlan, OwnedCompiledShake, PlanResult,
    Summary, VerificationFailure, VerificationPlan, VerificationReceipt, AUTHORITY,
};
use crate::execution::phase_report::{PhaseIdentity, PhaseKind, PhaseReportOwner};
use crate::graph_crypto::{ReservedNativeChild, ShakeWrapperLayout};

mod claims;
use claims::{caller_requirement, maximum, reunite, sum};

const LEAF_COUNT: usize = super::super::super::super::super::LEAVES;

/// Its actual compiler payload, when present, is owned by BankedLeaf/Parent.
/// This owner is never reexported from the parent compiler subtree.
pub(super) struct CompilerBank<'group, 'bound, 'source, 'request> {
    source: &'bound Source<'source, 'request>,
    groups: [&'group GroupCompilePlan<'request>; LEAF_COUNT],
    whole: Requirements,
    original: Reservation,
    caller: Reservation,
}

/// The payload is destroyed before the residual bank on every exit. Success
/// reclamation returns this same bank only after all payloads actually die.
pub(super) struct BankedLeaf<'group, 'bound, 'source, 'request> {
    compiled: LeafPayload<'request>,
    ordinal: usize,
    bank: CompilerBank<'group, 'bound, 'source, 'request>,
}

struct LeafPayload<'request>(Option<OwnedCompiledShake<'request>>);

impl<'request> LeafPayload<'request> {
    fn get(&self) -> &OwnedCompiledShake<'request> {
        self.0.as_ref().expect("private banked compiler payload")
    }
}

fn clear_witness(payload: &mut CompiledNode) {
    for value in &mut payload.witness {
        // SAFETY: no raw witness borrow escapes this private banked owner.
        unsafe { core::ptr::write_volatile(value, Val::ZERO) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Drop for LeafPayload<'_> {
    fn drop(&mut self) {
        if let Some(compiled) = &mut self.0 {
            clear_witness(&mut compiled.compiled);
        }
    }
}

pub(super) struct BankedParent<'group, 'bound, 'source, 'request> {
    compiled: CompiledLeafParent<'bound, 'source, 'request>,
    bank: CompilerBank<'group, 'bound, 'source, 'request>,
}

/// A compiler failure keeps its original bounded report. It is terminal; no
/// failed bank or partial compiler can be restored for another proof attempt.
pub(super) enum Failure {
    Admission(Error),
    Compilation {
        failure: CompilationFailure,
        // The actual bounded report dies before its added bank caller claim.
        caller: Reservation,
    },
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Admission(error)
    }
}

type BankResult<T> = core::result::Result<T, Failure>;

struct BankAdmission<'phase> {
    original: &'phase mut Reservation,
    program: Requirements,
    inputs: Requirements,
    // Preserve both separately admitted verifier components throughout a pair.
    // Sequential single-original reuse is deliberately not introduced here.
    returned: [Option<Reservation>; 2],
    verified: usize,
}

impl CompilerAdmission for BankAdmission<'_> {
    fn report_token(&mut self) -> PlanResult<Reservation> {
        self.original
            .split(PhaseReportOwner::requirements())
            .map_err(|_| AUTHORITY)
    }

    fn verifier_token(&mut self) -> PlanResult<Reservation> {
        self.original
            .split(VerificationPlan::component_requirement())
            .map_err(|_| AUTHORITY)
    }

    fn program_token(&mut self) -> PlanResult<Reservation> {
        self.original.split(self.program).map_err(|_| AUTHORITY)
    }

    fn input_token(&mut self) -> PlanResult<Reservation> {
        self.original.split(self.inputs).map_err(|_| AUTHORITY)
    }

    fn verify_child(
        &mut self,
        child: &ReservedNativeChild<'_>,
        original: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<(), VerificationFailure> {
        if self.verified >= self.returned.len() || self.returned[self.verified].is_some() {
            return Err(VerificationFailure::Configuration(AUTHORITY));
        }
        let (_, original) = child.verify_pre_reserved_retaining_original(original, ledger)?;
        self.returned[self.verified] = Some(original);
        self.verified += 1;
        Ok(())
    }
}

fn check_groups(
    source: &Source<'_, '_>,
    groups: &[&GroupCompilePlan<'_>; LEAF_COUNT],
    ledger: &Ledger,
) -> Result<()> {
    if !source.is_for(source.request, ledger) {
        return Err(Error::Authority);
    }
    for (ordinal, group) in groups.iter().enumerate() {
        let original = source.request.sources[ordinal]
            .as_ref()
            .ok_or(Error::Source)?;
        if group.ordinal != ordinal
            || group.layout != ShakeWrapperLayout::PairedV1
            || group.span != source.request.tree.spans[ordinal]
            || !original.is_for(group, ledger)
        {
            return Err(Error::Source);
        }
    }
    Ok(())
}

fn whole_requirement(groups: &[&GroupCompilePlan<'_>; LEAF_COUNT]) -> Result<Requirements> {
    let mut whole = Storage::source()?.complete;
    for group in groups {
        whole = maximum(whole, group.requirements())?;
    }
    Ok(whole)
}

impl<'group, 'bound, 'source, 'request> CompilerBank<'group, 'bound, 'source, 'request> {
    pub(super) fn reserve_before_native(
        source: &'bound Source<'source, 'request>,
        groups: [&'group GroupCompilePlan<'request>; LEAF_COUNT],
        ledger: &Ledger,
    ) -> Result<Self> {
        // Own added bank/source/reclamation call frames before inspecting or
        // constructing any of the bank's runtime metadata.
        let caller = ledger
            .admit_phase(caller_requirement()?)
            .map_err(|_| Error::Capacity)?;
        check_groups(source, &groups, ledger)?;
        let allowance = ledger.snapshot().allowance;
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) || allowance.device > 8 << 30 {
            return Err(Error::Authority);
        }
        let whole = whole_requirement(&groups)?;
        let original = ledger.admit_phase(whole).map_err(|_| Error::Capacity)?;
        Ok(Self {
            source,
            groups,
            whole,
            original,
            caller,
        })
    }

    fn check(&self, ledger: &Ledger, outstanding: Requirements) -> Result<()> {
        check_groups(self.source, &self.groups, ledger)?;
        if !self.original.belongs_to(ledger)
            || !self.caller.belongs_to(ledger)
            || self.caller.requirements() != caller_requirement()?
            || self.whole != whole_requirement(&self.groups)?
            || sum(self.original.requirements(), outstanding)? != self.whole
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub(super) fn compile_leaf(
        mut self,
        ordinal: usize,
        children: [Option<ReservedNativeChild<'request>>; 2],
        ledger: &Ledger,
    ) -> BankResult<BankedLeaf<'group, 'bound, 'source, 'request>> {
        self.check(ledger, Requirements::default())?;
        let group = *self.groups.get(ordinal).ok_or(Error::Source)?;
        let mut phase = self
            .original
            .split(group.requirements())
            .map_err(|_| Error::Authority)?;
        let mut admission = BankAdmission {
            original: &mut phase,
            program: group.program,
            inputs: group.inputs,
            returned: [None, None],
            verified: 0,
        };
        let compiled = match group.compile_owned(children, &mut admission, ledger) {
            Ok(compiled) => LeafPayload(Some(compiled)),
            Err(failure) => {
                // Verification and compiler temporaries have already died;
                // the failure owns its report original. Preserve the added
                // caller through the failure's actual last reporting use.
                drop(admission);
                drop(phase);
                let Self {
                    original, caller, ..
                } = self;
                drop(original);
                return Err(Failure::Compilation { failure, caller });
            }
        };
        if admission.verified != group.span.segment_count {
            return Err(Error::Authority.into());
        }
        let BankAdmission { returned, .. } = admission;
        for original in returned.into_iter().flatten() {
            phase = reunite(phase, original)?;
        }
        self.original = reunite(self.original, phase)?;
        let outstanding = leaf_outstanding(group)?;
        self.check(ledger, outstanding)?;
        self.source.request.sources[ordinal]
            .as_ref()
            .ok_or(Error::Source)?
            .check_compiled(compiled.get(), ledger)
            .map_err(|_| Error::Source)?;
        Ok(BankedLeaf {
            compiled,
            ordinal,
            bank: self,
        })
    }

    pub(super) fn compile_parent(
        mut self,
        ordinal: usize,
        left: AcceptedChild<'bound, 'source, 'request>,
        right: AcceptedChild<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> Result<BankedParent<'group, 'bound, 'source, 'request>> {
        self.check(ledger, Requirements::default())?;
        let (children, specs) = specs(self.source, ordinal)?;
        let storage = Storage::source()?;
        let original = self
            .original
            .split(storage.complete)
            .map_err(|_| Error::Authority)?;
        let compiler = PreissuedLeafParentCompiler {
            source: self.source,
            ordinal,
            children,
            specs,
            storage,
            original,
        };
        let compiled = compiler.compile_children(left, right, ledger)?;
        self.check(ledger, storage.complete)?;
        Ok(BankedParent {
            compiled,
            bank: self,
        })
    }
}

fn leaf_outstanding(group: &GroupCompilePlan<'_>) -> Result<Requirements> {
    sum(
        sum(group.program, group.inputs)?,
        PhaseReportOwner::requirements(),
    )
}

fn leaf_identity(group: &GroupCompilePlan<'_>) -> Result<PhaseIdentity> {
    Ok(PhaseIdentity {
        kind: PhaseKind::WrapperCompilation,
        ordinal: u64::try_from(group.ordinal).map_err(|_| Error::Overflow)?,
        first_segment: u64::try_from(group.span.first_segment).map_err(|_| Error::Overflow)?,
        segment_count: u8::try_from(group.span.segment_count).map_err(|_| Error::Overflow)?,
        profile: group.contract.profile,
    })
}

impl<'group, 'bound, 'source, 'request> BankedLeaf<'group, 'bound, 'source, 'request> {
    pub(super) fn compiled(&self) -> &OwnedCompiledShake<'request> {
        self.compiled.get()
    }

    pub(super) fn reclaim(
        self,
        ledger: &Ledger,
    ) -> Result<CompilerBank<'group, 'bound, 'source, 'request>> {
        let group = *self.bank.groups.get(self.ordinal).ok_or(Error::Source)?;
        self.bank.check(ledger, leaf_outstanding(group)?)?;
        self.bank.source.request.sources[self.ordinal]
            .as_ref()
            .ok_or(Error::Source)?
            .check_compiled(self.compiled.get(), ledger)
            .map_err(|_| Error::Source)?;
        if self.compiled.get()._program.requirements() != group.program
            || self.compiled.get()._inputs.requirements() != group.inputs
            || Arc::strong_count(&self.compiled.get().compiled.program) != 1
            || Arc::weak_count(&self.compiled.get().compiled.program) != 0
        {
            return Err(Error::Authority);
        }
        let identity = leaf_identity(group)?;
        let Self {
            mut compiled,
            mut bank,
            ..
        } = self;
        let OwnedCompiledShake {
            compiled: mut payload,
            report,
            _program,
            _inputs,
            ..
        } = compiled.0.take().expect("private banked compiler payload");
        clear_witness(&mut payload);
        drop(payload);
        // A044 destroys actual Box payload/encoding before returning this
        // exact report token. Every failure here is terminal, with no retry.
        let report = report
            .reclaim_original(identity, &bank.caller, ledger)
            .map_err(|_| Error::Authority)?;
        bank.original = reunite(bank.original, _program)?;
        bank.original = reunite(bank.original, _inputs)?;
        bank.original = reunite(bank.original, report)?;
        bank.check(ledger, Requirements::default())?;
        Ok(bank)
    }
}

impl<'group, 'bound, 'source, 'request> BankedParent<'group, 'bound, 'source, 'request> {
    pub(super) fn compiled(&self) -> &CompiledLeafParent<'bound, 'source, 'request> {
        &self.compiled
    }

    pub(super) fn reclaim(
        self,
        ledger: &Ledger,
    ) -> Result<CompilerBank<'group, 'bound, 'source, 'request>> {
        let storage = Storage::source()?;
        self.bank.check(ledger, storage.complete)?;
        if !core::ptr::eq(self.compiled.source, self.bank.source)
            || !self.compiled.original.belongs_to(ledger)
            || self.compiled.original.requirements() != storage.complete
            || Arc::strong_count(&self.compiled.payload.0.program) != 1
            || Arc::weak_count(&self.compiled.payload.0.program) != 0
        {
            return Err(Error::Authority);
        }
        let Self { compiled, mut bank } = self;
        let CompiledLeafParent {
            payload, original, ..
        } = compiled;
        // Payload::drop clears the actual witness; the Program and both Vecs
        // are then destroyed while their whole original claim is still live.
        drop(payload);
        bank.original = reunite(bank.original, original)?;
        bank.check(ledger, Requirements::default())?;
        Ok(bank)
    }
}

#[cfg(test)]
mod tests;
