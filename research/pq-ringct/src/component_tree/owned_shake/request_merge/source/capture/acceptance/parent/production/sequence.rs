//! One private original HashX attempt; no detached child/continuation inputs.
//!
//! The constructor receives only immutable source plans and their ledger. It
//! creates all producers, compiler storage and A's sequence internally before
//! native capacity is assigned. The only execution entry consumes the attempt;
//! every returned failure destroys its remaining state and permits no retry.
//! This closes one research HashX component, never a complete transaction.

use super::super::bank::{self, BankedLeaf, BankedParent, CompilerBank};
use super::*;
use crate::component_tree::owned_shake::{
    source_shape::GroupSourceBound, GroupCompilePlan, OwnedCompiledShake, ShakeWrapperLayout,
    Summary,
};
use crate::graph_crypto::{
    CompletedNativeHashx, PendingNativeHashx, PreissuedHashxOuter, ReservedNativeChild,
    RetiredHashxOuter,
};

mod claims;
use claims::attempt_requirement;

#[cfg(test)]
mod refusal;

#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod root_recheck;
#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod root_transport;
#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(in crate::component_tree::owned_shake) use root_transport::{
    RootTransportAction, RootTransportMeasurements,
};
#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(in crate::component_tree::owned_shake) use root_recheck::{
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod interior_opening;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use interior_opening::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
};

const LEAVES: usize = 5;
const PARENTS: usize = 4;
const NATIVE: usize = 10;
const OUTER: usize = LEAVES + PARENTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Leaf(usize),
    Parent(usize),
}

const ORDER: [Phase; OUTER] = [
    Phase::Leaf(0),
    Phase::Leaf(1),
    Phase::Parent(0),
    Phase::Leaf(2),
    Phase::Leaf(3),
    Phase::Parent(1),
    Phase::Parent(2),
    Phase::Leaf(4),
    Phase::Parent(3),
];

const STEPS: [HashxOuterStep; OUTER] = [
    HashxOuterStep::Leaf0,
    HashxOuterStep::Leaf1,
    HashxOuterStep::Parent0,
    HashxOuterStep::Leaf2,
    HashxOuterStep::Leaf3,
    HashxOuterStep::Parent1,
    HashxOuterStep::Parent2,
    HashxOuterStep::Leaf4,
    HashxOuterStep::Parent3,
];

// All types and fields in this module stay private. In particular there is no
// constructor taking an accepted child, bank, retired original or first-only
// completion, and no constructor for an intermediate state.
struct FutureLeaf<'bound, 'source, 'request> {
    source: &'bound GroupSourceBound<'request>,
    shape: OuterSourceShape,
    output: output::PreissuedOutput<'bound, 'request, 'request>,
    acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    support: Support<'request>,
}

struct FirstProducer<'bound, 'source, 'request> {
    ticket: PreissuedHashxOuter<'request>,
    leaf: FutureLeaf<'bound, 'source, 'request>,
}

struct LeafCompletion<'bound, 'source, 'request> {
    leaf: AcceptedLeaf<'bound, 'source, 'request>,
    originals: RetiredHashxOuterOriginals<'request>,
    support: Support<'request>,
}

// Actual retained outputs and prepared producers die before the bank and the
// additive enclosing caller reservation. Every payload has its own original
// backing claim as well: this outer claim accounts only inline/caller frames.
struct State<'group, 'bound, 'source, 'request> {
    accepted_leaves: [Option<AcceptedLeaf<'bound, 'source, 'request>>; LEAVES],
    accepted_parents: [Option<AcceptedParent<'bound, 'source, 'request>>; PARENTS],
    native_children: [Option<ReservedNativeChild<'request>>; NATIVE],
    first: Option<FirstProducer<'bound, 'source, 'request>>,
    future_leaves: [Option<FutureLeaf<'bound, 'source, 'request>>; LEAVES],
    future_parents: [Option<FutureHashxParent<'bound, 'source, 'request>>; PARENTS],
    ready_parents: [Option<PreissuedHashxParent<'bound, 'source, 'request>>; PARENTS],
    prepared_native: Option<PreparedNativeHashx<'request>>,
    pending_native: Option<PendingNativeHashx<'request>>,
    originals: Option<RetiredHashxOuterOriginals<'request>>,
    retained_support: [Option<Support<'request>>; OUTER],
    bank: Option<CompilerBank<'group, 'bound, 'source, 'request>>,
    source: &'bound ParentSourceBound<'source, 'request>,
    request: &'request ReservedShakeRequest,
    ledger: Ledger,
    report: ComponentReport,
    next: usize,
    #[cfg(test)]
    probe: Option<refusal::Probe>,
    // Last State field: all remaining outputs and compiler owners die first.
    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    interior: Option<interior_opening::PreissuedInteriorChildOpening<'bound, 'source, 'request>>,
}

struct Attempt<'group, 'bound, 'source, 'request> {
    state: State<'group, 'bound, 'source, 'request>,
    caller: Reservation,
}

enum Cause {
    Production(Error),
    Compiler(bank::Failure),
    #[cfg(test)]
    Injected(refusal::Probe),
}

impl From<Error> for Cause {
    fn from(error: Error) -> Self {
        Self::Production(error)
    }
}

impl From<bank::Failure> for Cause {
    fn from(error: bank::Failure) -> Self {
        Self::Compiler(error)
    }
}

// Keep actual bounded compiler failure/report storage alive through its last
// reporting use, before releasing this attempt's additive caller original.
struct Failure {
    cause: Cause,
    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    interior: Option<interior_opening::RetainedInteriorOpening>,
    caller: Reservation,
}

type AttemptResult<T> = core::result::Result<T, Cause>;

#[derive(Clone, Copy)]
struct ComponentReport {
    native_proofs: usize,
    leaf_proofs: usize,
    parent_proofs: usize,
    leaf_compilation: [Option<Summary>; LEAVES],
    leaf_compiler_ns: [u128; LEAVES],
    leaf_acceptance: [Option<LeafAcceptanceReport>; LEAVES],
    parent_compilation: [Option<LeafParentCompilationReport>; PARENTS],
    parent_acceptance: [Option<ParentAcceptanceReport>; PARENTS],
    elapsed_ns: u128,
    workflow_admitted: bool,
}

impl ComponentReport {
    fn empty() -> Self {
        Self {
            native_proofs: 0,
            leaf_proofs: 0,
            parent_proofs: 0,
            leaf_compilation: [None; LEAVES],
            leaf_compiler_ns: [0; LEAVES],
            leaf_acceptance: [None; LEAVES],
            parent_compilation: [None; PARENTS],
            parent_acceptance: [None; PARENTS],
            elapsed_ns: 0,
            workflow_admitted: false,
        }
    }
}

// The sole successful output remains private. It exposes no root/proof/key or
// runtime continuation conversion to transaction/full-request acceptance.
struct Component<'bound, 'source, 'request> {
    root: AcceptedParent<'bound, 'source, 'request>,
    originals: RetiredHashxOuterOriginals<'request>,
    retained_support: [Option<Support<'request>>; OUTER],
    report: ComponentReport,
    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    interior: Option<interior_opening::RetainedInteriorOpening>,
    caller: Reservation,
}

impl<'group, 'bound, 'source, 'request> Attempt<'group, 'bound, 'source, 'request> {
    fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        groups: [&'group GroupCompilePlan<'request>; LEAVES],
        ledger: &Ledger,
    ) -> Result<Self> {
        // The original caller precedes even the arrays/partial-constructor
        // frames. Its scope outlives every partial source, producer and bank.
        let caller = ledger
            .admit_phase(attempt_requirement()?)
            .map_err(|_| Error::Shape)?;
        let request = source.request.owner;
        source
            .check_original_request(request, ledger)
            .map_err(|_| Error::Authority)?;
        let bank = CompilerBank::reserve_before_native(source, groups, ledger)
            .map_err(|_| Error::Shape)?;
        let mut leaves = core::array::from_fn(|_| None);
        let mut parents = core::array::from_fn(|_| None);
        for (ordinal, group) in groups.iter().enumerate() {
            leaves[ordinal] = Some(FutureLeaf::reserve_before_native(
                source, group, ordinal, ledger,
            )?);
        }
        for (ordinal, destination) in parents.iter_mut().enumerate() {
            *destination = Some(FutureHashxParent::reserve_before_native(
                source, ordinal, request, ledger,
            )?);
        }
        // All nine output/acceptance/support owners and the entire compiler
        // bank already exist before A assigns any native PCS capacity.
        let pending = PendingNativeHashx::reserve_before_native(request, ledger)
            .and_then(PendingNativeHashx::with_outer_sequence)
            .map_err(|_| Error::Authority)?;
        Ok(Self {
            state: State {
                accepted_leaves: core::array::from_fn(|_| None),
                accepted_parents: core::array::from_fn(|_| None),
                native_children: core::array::from_fn(|_| None),
                first: None,
                future_leaves: leaves,
                future_parents: parents,
                ready_parents: core::array::from_fn(|_| None),
                prepared_native: None,
                pending_native: Some(pending),
                originals: None,
                retained_support: core::array::from_fn(|_| None),
                bank: Some(bank),
                source,
                request,
                ledger: ledger.clone(),
                report: ComponentReport::empty(),
                next: 0,
                #[cfg(test)]
                probe: None,
                #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
                interior: None,
            },
            caller,
        })
    }

    /// # Safety
    /// Preserve the same immutable process/exclusive physical-device guard
    /// from preflight through every actual native/outer session retirement,
    /// including returned errors and unwinding. No fallback or retry exists.
    unsafe fn run(mut self) -> core::result::Result<Component<'bound, 'source, 'request>, Failure> {
        let started = std::time::Instant::now();
        let attempted = unsafe { self.state.run() };
        match attempted {
            Err(cause) => {
                let Self { mut state, caller } = self;
                #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
                let interior = state.interior.take().map(
                    interior_opening::PreissuedInteriorChildOpening::into_retained,
                );
                drop(state);
                Err(Failure {
                    cause,
                    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
                    interior,
                    caller,
                })
            }
            Ok(()) => {
                self.state.report.elapsed_ns = started.elapsed().as_nanos();
                let Self { mut state, caller } = self;
                // State::run checked the whole fixed terminal state. These
                // moves cannot introduce a new error after dropping its bank.
                let root = state.accepted_parents[PARENTS - 1]
                    .take()
                    .expect("private complete HashX root");
                let originals = state.originals.take().expect("private actual retirement");
                let retained_support =
                    core::mem::replace(&mut state.retained_support, core::array::from_fn(|_| None));
                let report = state.report;
                #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
                let interior = state.interior.take().map(
                    interior_opening::PreissuedInteriorChildOpening::into_retained,
                );
                drop(state);
                Ok(Component {
                    root,
                    originals,
                    retained_support,
                    report,
                    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
                    interior,
                    caller,
                })
            }
        }
    }
}

impl<'group, 'bound, 'source, 'request> State<'group, 'bound, 'source, 'request> {
    unsafe fn prepare(&mut self) -> Result<()> {
        let pending = self.pending_native.take().ok_or(Error::Authority)?;
        let mut native = unsafe { pending.prepare() }.map_err(|_| Error::Runtime)?;
        let mut backends: [Option<PreissuedOuterBackend>; OUTER] = core::array::from_fn(|_| None);
        // A source refusal anywhere here precedes native zero. Every backend
        // is issued once against this same original native capacity.
        for (position, phase) in ORDER.iter().copied().enumerate() {
            backends[position] = Some(match phase {
                Phase::Leaf(ordinal) => self.future_leaves[ordinal]
                    .as_ref()
                    .ok_or(Error::Authority)?
                    .preissue_backend(&native)?,
                Phase::Parent(ordinal) => {
                    let future = self.future_parents[ordinal]
                        .take()
                        .ok_or(Error::Authority)?;
                    let (ready, backend) = future.complete_before_native(&mut native)?;
                    self.ready_parents[ordinal] = Some(ready);
                    backend
                }
            });
        }
        let first = backends[0].take().ok_or(Error::Authority)?;
        let successors = [
            backends[1].take().ok_or(Error::Authority)?,
            backends[2].take().ok_or(Error::Authority)?,
            backends[3].take().ok_or(Error::Authority)?,
            backends[4].take().ok_or(Error::Authority)?,
            backends[5].take().ok_or(Error::Authority)?,
            backends[6].take().ok_or(Error::Authority)?,
            backends[7].take().ok_or(Error::Authority)?,
            backends[8].take().ok_or(Error::Authority)?,
        ];
        let ticket = native
            .bind_outer_backend(first)
            .and_then(|ticket| ticket.with_successors(successors))
            .map_err(|_| Error::Authority)?;
        self.first = Some(FirstProducer {
            ticket,
            leaf: self.future_leaves[0].take().ok_or(Error::Authority)?,
        });
        self.prepared_native = Some(native);
        Ok(())
    }

    unsafe fn first(&mut self) -> AttemptResult<()> {
        if self.next != 0
            || self.originals.is_some()
            || self.native_children.iter().any(Option::is_some)
        {
            return Err(Error::Authority.into());
        }
        let native = self.prepared_native.take().ok_or(Error::Authority)?;
        let mut completed = unsafe {
            native.produce_for_outer(&self.first.as_ref().ok_or(Error::Authority)?.ticket)
        }
        .map_err(|_| Error::Proof)?;
        if completed.retained_native_count() != NATIVE {
            return Err(Error::Authority.into());
        }
        for (index, destination) in self.native_children.iter_mut().enumerate() {
            // First producer's pre-native report claim covers streaming each
            // original report. Emit it before the attachment consumes it.
            emit_receipt(completed.report(index).ok_or(Error::Report)?)?;
            let before = self.ledger.snapshot();
            *destination = Some(
                completed
                    .take_next_child(index, &self.ledger)
                    .map_err(|_| Error::Authority)?,
            );
            if self.ledger.snapshot() != before {
                return Err(Error::Authority.into());
            }
        }
        if completed.retained_native_count() != 0 {
            return Err(Error::Authority.into());
        }
        self.report.native_proofs = NATIVE;
        let bank = self.bank.take().ok_or(Error::Authority)?;
        let compile_started = std::time::Instant::now();
        let compiled = bank.compile_leaf(0, self.take_native_pair(0)?, &self.ledger)?;
        self.report.leaf_compiler_ns[0] = compile_started.elapsed().as_nanos();
        let FirstProducer { ticket, leaf } = self.first.take().ok_or(Error::Authority)?;
        let outer = ticket
            .finish_native(completed)
            .map_err(|_| Error::Authority)?;
        let node = &compiled.compiled().compiled;
        let prepared = unsafe { outer.bind(&node.program, &node.public, &node.witness) }
            .map_err(|_| Error::Shape)?;
        #[cfg(test)]
        self.return_refusal_if_selected(refusal::Probe::BeforeFirstStart)?;
        let completed = unsafe { leaf.produce(prepared, compiled.compiled()) }?;
        // A returned refusal here drops the genuine accepted completion before
        // the earlier-declared BankedLeaf. No compiler reclaim has occurred.
        #[cfg(test)]
        self.return_refusal_if_selected(refusal::Probe::AfterFirstProducer)?;
        self.accept_leaf(0, completed, compiled.compiled().summary)?;
        // Here the actual output/originals remain in State until Attempt's
        // terminal destruction, with their own full independent backing.
        #[cfg(test)]
        self.return_refusal_if_selected(refusal::Probe::AfterFirstAcceptance)?;
        // All registered Program aliases/captured borrows ended inside produce.
        // The bank checks exclusivity, destroys actual witness/Program/report
        // payloads and reunifies original categories without readmission.
        self.bank = Some(
            compiled
                .reclaim(&self.ledger)
                .map_err(|_| Error::Authority)?,
        );
        Ok(())
    }

    fn take_native_pair(
        &mut self,
        ordinal: usize,
    ) -> Result<[Option<ReservedNativeChild<'request>>; 2]> {
        if ordinal >= LEAVES {
            return Err(Error::Shape);
        }
        let first = 2 * ordinal;
        if self.native_children[first].is_none() || self.native_children[first + 1].is_none() {
            return Err(Error::Authority);
        }
        Ok([
            self.native_children[first].take(),
            self.native_children[first + 1].take(),
        ])
    }

    fn check_next(&self, phase: Phase) -> Result<()> {
        if self.next == 0
            || self.next >= OUTER
            || ORDER[self.next] != phase
            || self.retained_support[self.next].is_some()
        {
            return Err(Error::Authority);
        }
        self.source
            .check_original_request(self.request, &self.ledger)
            .map_err(|_| Error::Authority)?;
        let originals = self.originals.as_ref().ok_or(Error::Authority)?;
        originals
            .check(self.request, &self.ledger)
            .map_err(|_| Error::Authority)?;
        if originals.outer_step().map_err(|_| Error::Authority)? != STEPS[self.next - 1] {
            return Err(Error::Authority);
        }
        Ok(())
    }

    fn accept_leaf(
        &mut self,
        ordinal: usize,
        completed: LeafCompletion<'bound, 'source, 'request>,
        compilation: Summary,
    ) -> Result<()> {
        let accepted = completed.leaf.report();
        if self.next >= OUTER
            || ordinal >= LEAVES
            || ORDER[self.next] != Phase::Leaf(ordinal)
            || self.accepted_leaves[ordinal].is_some()
            || self.retained_support[self.next].is_some()
            || completed
                .originals
                .outer_step()
                .map_err(|_| Error::Authority)?
                != STEPS[self.next]
            || compilation.layout != ShakeWrapperLayout::PairedV1
            || compilation.ordinal != ordinal
            || accepted.leaf != ordinal
            || accepted.height != compilation.padded_rows
            || accepted.cpu_heights_admitted != 18
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
            || compilation.span.segment_count != 2
            || compilation.span.first_segment != 2 * ordinal
            || compilation.independent_native_verifications != 2
            || compilation.active_rows == 0
            || compilation.active_rows > compilation.padded_rows
            || !compilation.padded_rows.is_power_of_two()
            || compilation.padded_rows > MAX_ROWS
        {
            return Err(Error::Authority);
        }
        let LeafCompletion {
            leaf,
            originals,
            support,
        } = completed;
        self.report.leaf_compilation[ordinal] = Some(compilation);
        self.report.leaf_acceptance[ordinal] = Some(accepted);
        self.accepted_leaves[ordinal] = Some(leaf);
        self.originals = Some(originals);
        self.retained_support[self.next] = Some(support);
        self.report.leaf_proofs += 1;
        self.next += 1;
        Ok(())
    }

    unsafe fn leaf(&mut self, ordinal: usize) -> AttemptResult<()> {
        self.check_next(Phase::Leaf(ordinal))?;
        let bank = self.bank.take().ok_or(Error::Authority)?;
        let compile_started = std::time::Instant::now();
        let compiled = bank.compile_leaf(ordinal, self.take_native_pair(ordinal)?, &self.ledger)?;
        self.report.leaf_compiler_ns[ordinal] = compile_started.elapsed().as_nanos();
        let leaf = self.future_leaves[ordinal].take().ok_or(Error::Authority)?;
        leaf.check_compiled(compiled.compiled())?;
        let node = &compiled.compiled().compiled;
        let originals = self.originals.take().ok_or(Error::Authority)?;
        let prepared = unsafe {
            originals.bind_successor(STEPS[self.next], &node.program, &node.public, &node.witness)
        }
        .map_err(|_| Error::Shape)?;
        let completed = unsafe { leaf.produce(prepared, compiled.compiled()) }?;
        self.accept_leaf(ordinal, completed, compiled.compiled().summary)?;
        self.bank = Some(
            compiled
                .reclaim(&self.ledger)
                .map_err(|_| Error::Authority)?,
        );
        Ok(())
    }

    fn take_children(
        &mut self,
        ordinal: usize,
    ) -> Result<[AcceptedChild<'bound, 'source, 'request>; 2]> {
        // Only exact internally accepted edges are available; neither this
        // function nor the state constructor accepts a caller-supplied child.
        let (left, right) = match ordinal {
            0 => (
                AcceptedChild::Leaf(self.accepted_leaves[0].take().ok_or(Error::Authority)?),
                AcceptedChild::Leaf(self.accepted_leaves[1].take().ok_or(Error::Authority)?),
            ),
            1 => (
                AcceptedChild::Leaf(self.accepted_leaves[2].take().ok_or(Error::Authority)?),
                AcceptedChild::Leaf(self.accepted_leaves[3].take().ok_or(Error::Authority)?),
            ),
            2 => (
                AcceptedChild::Parent(self.accepted_parents[0].take().ok_or(Error::Authority)?),
                AcceptedChild::Parent(self.accepted_parents[1].take().ok_or(Error::Authority)?),
            ),
            3 => (
                AcceptedChild::Parent(self.accepted_parents[2].take().ok_or(Error::Authority)?),
                AcceptedChild::Leaf(self.accepted_leaves[4].take().ok_or(Error::Authority)?),
            ),
            _ => return Err(Error::Shape),
        };
        Ok([left, right])
    }

    unsafe fn parent(&mut self, ordinal: usize) -> AttemptResult<()> {
        self.check_next(Phase::Parent(ordinal))?;
        let [left, right] = self.take_children(ordinal)?;
        #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
        let mut left = left;
        #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
        interior_opening::probe_before_parent(self, ordinal, &mut left, &right)?;
        let bank = self.bank.take().ok_or(Error::Authority)?;
        let compiled = bank
            .compile_parent(ordinal, left, right, &self.ledger)
            .map_err(|_| Error::Shape)?;
        let producer = self.ready_parents[ordinal].take().ok_or(Error::Authority)?;
        let originals = self.originals.take().ok_or(Error::Authority)?;
        let completed = unsafe { producer.produce(originals, compiled.compiled()) }?;
        let accepted = completed.parent.report();
        if completed
            .originals
            .outer_step()
            .map_err(|_| Error::Authority)?
            != STEPS[self.next]
            || self.accepted_parents[ordinal].is_some()
            || accepted.parent != ordinal
            || accepted.height != compiled.compiled().report.padded_rows
            || accepted.cpu_heights_admitted != 18
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err(Error::Authority.into());
        }
        self.report.parent_compilation[ordinal] = Some(compiled.compiled().report);
        let AcceptedHashxParentCompletion {
            parent,
            originals,
            support,
        } = completed;
        self.report.parent_acceptance[ordinal] = Some(accepted);
        self.accepted_parents[ordinal] = Some(parent);
        self.originals = Some(originals);
        self.retained_support[self.next] = Some(support);
        self.report.parent_proofs += 1;
        self.next += 1;
        self.bank = Some(
            compiled
                .reclaim(&self.ledger)
                .map_err(|_| Error::Authority)?,
        );
        #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
        interior_opening::parent_completed(self, ordinal)?;
        Ok(())
    }

    unsafe fn run(&mut self) -> AttemptResult<()> {
        unsafe { self.prepare() }?;
        #[cfg(test)]
        self.return_refusal_if_selected(refusal::Probe::AfterPreissue)?;
        unsafe { self.first() }?;
        for phase in ORDER.into_iter().skip(1) {
            match phase {
                Phase::Leaf(ordinal) => unsafe { self.leaf(ordinal) }?,
                Phase::Parent(ordinal) => unsafe { self.parent(ordinal) }?,
            }
        }
        let root = self.report.parent_compilation[PARENTS - 1].ok_or(Error::Authority)?;
        if self.next != OUTER
            || root.first != 0
            || root.count != 122
            || root.level != 3
            || self.report.native_proofs != NATIVE
            || self.report.leaf_proofs != LEAVES
            || self.report.parent_proofs != PARENTS
            || self.bank.is_none()
            || self.first.is_some()
            || self.pending_native.is_some()
            || self.prepared_native.is_some()
            || self.native_children.iter().any(Option::is_some)
            || self.accepted_leaves.iter().any(Option::is_some)
            || self.accepted_parents[..PARENTS - 1]
                .iter()
                .any(Option::is_some)
            || self.accepted_parents[PARENTS - 1].is_none()
            || self.future_leaves.iter().any(Option::is_some)
            || self.future_parents.iter().any(Option::is_some)
            || self.ready_parents.iter().any(Option::is_some)
            || self.retained_support.iter().any(Option::is_none)
            || self.report.leaf_compilation.iter().any(Option::is_none)
            || self.report.leaf_acceptance.iter().any(Option::is_none)
            || self.report.parent_compilation.iter().any(Option::is_none)
            || self.report.parent_acceptance.iter().any(Option::is_none)
            || self
                .originals
                .as_ref()
                .ok_or(Error::Authority)?
                .outer_step()
                .map_err(|_| Error::Authority)?
                != HashxOuterStep::Parent3
        {
            return Err(Error::Authority.into());
        }
        #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
        interior_opening::require_completed(self)?;
        Ok(())
    }
}

impl<'bound, 'source, 'request> FutureLeaf<'bound, 'source, 'request> {
    fn reserve_before_native(
        parent: &'bound ParentSourceBound<'source, 'request>,
        group: &GroupCompilePlan<'request>,
        ordinal: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        let original = ledger
            .admit_phase(caller_requirement()?)
            .map_err(|_| Error::Shape)?;
        let request = parent.request.owner;
        parent
            .check_original_request(request, ledger)
            .map_err(|_| Error::Authority)?;
        let source = parent
            .request
            .sources
            .get(ordinal)
            .and_then(Option::as_ref)
            .ok_or(Error::Shape)?;
        if ordinal >= LEAVES
            || group.ordinal != ordinal
            || !source.is_for(group, ledger)
            || group.layout != ShakeWrapperLayout::PairedV1
            || group.span.segment_count != 2
            || group.span.first_segment != 2 * ordinal
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
        .map_err(|_| Error::Shape)?;
        let planning = PlanningLease::reserve(ledger).map_err(|_| Error::Shape)?;
        let metadata = ledger
            .admit_phase(metadata_requirement()?)
            .map_err(|_| Error::Shape)?;
        let reports = ledger
            .admit_phase(report_requirement()?)
            .map_err(|_| Error::Shape)?;
        let wrappers = ledger
            .admit_phase(wrapper_requirement()?)
            .map_err(|_| Error::Shape)?;
        let acceptance = parent
            .preissue_leaf_acceptance(ordinal, ledger)
            .map_err(|_| Error::Shape)?;
        let output = output::PreissuedOutput::reserve(source, group, request, ledger)
            .map_err(Error::Output)?;
        Ok(Self {
            source,
            shape,
            output,
            acceptance,
            support: Support {
                request,
                ledger: ledger.clone(),
                wrappers,
                reports,
                metadata,
                planning,
                original,
            },
        })
    }

    fn preissue_backend(
        &self,
        native: &PreparedNativeHashx<'request>,
    ) -> Result<PreissuedOuterBackend> {
        self.support.check(&self.support.ledger)?;
        native
            .check_outer_request(self.support.request, &self.support.ledger)
            .map_err(|_| Error::Authority)?;
        let capacity = native
            .outer_continuation_capacity()
            .map_err(|_| Error::Authority)?;
        if capacity.retained_tree_host_bytes != 8 << 30
            || capacity.startup.host < capacity.retained_tree_host_bytes
            || capacity.pcs.host == 0
            || capacity.pcs.host > 24 << 30
            || capacity.startup.device.checked_add(capacity.pcs.device) != Some(8 << 30)
        {
            return Err(Error::Authority);
        }
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, MAX_ROWS)
            .map_err(|_| Error::Runtime)?;
        OuterSourceEnvelope::inspect(self.shape, limits, capacity.pcs.host)
            .and_then(OuterSourceEnvelope::preissue)
            .map_err(|_| Error::Shape)
    }

    fn check_compiled(&self, compiled: &OwnedCompiledShake<'request>) -> Result<()> {
        self.support.check(&self.support.ledger)?;
        self.source
            .check_compiled(compiled, &self.support.ledger)
            .map_err(|_| Error::Shape)?;
        self.acceptance
            .check_compiled(compiled, self.support.request, &self.support.ledger)
            .map_err(|_| Error::Shape)
    }

    // One maintained body serves Leaf0 and every later paired leaf. Only the
    // private caller's binding differs; report/output/acceptance checks do not.
    unsafe fn produce<'compiled>(
        self,
        prepared: PreparedHashxOuter<'compiled, 'request>,
        compiled: &'compiled OwnedCompiledShake<'request>,
    ) -> Result<LeafCompletion<'bound, 'source, 'request>> {
        self.check_compiled(compiled)?;
        let Self {
            output,
            acceptance,
            support,
            ..
        } = self;
        let output = output
            .attach(compiled, &support.ledger)
            .map_err(Error::Output)?;
        let active = unsafe { prepared.start() }.map_err(|_| Error::Runtime)?;
        let attempted: Result<(
            output::RetainedNodeOutput<'request>,
            CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
        )> = (|| {
            let runtime_guard = active
                .session()
                .check_reserved_runtime(&support.ledger)
                .map_err(|_| Error::Runtime)?;
            let backend = active.backend();
            backend
                .check_execution_selection()
                .map_err(|_| Error::Runtime)?;
            let request = Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            };
            let node = &compiled.compiled;
            let (registered, report) =
                RegisteredProgram::new_with_cpu_identity_and_report(
                    MachineAir::from_shared_program(Arc::clone(&node.program)),
                    backend.host_budget_bytes(),
                    request,
                )
                .map_err(|_| Error::Setup)?;
            validate_report(&report.preprocessing, CoverageScope::Preprocessing)?;
            validate_report(&report.identity, CoverageScope::Operation)?;
            emit_receipt(&report.preprocessing)?;
            emit_receipt(&report.identity)?;
            let setup_ns = report.preprocessing.elapsed_ns;
            drop(report);
            let captured = acceptance
                .capture(compiled, &registered, &support.ledger)
                .map_err(|_| Error::Shape)?;
            let key = NodeKey {
                spec: node.spec.clone(),
                height: node.program.height(),
                cap: registered.preprocessing_cap().roots().to_vec(),
                verifier: Arc::new(registered.verifier()),
            };
            let (proof, report) = registered
                .into_prove_outer_with_request_and_report(backend, request)
                .map_err(|_| Error::Proof)?;
            validate_report(&report, CoverageScope::RegisteredProof)?;
            emit_receipt(&report)?;
            let prove_ns = report.elapsed_ns;
            drop(report);
            let output = output
                .verify_and_retain(
                    key,
                    NodeProof {
                        public: node.public.clone(),
                        proof,
                    },
                    setup_ns,
                    prove_ns,
                )
                .map_err(Error::Output)?;
            drop(runtime_guard);
            Ok((output, captured))
        })();
        // Every returned setup/proof/output error consumes the same active
        // session before propagation, matching the maintained standalone path.
        let before = support.ledger.snapshot();
        let originals = active.finish().map_err(|_| Error::Runtime)?;
        if support.ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        let (output, captured) = attempted?;
        if !output.belongs_to(&support.ledger) || !output.report().independent_verification_complete
        {
            return Err(Error::Authority);
        }
        let retirement = originals
            .check(support.request, &support.ledger)
            .map_err(|_| Error::Authority)?;
        let leaf = finish_source_acceptance(captured, output, retirement, &support.ledger)
            .map_err(|_| Error::Shape)?;
        Ok(LeafCompletion {
            leaf,
            originals,
            support,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod qualification;
