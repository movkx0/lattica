//! Fail-closed source preflight for the exact active-policy HashX request.
//!
//! This owns only bounded scheduling/source metadata. In particular, even five
//! genuine leaf source bounds cannot become a complete-request dispatch permit:
//! the parent/compiler/verifier and transaction/final closure below is missing.
//! No proof, key, AIR, callback, runtime or numeric dispatch receipt is accepted.
use super::{
    source_shape::GroupSourceBound, EndpointContext, GroupCompilePlan, Ledger, Requirements,
    Reservation, ShakeWrapperLayout, ShakeWrapperSpan,
};
use crate::{
    execution::retained_resources::{Bytes, Category, Snapshot},
    graph_crypto::{RequestDescriptor, ReservedShakeRequest},
};
use core::{convert::Infallible, mem::size_of};

const LEAVES: usize = 5;
const PARENTS: usize = 4;
const TOTAL: u32 = 122;
const COUNTS: [usize; 10] = [16, 16, 16, 16, 16, 16, 16, 8, 1, 1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authority,
    Geometry,
    Order,
    Context,
    Source,
    Overflow,
}
type Result<T> = core::result::Result<T, Error>;

/// Scheduling metadata, never an observed/proven recursive height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Interval {
    first: u32,
    count: u32,
    level: u32,
}

impl Interval {
    fn end(self) -> Result<u32> {
        self.first.checked_add(self.count).ok_or(Error::Overflow)
    }

    fn merge(left: Self, right: Self) -> Result<Self> {
        if left.count == 0 || right.count == 0 || left.end()? != right.first || right.end()? > TOTAL
        {
            return Err(Error::Geometry);
        }
        Ok(Self {
            first: left.first,
            count: left.count.checked_add(right.count).ok_or(Error::Overflow)?,
            level: left
                .level
                .max(right.level)
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Leaf(usize),
    Parent(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Merge {
    left: Node,
    right: Node,
    interval: Interval,
}

/// Fixed carry slots reproduce RequestProver's push/finish order, including
/// the asymmetric final merge. No Vec, proof template or compiler is created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tree {
    spans: [ShakeWrapperSpan; LEAVES],
    leaves: [Interval; LEAVES],
    parents: [Option<Merge>; PARENTS],
    parent_count: usize,
    root: Option<Node>,
}

impl Tree {
    fn interval(&self, node: Node) -> Result<Interval> {
        match node {
            Node::Leaf(i) => self.leaves.get(i).copied().ok_or(Error::Geometry),
            Node::Parent(i) => self
                .parents
                .get(i)
                .and_then(|value| *value)
                .map(|value| value.interval)
                .ok_or(Error::Geometry),
        }
    }

    fn merge(&mut self, left: Node, right: Node) -> Result<Node> {
        let interval = Interval::merge(self.interval(left)?, self.interval(right)?)?;
        let slot = self
            .parents
            .get_mut(self.parent_count)
            .ok_or(Error::Geometry)?;
        if slot.is_some() {
            return Err(Error::Order);
        }
        *slot = Some(Merge {
            left,
            right,
            interval,
        });
        let result = Node::Parent(self.parent_count);
        self.parent_count += 1;
        Ok(result)
    }

    fn derive(spans: [ShakeWrapperSpan; LEAVES]) -> Result<Self> {
        let empty = Interval {
            first: 0,
            count: 0,
            level: 0,
        };
        let mut tree = Self {
            spans,
            leaves: [empty; LEAVES],
            parents: [None; PARENTS],
            parent_count: 0,
            root: None,
        };
        let mut next_segment = 0usize;
        let mut next_unit = 0usize;
        for (i, span) in spans.into_iter().enumerate() {
            if span.first_segment != next_segment
                || span.segment_count != 2
                || span.first_unit != next_unit
                || span.units == 0
            {
                return Err(Error::Geometry);
            }
            next_segment = next_segment
                .checked_add(span.segment_count)
                .ok_or(Error::Overflow)?;
            next_unit = next_unit.checked_add(span.units).ok_or(Error::Overflow)?;
            tree.leaves[i] = Interval {
                first: u32::try_from(span.first_unit).map_err(|_| Error::Overflow)?,
                count: u32::try_from(span.units).map_err(|_| Error::Overflow)?,
                level: 0,
            };
        }
        if next_segment != COUNTS.len() || next_unit != TOTAL as usize {
            return Err(Error::Geometry);
        }
        let mut slots = [None; 3];
        for i in 0..LEAVES {
            let mut value = Node::Leaf(i);
            let mut level = 0;
            loop {
                let slot = slots.get_mut(level).ok_or(Error::Geometry)?;
                match slot.take() {
                    None => {
                        *slot = Some(value);
                        break;
                    }
                    Some(left) => {
                        value = tree.merge(left, value)?;
                        level += 1;
                    }
                }
            }
        }
        let mut root = None;
        for left in slots.into_iter().flatten() {
            root = Some(match root {
                None => left,
                Some(right) => tree.merge(left, right)?,
            });
        }
        let root = root.ok_or(Error::Geometry)?;
        if tree.parent_count != PARENTS
            || tree.interval(root)?
                != (Interval {
                    first: 0,
                    count: TOTAL,
                    level: 3,
                })
        {
            return Err(Error::Geometry);
        }
        tree.root = Some(root);
        Ok(tree)
    }
}

/// This plan borrows already-admitted immutable input. Its allocation-free
/// caller frame must be charged by the enclosing worker before construction.
pub(crate) struct RequestClosurePlan<'request> {
    owner: &'request ReservedShakeRequest,
    context: EndpointContext,
}

pub(crate) struct ReservedRequestClosure<'request> {
    owner: &'request ReservedShakeRequest,
    context: EndpointContext,
    tree: Tree,
    // Original source-bound owners are destroyed before our enclosing claim.
    sources: [Option<GroupSourceBound<'request>>; LEAVES],
    next_source: usize,
    original: Reservation,
}

/// Pre-dispatch refusal preserves the complete incoming metadata reservation.
pub(crate) struct OpenRefusal {
    pub(crate) reason: Error,
    original: Reservation,
}

/// Complete owners survive a refused source handoff. No attempt has started.
pub(crate) struct SourceRefusal<'request> {
    pub(crate) reason: Error,
    source: GroupSourceBound<'request>,
    request: ReservedRequestClosure<'request>,
}

/// Precise missing integration bounds. Generic core shape planners already
/// exist; they do not include this request's binding, caller or phase closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissingBound {
    OriginalLeafSources,
    ParentVerifierAndBindingSource,
    IndependentParentVerifier,
    CorrelatedCompilerWorkspace,
    RetainedRecursiveOutputsAndKeys,
    TransactionAndFinalAggregationClosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RefusalReport {
    pub(crate) native_proofs_scheduled: usize,
    pub(crate) recursive_leaves_scheduled: usize,
    pub(crate) recursive_parents_scheduled: usize,
    pub(crate) retained_original_leaf_sources: usize,
    pub(crate) root_first: u32,
    pub(crate) root_count: u32,
    pub(crate) root_spec_level: u32,
    pub(crate) missing: [Option<MissingBound>; 6],
}

/// Cleanup-only owner. A numeric report, all leaf source bounds or a matching
/// tree cannot restore it into a compiler/runtime/native dispatch capability.
pub(crate) struct RefusedRequest<'request> {
    report: RefusalReport,
    request: ReservedRequestClosure<'request>,
}

// Explicit helper-frame inventories. These are counted in addition to each
// complete owner/Result frame below; no tail call, inlining or move elision is
// assumed. None is constructed and none authorizes an allocation.
#[allow(dead_code)]
struct TreeLoopFrames {
    span_iteration: core::iter::Enumerate<core::array::IntoIter<ShakeWrapperSpan, LEAVES>>,
    leaf_iteration: core::ops::Range<usize>,
    carry_iteration: core::iter::Flatten<core::array::IntoIter<Option<Node>, 3>>,
    next_segment: usize,
    next_unit: usize,
    index: usize,
    level: usize,
    value: Node,
    left: Node,
    right: Option<Node>,
    slot: *mut Option<Node>,
}

#[allow(dead_code)]
struct SourceLoopFrames {
    iteration: core::iter::Enumerate<
        core::iter::Zip<
            core::slice::Iter<'static, usize>,
            core::slice::Iter<'static, crate::graph_crypto::SegmentInfo>,
        >,
    >,
    segments: &'static [crate::graph_crypto::SegmentInfo],
    group: *mut ShakeWrapperSpan,
    segment: *const crate::graph_crypto::SegmentInfo,
    end: usize,
    index: usize,
    count: usize,
}

#[allow(dead_code)]
struct IdentityFrames {
    ledger: &'static Ledger,
    owner: &'static ReservedShakeRequest,
    plan: &'static GroupCompilePlan<'static>,
    original: &'static Reservation,
    required: Requirements,
    bytes: Bytes,
    allowance: crate::execution::retained_resources::WorkerAllowance,
    ordinal: usize,
    span: ShakeWrapperSpan,
    checked: Result<()>,
}

fn frame_bytes<T>(copies: usize) -> Result<usize> {
    size_of::<T>().checked_mul(copies).ok_or(Error::Overflow)
}

/// Fixed complete source/return/refusal/carry census, with no move elision
/// credit. All heap source-bound backing stays charged by its original owner.
fn metadata_requirement() -> Result<Requirements> {
    let parts = [
        frame_bytes::<RequestClosurePlan<'static>>(3)?,
        frame_bytes::<ReservedRequestClosure<'static>>(4)?,
        frame_bytes::<OpenRefusal>(3)?,
        frame_bytes::<core::result::Result<ReservedRequestClosure<'static>, OpenRefusal>>(3)?,
        frame_bytes::<SourceRefusal<'static>>(3)?,
        frame_bytes::<core::result::Result<ReservedRequestClosure<'static>, SourceRefusal<'static>>>(
            3,
        )?,
        frame_bytes::<RefusedRequest<'static>>(3)?,
        frame_bytes::<core::result::Result<Infallible, RefusedRequest<'static>>>(3)?,
        frame_bytes::<GroupSourceBound<'static>>(3)?,
        frame_bytes::<Tree>(4)?,
        frame_bytes::<Result<Tree>>(3)?,
        frame_bytes::<[ShakeWrapperSpan; LEAVES]>(4)?,
        frame_bytes::<[Option<Node>; 3]>(3)?,
        frame_bytes::<Interval>(12)?,
        frame_bytes::<Result<Interval>>(6)?,
        frame_bytes::<Merge>(6)?,
        frame_bytes::<Option<Node>>(12)?,
        frame_bytes::<Result<Node>>(6)?,
        frame_bytes::<EndpointContext>(4)?,
        frame_bytes::<RefusalReport>(4)?,
        frame_bytes::<[Option<MissingBound>; 6]>(3)?,
        frame_bytes::<Reservation>(6)?,
        frame_bytes::<Requirements>(6)?,
        frame_bytes::<Result<Requirements>>(3)?,
        frame_bytes::<Snapshot>(3)?,
        frame_bytes::<RequestDescriptor>(3)?,
        frame_bytes::<Error>(12)?,
        frame_bytes::<Result<()>>(6)?,
        frame_bytes::<TreeLoopFrames>(3)?,
        frame_bytes::<SourceLoopFrames>(3)?,
        frame_bytes::<IdentityFrames>(3)?,
        frame_bytes::<core::slice::Iter<'static, usize>>(3)?,
        frame_bytes::<core::result::Result<usize, Error>>(6)?,
        // The immutable exact count table and each checked-size helper's
        // input/output words are conservatively counted as separate frames.
        frame_bytes::<[usize; 10]>(6)?,
        frame_bytes::<(usize, usize, usize)>(12)?,
    ];
    let helper = core::mem::size_of_val(&parts)
        .checked_mul(3)
        .ok_or(Error::Overflow)?;
    let bytes = parts
        .iter()
        .try_fold(helper, |a, &b| a.checked_add(b).ok_or(Error::Overflow))?;
    Ok(Requirements::single(
        Category::RegisteredMetadata,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

impl<'request> RequestClosurePlan<'request> {
    pub(crate) fn new(owner: &'request ReservedShakeRequest, context: EndpointContext) -> Self {
        Self { owner, context }
    }

    pub(crate) fn requirements(&self) -> Result<Requirements> {
        metadata_requirement()
    }

    fn spans(&self) -> Result<[ShakeWrapperSpan; LEAVES]> {
        let request = self.owner.request();
        match request.descriptor() {
            RequestDescriptor::Shake(d) if d.input_len == 16_416 && d.output_len == 137 => {}
            _ => return Err(Error::Geometry),
        }
        let segments = request.segments();
        if segments.len() != COUNTS.len() {
            return Err(Error::Geometry);
        }
        let empty = ShakeWrapperSpan {
            first_segment: 0,
            segment_count: 0,
            first_unit: 0,
            units: 0,
        };
        let mut spans = [empty; LEAVES];
        let mut end = 0usize;
        for (index, (&count, segment)) in COUNTS.iter().zip(segments).enumerate() {
            if segment.first_unit != end
                || segment.units != count
                || segment.height != 4096 * count
                || segment.width != if count == 1 { 517 } else { 518 }
            {
                return Err(Error::Geometry);
            }
            let group = &mut spans[index / 2];
            if index % 2 == 0 {
                group.first_segment = index;
                group.first_unit = end;
            }
            group.segment_count += 1;
            group.units = group.units.checked_add(count).ok_or(Error::Overflow)?;
            end = end.checked_add(count).ok_or(Error::Overflow)?;
        }
        if end != TOTAL as usize {
            return Err(Error::Geometry);
        }
        Ok(spans)
    }

    pub(crate) fn open(
        self,
        original: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<ReservedRequestClosure<'request>, OpenRefusal> {
        let allowance = ledger.snapshot().allowance;
        if !self.owner.belongs_to(ledger)
            || !original.belongs_to(ledger)
            || !metadata_requirement().is_ok_and(|required| original.requirements() == required)
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device > 8 << 30
        {
            return Err(OpenRefusal {
                reason: Error::Authority,
                original,
            });
        }
        let tree = match self.spans().and_then(Tree::derive) {
            Ok(tree) => tree,
            Err(reason) => return Err(OpenRefusal { reason, original }),
        };
        Ok(ReservedRequestClosure {
            owner: self.owner,
            context: self.context,
            tree,
            sources: [None, None, None, None, None],
            next_source: 0,
            original,
        })
    }
}

impl<'request> ReservedRequestClosure<'request> {
    fn check_group(&self, plan: &GroupCompilePlan<'_>, ledger: &Ledger) -> Result<()> {
        if !self.owner.belongs_to(ledger)
            || !self.original.belongs_to(ledger)
            || !core::ptr::eq(self.owner.request(), plan.request)
            || !metadata_requirement()
                .is_ok_and(|required| self.original.requirements() == required)
        {
            return Err(Error::Authority);
        }
        if plan.context != self.context {
            return Err(Error::Context);
        }
        if plan.layout != ShakeWrapperLayout::PairedV1
            || plan.ordinal != self.next_source
            || self.tree.spans.get(self.next_source) != Some(&plan.span)
            || self
                .sources
                .get(self.next_source)
                .is_none_or(Option::is_some)
        {
            return Err(Error::Order);
        }
        Ok(())
    }

    pub(crate) fn retain_source(
        mut self,
        plan: &GroupCompilePlan<'_>,
        source: GroupSourceBound<'request>,
        ledger: &Ledger,
    ) -> core::result::Result<Self, SourceRefusal<'request>> {
        let checked = self.check_group(plan, ledger).and_then(|()| {
            if source.is_for(plan, ledger) {
                Ok(())
            } else {
                Err(Error::Source)
            }
        });
        if let Err(reason) = checked {
            return Err(SourceRefusal {
                reason,
                request: self,
                source,
            });
        }
        self.sources[self.next_source] = Some(source);
        self.next_source += 1;
        Ok(self)
    }

    /// The uninhabited success type makes the missing closure enforceable.
    /// This API cannot issue even a dormant proof/runtime/admission capability.
    pub(crate) fn require_complete(
        self,
    ) -> core::result::Result<Infallible, RefusedRequest<'request>> {
        let report = RefusalReport {
            native_proofs_scheduled: COUNTS.len(),
            recursive_leaves_scheduled: LEAVES,
            recursive_parents_scheduled: PARENTS,
            retained_original_leaf_sources: self.next_source,
            root_first: 0,
            root_count: TOTAL,
            root_spec_level: 3,
            missing: [
                (self.next_source != LEAVES).then_some(MissingBound::OriginalLeafSources),
                Some(MissingBound::ParentVerifierAndBindingSource),
                Some(MissingBound::IndependentParentVerifier),
                Some(MissingBound::CorrelatedCompilerWorkspace),
                Some(MissingBound::RetainedRecursiveOutputsAndKeys),
                Some(MissingBound::TransactionAndFinalAggregationClosure),
            ],
        };
        Err(RefusedRequest {
            request: self,
            report,
        })
    }
}

impl RefusedRequest<'_> {
    pub(crate) fn report(&self) -> RefusalReport {
        self.report
    }
}

#[cfg(test)]
mod tests;

mod source;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use source::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};

#[cfg(test)]
pub(super) use source::{authenticate_retired_leaf, AcceptedLeaf, AcceptedLeafCompletion, CapturedLeafAcceptance, CompiledLeafParent, EmittedParentChild, LeafAcceptanceReport, LeafParentCompilationReport, ParentChildEmission, PreissuedLeafAcceptance, PreissuedLeafParentCompiler};
#[cfg(test)]
pub(super) use source::Error as ParentCompileError;

#[cfg(test)]
pub(super) use source::{authenticate_retired_hashx_leaf, AcceptedHashxLeafCompletion};

#[cfg(test)]
pub(super) use source::{AcceptedChild, AcceptedParent, CapturedParentAcceptance, ParentAcceptanceReport, PreissuedParentAcceptance};
