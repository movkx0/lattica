//! Admitted exhaustive registered-verifier source closure for the four HashX
//! parents. This returns counts/metadata only, never a program/key/dispatch.
//! Independent numerical verification and complete phase ownership stay open.
use super::{
    metadata_requirement as request_requirement, Interval, Node, ReservedRequestClosure, LEAVES,
    PARENTS,
};
use crate::{
    component_tree::{owned_shake::MAX_ROWS, HEADER},
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation, Snapshot},
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ConstructionLimits, MAX_WIRES},
        verifier::{
            batch::shape::{
                self, OperationCounts, PlanningStorage, RegisteredChildShape,
                VerifierHeightEnvelope,
            },
            CompileError,
        },
    },
    profile,
};

mod capture;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use capture::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};
mod framing;
#[cfg(test)]
pub(in crate::component_tree::owned_shake) use capture::{
    authenticate_retired_hashx_leaf, authenticate_retired_leaf, AcceptedChild,
    AcceptedHashxLeafCompletion, AcceptedLeaf, AcceptedLeafCompletion, AcceptedParent,
    CapturedLeafAcceptance, CapturedParentAcceptance, CompiledLeafParent, EmittedParentChild,
    LeafAcceptanceReport, LeafParentCompilationReport, ParentAcceptanceReport, ParentChildEmission,
    PreissuedLeafAcceptance, PreissuedLeafParentCompiler, PreissuedParentAcceptance,
};
pub(super) use capture::{CapturedLeafCap, PreissuedLeafCap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::component_tree::owned_shake) enum Error {
    Authority,
    MissingLeafSources,
    Source,
    Overflow,
    Capacity,
    Planner,
}
type Result<T> = core::result::Result<T, Error>;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn times(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
fn construction() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: super::super::PROGRAM_BYTES,
        max_wires: MAX_WIRES,
        max_input_values: super::super::INPUT_VALUES,
    }
}
fn shape(height: usize) -> Result<RegisteredChildShape> {
    if !(8..=MAX_ROWS).contains(&height) || !height.is_power_of_two() {
        return Err(Error::Source);
    }
    Ok(RegisteredChildShape {
        public_values: HEADER + 8,
        height,
        preprocessing_cap_roots: 1
            << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT),
    })
}
fn requirement(category: Category, bytes: usize) -> Result<Requirements> {
    Ok(Requirements::single(
        category,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| Error::Overflow)?,
            device: 0,
        },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ParentGeometry {
    pub(super) operations: OperationCounts,
    pub(super) active_rows_upper_bound: usize,
    pub(super) padded_rows_upper_bound: usize,
    pub(super) wires_upper_bound: usize,
    pub(super) input_values_upper_bound: usize,
    pub(super) selection_hint_words_upper_bound: usize,
}

impl ParentGeometry {
    fn from_envelope(envelope: &VerifierHeightEnvelope) -> Result<Self> {
        if envelope.public_values != HEADER + 8
            || envelope.maximum_child_height != MAX_ROWS
            || envelope.heights_enumerated != MAX_ROWS.ilog2() as usize - 2
        {
            return Err(Error::Source);
        }
        let binding = framing::operations();
        let operations = envelope
            .operations
            .with_overhead(envelope.operations)
            .and_then(|ops| ops.with_overhead(binding))
            .map_err(|_| Error::Overflow)?;
        // Each framing scalar instruction adds at most one wire; equalities
        // add none. Both cores have separate fresh proof/public inputs. Public
        // wire offset renaming and shared constant/hash interning add no work.
        let wires = add(
            HEADER + 8,
            add(times(2, envelope.wire_upper_bound)?, binding.scalar)?,
        )?;
        let inputs = times(2, envelope.input_values_upper_bound)?;
        // Framing emits only fixed scalar equalities and no SelectHint. The
        // two independent registered-verifier cores contribute their complete
        // opaque-cap hint entry/bit backing, maximized over all18 heights.
        let hints = times(2, envelope.selection_hint_words_upper_bound)?;
        let active = operations
            .active_rows(HEADER + 8)
            .map_err(|_| Error::Overflow)?;
        let padded = operations
            .padded_rows(HEADER + 8)
            .map_err(|_| Error::Overflow)?;
        if padded > MAX_ROWS || wires > MAX_WIRES || inputs > super::super::INPUT_VALUES {
            return Err(Error::Capacity);
        }
        Ok(Self {
            operations,
            active_rows_upper_bound: active,
            padded_rows_upper_bound: padded,
            wires_upper_bound: wires,
            input_values_upper_bound: inputs,
            selection_hint_words_upper_bound: hints,
        })
    }
}

pub(super) struct ParentSourcePlan<'source, 'request> {
    request: &'source ReservedRequestClosure<'request>,
    storage: PlanningStorage,
    temporary: Requirements,
    metadata: Requirements,
    whole: Requirements,
}

/// Retains the actual original five leaf-source owners via its request borrow.
/// The one finite envelope covers all child heights from8 through the unchanged
/// row ceiling, so every parent can consume an earlier admitted parent source.
pub(super) struct ParentSourceBound<'source, 'request> {
    request: &'source ReservedRequestClosure<'request>,
    envelope: VerifierHeightEnvelope,
    geometry: ParentGeometry,
    parents: [Interval; PARENTS],
    metadata: Reservation,
}

fn metadata_requirement() -> Result<Requirements> {
    let parts = [
        times(3, size_of::<ParentSourceBound<'static, 'static>>())?,
        times(3, size_of::<Result<ParentSourceBound<'static, 'static>>>())?,
        times(3, size_of::<ParentGeometry>())?,
        times(3, size_of::<VerifierHeightEnvelope>())?,
        times(3, size_of::<Reservation>())?,
        times(3, size_of::<[Interval; PARENTS]>())?,
    ];
    let bytes = parts.into_iter().try_fold(0, add)?;
    requirement(Category::RegisteredMetadata, bytes)
}

fn caller_bytes() -> Result<usize> {
    let parts = [
        times(4, size_of::<ParentSourcePlan<'static, 'static>>())?,
        times(3, size_of::<Result<ParentSourcePlan<'static, 'static>>>())?,
        times(3, size_of::<VerifierHeightEnvelope>())?,
        times(
            3,
            size_of::<core::result::Result<VerifierHeightEnvelope, CompileError>>(),
        )?,
        times(3, size_of::<PlanningStorage>())?,
        times(3, size_of::<Result<PlanningStorage>>())?,
        times(
            3,
            size_of::<core::result::Result<PlanningStorage, CompileError>>(),
        )?,
        times(3, size_of::<RegisteredChildShape>())?,
        times(3, size_of::<Result<RegisteredChildShape>>())?,
        times(3, size_of::<ConstructionLimits>())?,
        times(3, size_of::<ParentGeometry>())?,
        times(3, size_of::<Result<ParentGeometry>>())?,
        times(3, size_of::<[Interval; PARENTS]>())?,
        times(3, size_of::<OperationCounts>())?,
        times(3, size_of::<Snapshot>())?,
        times(6, size_of::<Requirements>())?,
        times(3, size_of::<Reservation>())?,
        times(3, size_of::<Result<Requirements>>())?,
        times(6, size_of::<Result<usize>>())?,
        times(3, size_of::<core::ops::RangeInclusive<u32>>())?,
        times(
            3,
            size_of::<core::iter::Enumerate<core::slice::Iter<'static, Option<super::Merge>>>>(),
        )?,
        times(
            3,
            size_of::<
                core::iter::Flatten<
                    core::slice::Iter<
                        'static,
                        Option<super::super::source_shape::GroupSourceBound<'static>>,
                    >,
                >,
            >(),
        )?,
        times(6, size_of::<(usize, usize, usize)>())?,
        times(
            3,
            size_of::<(&Ledger, &ReservedRequestClosure<'_>, &Reservation)>(),
        )?,
        times(3, size_of::<core::array::IntoIter<usize, 6>>())?,
        times(3, size_of::<core::array::IntoIter<Node, 2>>())?,
    ];
    let helper = add(
        times(3, core::mem::size_of_val(&parts))?,
        times(3, size_of::<core::slice::Iter<'static, usize>>())?,
    )?;
    parts.iter().try_fold(helper, |a, &b| add(a, b))
}

fn request_is_original(request: &ReservedRequestClosure<'_>, ledger: &Ledger) -> bool {
    let allowance = ledger.snapshot().allowance;
    request.owner.belongs_to(ledger)
        && request.original.belongs_to(ledger)
        && request_requirement().is_ok_and(|required| request.original.requirements() == required)
        && crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
        && allowance.device <= 8 << 30
}

impl<'source, 'request> ParentSourcePlan<'source, 'request> {
    pub(super) fn new(
        request: &'source ReservedRequestClosure<'request>,
        ledger: &Ledger,
    ) -> Result<Self> {
        if !request_is_original(request, ledger) {
            return Err(Error::Authority);
        }
        if request.next_source != LEAVES || request.sources.iter().any(Option::is_none) {
            return Err(Error::MissingLeafSources);
        }
        for source in request.sources.iter().flatten() {
            shape(source.geometry().padded_rows_upper_bound)?;
        }
        // Universal original row ceiling: no observed actual output can admit
        // a parent later and no monotonicity in log(height) is assumed.
        let storage = PlanningStorage::for_children(0, &[shape(MAX_ROWS)?], construction())
            .map_err(|_| Error::Source)?;
        let temporary = requirement(
            Category::PhaseScratch,
            add(storage.total_requested_bytes, caller_bytes()?)?,
        )?;
        let metadata = metadata_requirement()?;
        let mut whole = temporary;
        whole
            .add(
                Category::RegisteredMetadata,
                metadata.get(Category::RegisteredMetadata),
            )
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            request,
            storage,
            temporary,
            metadata,
            whole,
        })
    }

    pub(super) fn requirements(&self) -> Requirements {
        self.whole
    }

    pub(super) fn inspect(
        self,
        mut original: Reservation,
        ledger: &Ledger,
    ) -> Result<ParentSourceBound<'source, 'request>> {
        if !request_is_original(self.request, ledger)
            || !original.belongs_to(ledger)
            || original.requirements() != self.whole
        {
            return Err(Error::Authority);
        }
        let metadata = original
            .split(self.metadata)
            .map_err(|_| Error::Authority)?;
        let envelope = shape::verifier_height_envelope(
            HEADER + 8,
            MAX_ROWS,
            construction(),
            self.storage.auxiliary_peak_bytes,
        )
        .map_err(|_| Error::Planner)?;
        if envelope.planning_storage != self.storage {
            return Err(Error::Source);
        }
        let geometry = ParentGeometry::from_envelope(&envelope)?;
        let empty = Interval {
            first: 0,
            count: 0,
            level: 0,
        };
        let mut parents = [empty; PARENTS];
        for (i, parent) in self.request.tree.parents.iter().enumerate() {
            let parent = parent.ok_or(Error::Source)?;
            for child in [parent.left, parent.right] {
                let height = match child {
                    Node::Leaf(index) => {
                        self.request
                            .sources
                            .get(index)
                            .and_then(Option::as_ref)
                            .ok_or(Error::Source)?
                            .geometry()
                            .padded_rows_upper_bound
                    }
                    Node::Parent(index) if index < i => geometry.padded_rows_upper_bound,
                    Node::Parent(_) => return Err(Error::Source),
                };
                shape(height)?;
            }
            parents[i] = parent.interval;
        }
        if original.requirements() != self.temporary {
            return Err(Error::Authority);
        }
        // The core planner destroys every invalid template/symbolic/builder
        // payload before returning. Only numeric counts/metadata survive.
        drop(original);
        Ok(ParentSourceBound {
            request: self.request,
            envelope,
            geometry,
            parents,
            metadata,
        })
    }
}

impl ParentSourceBound<'_, '_> {
    pub(super) fn geometry(&self) -> ParentGeometry {
        self.geometry
    }
    pub(super) fn is_for(&self, request: &ReservedRequestClosure<'_>, ledger: &Ledger) -> bool {
        core::ptr::eq(self.request, request)
            && request_is_original(request, ledger)
            && self.metadata.belongs_to(ledger)
            && metadata_requirement().is_ok_and(|required| self.metadata.requirements() == required)
    }
}

#[cfg(test)]
mod tests;
