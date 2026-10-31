//! Closed singleton continuation using original pre-native claims throughout.
use super::*;
use crate::{
    component_tree::owned_shake::{source_shape::GroupSourceBound, GroupCompilePlan},
    execution::retained_resources::Requirements,
};
use lattica_prover_p3::block_v2::{
    machine::{OuterSourceEnvelope, OuterSourceShape, PreissuedOuterBackend},
    native_gpu::owned_shake::RetiredNativeReservations,
};

type Result<T> = core::result::Result<T, Error>;

mod outer_continuation;

fn report_requirement() -> Result<Requirements> {
    let host = fixed_producer_report_host_bytes()?;
    Ok(Requirements::single(
        Category::Report,
        Bytes {
            host: host as u64,
            device: 0,
        },
    ))
}

fn metadata_requirement() -> Result<Requirements> {
    let mut host =
        OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| Error::Shape)?;
    for part in [
        2 * size_of::<FutureOuter<'static, 'static, 'static>>(),
        2 * size_of::<ReadyOuter<'static, 'static, 'static>>(),
        2 * size_of::<Continuation<'static, 'static, 'static>>(),
        2 * size_of::<Result<ReadyOuter<'static, 'static, 'static>>>(),
        2 * size_of::<Result<Continuation<'static, 'static, 'static>>>(),
        2 * size_of::<PreissuedOuterBackend>(),
        4 * size_of::<Reservation>(),
        4 * size_of::<Requirements>(),
        outer_continuation::additional_host_bytes()?,
    ] {
        host = host.checked_add(part).ok_or(Error::Shape)?;
    }
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: host as u64,
            device: 0,
        },
    ))
}

pub(in crate::component_tree::owned_shake) struct FutureOuter<'source, 'owner, 'request> {
    source: &'source GroupSourceBound<'request>,
    request: &'owner ReservedShakeRequest,
    output: output::PreissuedOutput<'source, 'owner, 'request>,
    ledger: Ledger,
    wrappers: Reservation,
    reports: Reservation,
    metadata: Reservation,
    planning: PlanningLease,
}

impl<'source, 'owner, 'request> FutureOuter<'source, 'owner, 'request> {
    /// Call before constructing the native phase, so all these owners reduce
    /// the real native PCS assignment from the start.
    pub(in crate::component_tree::owned_shake) fn reserve_before_native(
        source: &'source GroupSourceBound<'request>,
        group: &GroupCompilePlan<'request>,
        request: &'owner ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self> {
        if !source.is_for(group, ledger) || !request.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let planning = PlanningLease::reserve(ledger).map_err(|_| Error::Shape)?;
        let metadata = ledger
            .admit_phase(metadata_requirement()?)
            .map_err(|_| Error::Shape)?;
        let reports = ledger
            .admit_phase(report_requirement()?)
            .map_err(|_| Error::Report)?;
        let wrappers = reserve_ocl_wrappers(ledger)?;
        let output = output::PreissuedOutput::reserve(source, group, request, ledger)
            .map_err(Error::Output)?;
        Ok(Self {
            source,
            request,
            output,
            ledger: ledger.clone(),
            wrappers,
            reports,
            metadata,
            planning,
        })
    }

    /// Numeric capacities declare feasibility only. The corresponding intact
    /// original sealed startup/PCS tokens are mandatory at finish_native.
    /// This runs after native admission but before its first GPU attempt.
    pub(in crate::component_tree::owned_shake) fn complete_before_native(
        self,
        original_startup: Bytes,
        original_pcs: Bytes,
        tree_host_bytes: u64,
    ) -> Result<ReadyOuter<'source, 'owner, 'request>> {
        if tree_host_bytes != 8 << 30
            || original_startup.host < tree_host_bytes
            || original_pcs.host == 0
            || original_pcs.host > 24 << 30
            || original_startup.device.checked_add(original_pcs.device) != Some(8 << 30)
            || !self.metadata.belongs_to(&self.ledger)
            || self.metadata.requirements() != metadata_requirement()?
        {
            return Err(Error::Authority);
        }
        let geometry = self.source.geometry();
        let shape = OuterSourceShape::owned_shake(
            geometry.operations,
            geometry.wires_upper_bound,
            geometry.input_values,
            geometry.selection_hint_words_upper_bound,
        )
        .map_err(|_| Error::Shape)?;
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, MAX_ROWS)
            .map_err(|_| Error::Runtime)?;
        let backend = OuterSourceEnvelope::inspect(shape, limits, original_pcs.host)
            .and_then(OuterSourceEnvelope::preissue)
            .map_err(|_| Error::Shape)?;
        Ok(ReadyOuter {
            future: self,
            backend,
            original_startup,
            original_pcs,
        })
    }
}

pub(in crate::component_tree::owned_shake) struct ReadyOuter<'source, 'owner, 'request> {
    future: FutureOuter<'source, 'owner, 'request>,
    backend: PreissuedOuterBackend,
    original_startup: Bytes,
    original_pcs: Bytes,
}

impl<'owner, 'request> ReadyOuter<'_, 'owner, 'request> {
    /// # Safety
    /// The coordinator must preserve the same immutable/exclusive host profile
    /// through restored outer startup, proving and exact runtime retirement.
    pub(in crate::component_tree::owned_shake) unsafe fn finish_native<'compiled>(
        self,
        compiled: &'compiled OwnedCompiledShake<'request>,
        originals: RetiredNativeReservations,
    ) -> Result<Continuation<'compiled, 'owner, 'request>> {
        let Self {
            future,
            backend,
            original_startup,
            original_pcs,
        } = self;
        let FutureOuter {
            source,
            request,
            output,
            ledger,
            wrappers,
            reports,
            metadata,
            planning,
        } = future;
        source
            .check_compiled(compiled, &ledger)
            .map_err(|_| Error::Shape)?;
        if !originals.belongs_to(&ledger)
            || !planning.belongs_to(&ledger)
            || !wrappers.belongs_to(&ledger)
            || !reports.belongs_to(&ledger)
            || !metadata.belongs_to(&ledger)
            || reports.requirements() != report_requirement()?
            || metadata.requirements() != metadata_requirement()?
            || wrappers.requirements()
                != Requirements::single(
                    Category::PhaseScratch,
                    Bytes {
                        host: FixedOuterOclStorage::fixed()
                            .map_err(|_| Error::Shape)?
                            .required_host_bytes() as u64,
                        device: 0,
                    },
                )
        {
            return Err(Error::Authority);
        }
        let (mut runtime, native_wrappers, pcs) = match PendingRuntime::restore_outer_host_v1(
            originals,
            &ledger,
            Limits {
                host_bytes: 32 << 30,
                device_bytes: 8 << 30,
                max_rows: MAX_ROWS,
            },
        ) {
            Ok(originals) => originals,
            Err(_) => return Err(Error::Runtime),
        };
        let footprint = backend.footprint();
        if runtime.reserved_bytes() != original_startup
            || !runtime.belongs_to(&ledger)
            || runtime.reserved_tree_host_bytes() != 8 << 30
            || !native_wrappers.belongs_to(&ledger)
            || !pcs.belongs_to(&ledger)
            || pcs.requirements() != Requirements::single(Category::PhaseScratch, original_pcs)
            || footprint.backend_scope_host_bytes.checked_sub(8 << 30) != Some(original_pcs.host)
            || footprint
                .complete_device_phase_ceiling
                .checked_sub(original_startup.device)
                != Some(original_pcs.device)
        {
            return Err(Error::Authority);
        }
        let output = output.attach(compiled, &ledger).map_err(Error::Output)?;
        // SAFETY: retained original startup/selection claim and caller guard.
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        let node = &compiled.compiled;
        let backend = backend
            .bind(&node.program, &node.public, &node.witness)
            .map_err(|_| Error::Shape)?;
        drop(preflight);
        Ok(Continuation {
            producer: PreparedOuter {
                compiled,
                request,
                output,
                backend,
                runtime,
                ledger,
                backend_token: pcs,
                wrappers,
                reports,
                planning,
            },
            native_wrappers,
            metadata,
        })
    }
}

pub(in crate::component_tree::owned_shake) struct Continuation<'compiled, 'owner, 'request> {
    producer: PreparedOuter<'compiled, 'owner, 'request>,
    native_wrappers: Reservation,
    metadata: Reservation,
}

impl<'owner> Continuation<'_, 'owner, '_> {
    /// # Safety
    /// Inherits the unchanged immutable/exclusive process contract through the
    /// actual restored runtime's retirement. There is no fallback or retry.
    pub(in crate::component_tree::owned_shake) unsafe fn produce(
        self,
    ) -> Result<output::RetainedNodeOutput<'owner>> {
        let Self {
            producer,
            native_wrappers,
            metadata,
        } = self;
        // SAFETY: same exact closed producer, using original claims throughout.
        let result = unsafe { producer.produce_reported() };
        drop(native_wrappers);
        drop(metadata);
        result
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, not(debug_assertions)))]
mod sequence;

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use outer_continuation::{RetiredLeafAttempt, RetiredOuterOriginals};

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod hashx_leaf;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use hashx_leaf::{FutureHashxLeaf, PreissuedHashxLeaf, PreparedHashxLeaf, RetiredHashxLeafAttempt, RetiredHashxLeafOriginals};
