//! Fixed-source preparation ownership for an already owned SHAKE request.
//!
//! This owner grants no dispatch authority. Its request borrow retains the
//! original raw bytes and native partition without copying or charging them
//! again. The preparation claim stays live through recording, normalization,
//! configuration and PCS; device/output/runtime owners remain separate.
use crate::{
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    graph_crypto::{Payload, Request, RequestDescriptor, ReservedShakeRequest},
    shake_air::{self, lane::batch::ShakeSegmentAir},
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::native_gpu::{
    shake_preparation::ShakePreparationPlan, shake_recording, ShakeTraceSpec,
};
use p3_air::BaseAir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Request,
    Shape,
    Overflow,
    Census,
    WrongLedger,
    WrongReservation,
    Recording,
}
type Result<T> = core::result::Result<T, Error>;

/// Immutable public-source planning only. No AIR callback, entropy, driver,
/// configuration, trace or proof operation occurs during construction.
pub(crate) struct NativePreparationPlan<'request> {
    owner: &'request ReservedShakeRequest,
    index: usize,
    air: &'request ShakeSegmentAir,
    input: &'request [u8],
    census: ShakePreparationPlan,
    requirements: Requirements,
}

fn descriptor(air: &ShakeSegmentAir) -> shake_air::Descriptor {
    match air {
        ShakeSegmentAir::Single(air) => air.descriptor,
        ShakeSegmentAir::Batch(air) => air.descriptor(),
    }
}

impl<'request> NativePreparationPlan<'request> {
    pub(crate) fn new(owner: &'request ReservedShakeRequest, index: usize) -> Result<Self> {
        let request = owner.request();
        let RequestDescriptor::Shake(expected) = request.descriptor() else {
            return Err(Error::Request);
        };
        let Payload::Shake(input) = &request.payload else {
            return Err(Error::Request);
        };
        let partition = request.shake_partition().ok_or(Error::Request)?;
        let bounds = owner.bounds();
        if input.len() != expected.input_len
            || input.len() != bounds.payload_bytes
            || input.capacity() > bounds.payload_bytes
            || partition.descriptor() != expected
            || partition.segments().len() != bounds.selected_segments
            || request.segments().len() != bounds.selected_segments
            || expected.permutations().map_err(|_| Error::Shape)? != bounds.total_permutations
        {
            return Err(Error::Shape);
        }
        // Although the original constructor seals its partition, recheck exact
        // coverage and source metadata here rather than trusting an index or a
        // caller-supplied shape. These getters do not allocate or evaluate AIR.
        let mut next = 0usize;
        for (air, info) in partition.segments().iter().zip(request.segments()) {
            let first = air.first_permutation();
            let count = air.permutations();
            let raw = air
                .height()
                .checked_mul(air.width())
                .and_then(|n| n.checked_mul(size_of::<u64>()))
                .ok_or(Error::Overflow)?;
            if descriptor(air) != expected
                || first != next
                || count == 0
                || info.first_unit != first
                || info.units != count
                || info.width != air.width()
                || info.height != air.height()
                || info.raw_trace_bytes != raw as u64
            {
                return Err(Error::Shape);
            }
            next = next.checked_add(count).ok_or(Error::Overflow)?;
        }
        if next != bounds.total_permutations {
            return Err(Error::Shape);
        }
        let air = partition.segments().get(index).ok_or(Error::Request)?;
        let spec = ShakeTraceSpec {
            input_len: expected.input_len,
            output_len: expected.output_len,
            first_permutation: air.first_permutation(),
            permutations: air.permutations(),
        };
        let census = match air {
            ShakeSegmentAir::Single(_) => ShakePreparationPlan::singleton(spec),
            ShakeSegmentAir::Batch(_) => ShakePreparationPlan::batch(spec),
        }
        .map_err(|_| Error::Census)?;
        let geometry = census.geometry();
        if geometry.rows() != air.height()
            || geometry.width() != air.width()
            || geometry.public_values() != air.num_public_values()
            || geometry.periodic_columns() != air.num_periodic_columns()
        {
            return Err(Error::Shape);
        }
        let symbolic = census
            .host()
            .prepared_partition_bytes()
            .map_err(|_| Error::Census)?;
        let other = census
            .host()
            .required_host_bytes()
            .checked_sub(symbolic)
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .and_then(|n| n.checked_add(size_of::<PendingNativePreparation<'_>>()))
            .and_then(|n| n.checked_add(shake_recording::additional_host_bytes()))
            .ok_or(Error::Overflow)?;
        let mut requirements = Requirements::single(
            Category::SymbolicCompiler,
            Bytes {
                host: u64::try_from(symbolic).map_err(|_| Error::Overflow)?,
                device: 0,
            },
        );
        requirements
            .add(
                Category::PhaseScratch,
                Bytes {
                    host: u64::try_from(other).map_err(|_| Error::Overflow)?,
                    device: 0,
                },
            )
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            owner,
            index,
            air,
            input,
            census,
            requirements,
        })
    }

    pub(crate) fn requirements(&self) -> Requirements {
        self.requirements
    }

    pub(crate) fn census(&self) -> ShakePreparationPlan {
        self.census
    }

    pub(crate) fn is_for(&self, owner: &ReservedShakeRequest, index: usize) -> bool {
        core::ptr::eq(self.owner, owner)
            && core::ptr::eq(self.owner.request(), owner.request())
            && self.index == index
    }

    /// Consume an exact original token split from enclosing workflow admission.
    /// No numeric budget or detached Request can construct the retained owner.
    pub(crate) fn claim_for(
        self,
        owner: &ReservedShakeRequest,
        index: usize,
        reservation: Reservation,
        ledger: &Ledger,
    ) -> Result<PendingNativePreparation<'request>> {
        if !self.is_for(owner, index) {
            return Err(Error::Request);
        }
        if !owner.belongs_to(ledger) || !reservation.belongs_to(ledger) {
            return Err(Error::WrongLedger);
        }
        let allowance = ledger.snapshot().allowance;
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device > 8u64 << 30
            || reservation.requirements() != self.requirements
        {
            return Err(Error::WrongReservation);
        }
        Ok(PendingNativePreparation {
            plan: self,
            reservation,
        })
    }
}

/// Neither Clone nor dispatch authority. The original reservation drops last;
/// all source and future prepared-data borrows keep it live until cleanup.
pub(crate) struct PendingNativePreparation<'request> {
    plan: NativePreparationPlan<'request>,
    reservation: Reservation,
}

impl PendingNativePreparation<'_> {
    pub(crate) fn is_for(
        &self,
        owner: &ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> bool {
        self.plan.is_for(owner, index)
            && owner.belongs_to(ledger)
            && self.reservation.belongs_to(ledger)
            && self.reservation.requirements() == self.plan.requirements
    }

    pub(crate) fn request(&self) -> &Request {
        self.plan.owner.request()
    }

    pub(crate) fn index(&self) -> usize {
        self.plan.index
    }

    pub(crate) fn air(&self) -> &ShakeSegmentAir {
        self.plan.air
    }

    pub(crate) fn input(&self) -> &[u8] {
        self.plan.input
    }

    pub(crate) fn census(&self) -> ShakePreparationPlan {
        self.plan.census
    }

    pub(crate) fn reservation(&self) -> &Reservation {
        &self.reservation
    }
}

#[cfg(test)]
mod tests;

mod recording;

mod production;
pub(crate) use production::{
    FutureNativeSingleton, NativeCompletionError, NativeSuccessorError, OuterContinuationCapacity,
    PreparedNativeSingleton, PreparedNativeSingletonAttachment, ReadyNativeSingleton,
    VerifiedNativeSingleton, VerifiedNativeSingletonWithOriginals,
};

pub(super) use production::NativeSingletonChild;

pub(super) use production::NativeSegmentChild;
pub(crate) use production::{
    ActiveHashxOuter, CompletedNativeHashx, HashxOuterStep, PendingNativeHashx,
    PreissuedHashxOuter, PreparedHashxOuter, PreparedNativeHashx, ProjectedHashxQuota,
    RetiredHashxOuter, RetiredHashxOuterOriginals,
};
