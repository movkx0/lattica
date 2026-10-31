//! Pre-admitted immutable storage for one serial SHAKE Request.
//!
//! Input serialization and the borrowed source/graph already exist and need
//! separate enclosing admission. This constructor accounts only for its new
//! owned copy, partition/segment Vecs, and pinned Request::new diagnostics. It
//! neither authenticates a graph/manifest nor authorizes native proof dispatch.

use super::{Admission, Partition, Payload, Policy, Request, RequestDescriptor, SegmentInfo};
use crate::{
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    shake_air::{self, lane::batch::ShakeSegmentAir},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    UnsupportedProfile,
    Descriptor,
    Identity,
    Policy,
    NativeBudget,
    Overflow,
    WrongLedger,
    WrongReservation,
    Construction,
    ShapeChanged,
}
type Result<T> = core::result::Result<T, Error>;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Overflow)
}

// All original constructor error sources are fixed literals or Debug of the
// closed ShakeAir Error/TryFromIntError types. This list pins the largest
// possible text; one failure stops construction. Four times the longest text
// covers all old/new String requests under pinned RawVec geometric growth.
const fn error_text_bound() -> usize {
    let texts = [
        "crypto subrequest index",
        "crypto request index overflow",
        "crypto trace size overflow",
        "crypto memory estimate overflow",
        "smallest crypto segment exceeds estimated child memory budget",
        "TryFromIntError(())",
        "Length",
        "Segment",
        "Overflow",
    ];
    let mut longest = 8;
    let mut i = 0;
    while i < texts.len() {
        if texts[i].len() > longest {
            longest = texts[i].len();
        }
        i += 1;
    }
    longest
}
const ORIGINAL_ERROR_BYTES: usize = 4 * error_text_bound() + 2 * size_of::<String>();

/// Cumulative allocation requests, not observed capacity or a process RSS bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub(crate) payload_bytes: usize,
    pub(crate) partition_requested_bytes: usize,
    pub(crate) segment_requested_bytes: usize,
    pub(crate) original_error_bytes: usize,
    pub(crate) attempts: usize,
    pub(crate) selected_maximum: usize,
    pub(crate) selected_segments: usize,
    pub(crate) total_permutations: usize,
    pub(crate) requested_bytes: usize,
}

// Vec::push and Result<collect> use pinned RawVec growth. This sums all
// allocations/replacements, including minimum capacity and final spare backing.
fn growing<T>(count: usize) -> Result<usize> {
    if count == 0 {
        return Ok(0);
    }
    mul(mul(4, count.max(8))?, size_of::<T>())
}

fn range_segments(count: usize, maximum: usize) -> Result<usize> {
    add(count / maximum, (count % maximum).count_ones() as usize)
}

fn segment_count(descriptor: shake_air::Descriptor, maximum: usize) -> Result<usize> {
    let absorb = descriptor.input_len / shake_air::RATE;
    let squeeze = (descriptor.output_len / shake_air::RATE).saturating_sub(1);
    let tail = usize::from(
        descriptor.output_len > shake_air::RATE && descriptor.output_len % shake_air::RATE != 0,
    );
    add(
        add(
            range_segments(absorb, maximum)?,
            range_segments(squeeze, maximum)?,
        )?,
        1 + tail,
    )
}

fn largest_units(descriptor: shake_air::Descriptor, maximum: usize) -> usize {
    let full = (descriptor.input_len / shake_air::RATE)
        .max((descriptor.output_len / shake_air::RATE).saturating_sub(1));
    let capped = full.min(maximum).max(1);
    1usize << (usize::BITS - 1 - capped.leading_zeros())
}

fn estimated_native_peak(units: usize) -> Result<u64> {
    let width = if units == 1 {
        shake_air::lane::WIDTH
    } else {
        shake_air::lane::batch::WIDTH
    };
    let bytes = mul(mul(mul(units, shake_air::lane::HEIGHT)?, width)?, 8)?;
    let bytes = add(mul(bytes, 48)?, 512 << 20)?;
    u64::try_from(bytes).map_err(|_| Error::Overflow)
}

/// Exact immutable source borrow plus fixed metadata. There is no constructor
/// that attaches a token to an already allocated Request or caller-owned Vec.
pub(crate) struct ShakeRequestPlan<'source> {
    input: &'source [u8],
    profile: [u8; 32],
    operation: usize,
    subrequest: u32,
    descriptor: shake_air::Descriptor,
    policy: Policy,
    bounds: Bounds,
    requirements: Requirements,
}

impl<'source> ShakeRequestPlan<'source> {
    pub(crate) fn new(
        profile: [u8; 32],
        operation: usize,
        subrequest: u32,
        input: &'source [u8],
        output_len: usize,
        policy: Policy,
    ) -> Result<Self> {
        let (descriptor, bounds, requirements) =
            Self::source_geometry(operation, subrequest, input.len(), output_len, policy)?;
        Ok(Self {
            input,
            profile,
            operation,
            subrequest,
            descriptor,
            policy,
            bounds,
            requirements,
        })
    }

    /// Shared allocation-free geometry for the closed graph collection. This
    /// derives no owner or dispatch authority; construction still requires an
    /// exact immutable byte borrow and this constructor's same-ledger token.
    pub(super) fn source_geometry(
        operation: usize,
        subrequest: u32,
        input_len: usize,
        output_len: usize,
        policy: Policy,
    ) -> Result<(shake_air::Descriptor, Bounds, Requirements)> {
        Self::source_geometry_with_estimate_ceiling(
            operation,
            subrequest,
            input_len,
            output_len,
            policy,
            8u64 << 30,
        )
    }

    // The child-estimate ceiling reproduces the caller's existing partition
    // policy. It is not a worker/GPU allowance or permission to produce a proof.
    // Only the default path above and the exact opt-validator source profile
    // in active_policy may select it; no public numeric-ceiling API exists.
    fn source_geometry_with_estimate_ceiling(
        operation: usize,
        subrequest: u32,
        input_len: usize,
        output_len: usize,
        policy: Policy,
        estimate_ceiling: u64,
    ) -> Result<(shake_air::Descriptor, Bounds, Requirements)> {
        if !cfg!(all(not(debug_assertions), target_arch = "x86_64"))
            || size_of::<usize>() != 8
            || size_of::<Vec<u8>>() != 24
        {
            return Err(Error::UnsupportedProfile);
        }
        if input_len > u32::MAX as usize || output_len > u32::MAX as usize {
            return Err(Error::Descriptor);
        }
        if subrequest > 1
            || u32::try_from(operation)
                .ok()
                .and_then(|n| n.checked_mul(2))
                .and_then(|n| n.checked_add(subrequest))
                .is_none()
        {
            return Err(Error::Identity);
        }
        if [policy.maximum_aes_blocks, policy.maximum_shake_permutations]
            .into_iter()
            .any(|n| !n.is_power_of_two() || n > 64)
            || policy.child_memory_budget_bytes == 0
            || policy.child_memory_budget_bytes > estimate_ceiling
        {
            return Err(Error::Policy);
        }
        if estimated_native_peak(1)? > policy.child_memory_budget_bytes {
            return Err(Error::NativeBudget);
        }
        let descriptor = shake_air::Descriptor {
            input_len,
            output_len,
        };
        let total_permutations = descriptor.permutations().map_err(|_| Error::Overflow)?;
        let mut maximum = if policy.admission == Admission::ValidatedLocal {
            policy.maximum_shake_permutations.min(8)
        } else {
            policy.maximum_shake_permutations
        };
        let mut partition_requested_bytes = 0;
        let mut segment_requested_bytes = 0;
        let mut attempts = 0;
        let selected_segments;
        loop {
            let count = segment_count(descriptor, maximum)?;
            if count == 0 || count > total_permutations {
                return Err(Error::Descriptor);
            }
            attempts += 1;
            partition_requested_bytes = add(
                partition_requested_bytes,
                growing::<ShakeSegmentAir>(count)?,
            )?;
            segment_requested_bytes = add(segment_requested_bytes, growing::<SegmentInfo>(count)?)?;
            if estimated_native_peak(largest_units(descriptor, maximum))?
                <= policy.child_memory_budget_bytes
            {
                selected_segments = count;
                break;
            }
            if maximum == 1 {
                return Err(Error::NativeBudget);
            }
            maximum /= 2;
        }
        // Charge fixed construction/ownership bookkeeping conservatively even
        // where it lives on the stack. No header or observed capacity is used
        // to grant extra worker storage after construction.
        let headers = add(size_of::<Self>(), size_of::<ReservedShakeRequest>())?;
        let metadata = add(
            add(
                add(partition_requested_bytes, segment_requested_bytes)?,
                ORIGINAL_ERROR_BYTES,
            )?,
            headers,
        )?;
        let mut requirements = Requirements::single(
            Category::CompilerInputs,
            Bytes {
                host: input_len as u64,
                device: 0,
            },
        );
        requirements
            .add(
                Category::RegisteredMetadata,
                Bytes {
                    host: u64::try_from(metadata).map_err(|_| Error::Overflow)?,
                    device: 0,
                },
            )
            .map_err(|_| Error::Overflow)?;
        let bounds = Bounds {
            payload_bytes: input_len,
            partition_requested_bytes,
            segment_requested_bytes,
            original_error_bytes: ORIGINAL_ERROR_BYTES,
            attempts,
            selected_maximum: maximum,
            selected_segments,
            total_permutations,
            requested_bytes: usize::try_from(
                requirements.total().map_err(|_| Error::Overflow)?.host,
            )
            .map_err(|_| Error::Overflow)?,
        };
        Ok((descriptor, bounds, requirements))
    }

    pub(crate) fn requirements(&self) -> Requirements {
        self.requirements
    }
    pub(crate) fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// Validate the exact same-ledger token before copying the input or invoking
    /// the unchanged source constructor. Previous partition attempts and their
    /// old/new Vec buffers remain included in this fixed cumulative allowance.
    pub(crate) fn construct(
        self,
        reservation: Reservation,
        ledger: &Ledger,
    ) -> Result<ReservedShakeRequest> {
        if !reservation.belongs_to(ledger) {
            return Err(Error::WrongLedger);
        }
        let allowance = ledger.snapshot().allowance;
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device > 8u64 << 30
            || reservation.requirements() != self.requirements
        {
            return Err(Error::WrongReservation);
        }
        let payload = Payload::Shake(self.input.to_vec());
        let request = Request::new(
            self.profile,
            self.operation,
            self.subrequest,
            RequestDescriptor::Shake(self.descriptor),
            payload,
            self.policy,
        )
        .map_err(|error| {
            // The original bounded String dies while all source storage is
            // still reserved; only this inline code can escape construction.
            debug_assert!(error.0.len() <= error_text_bound());
            drop(error);
            Error::Construction
        })?;
        let Partition::Shake(partition) = &request.partition else {
            return Err(Error::ShapeChanged);
        };
        if request.segments.len() != self.bounds.selected_segments
            || partition.segments().len() != self.bounds.selected_segments
            || partition.descriptor() != self.descriptor
            || request.units() != self.bounds.total_permutations
            || request.maximum_segment_units()
                != largest_units(self.descriptor, self.bounds.selected_maximum)
        {
            return Err(Error::ShapeChanged);
        }
        Ok(ReservedShakeRequest {
            request,
            bounds: self.bounds,
            reservation,
        })
    }
}

/// The full Request is destroyed before its linear storage reservation.
/// Its shared borrow keeps the token alive through native/compiler owners and
/// actual synchronous phase cleanup. No Clone, mutable borrow or raw extraction.
pub(crate) struct ReservedShakeRequest {
    request: Request,
    bounds: Bounds,
    reservation: Reservation,
}
impl ReservedShakeRequest {
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }
    pub(crate) fn bounds(&self) -> Bounds {
        self.bounds
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.reservation.belongs_to(ledger)
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;

mod active_policy;
