//! Source-derived simultaneous storage for independent registered verification.
//! Construction uses the empty trusted machine shape, not the prover's program.
//! The phase sum includes one already-owned, admitted native proof throughout.
//! Caller caches, registry ownership, stacks, callbacks, allocator/OS/driver
//! overhead and diagnostic I/O need separate enclosing worker reservations.

use super::{profile, verification_call, Config, ExecutionError, RegisteredVerifier};
use crate::block_v2::machine::{
    program::{Program, Row, MAX_PUBLIC_VALUES, PUBLICS_PER_ROW},
    symbolic::{verifier::Limits, LookupLayout},
};
use core::mem::size_of;
use p3_batch_stark::common::PreprocessedInstanceMeta;
use p3_lookup::Lookups;

/// A cap has at most 64 roots (2 KiB of digests) in this profile. Allow spare
/// capacity, but reject unbounded caller-owned backing storage before setup.
pub(crate) const CAP_LIMIT_BYTES: usize = 64 << 10;
/// Checked component ceiling: 192 MiB metadata workspace + 64 MiB proof
/// backing, plus bounded cap, shape and common-data containers. This is a
/// payload reservation, not a claim about complete process RSS.
pub(crate) const LIMIT_BYTES: usize = super::NATIVE_VERIFIER_COMPONENT_BYTES as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    pub(crate) cap_bytes: usize,
    pub(crate) shape_retained_bytes: usize,
    pub(crate) graph_workspace_bytes: usize,
    pub(crate) metadata_retained_bytes: usize,
    pub(crate) construction_peak_bytes: usize,
    pub(crate) verification_peak_bytes: usize,
    pub(crate) peak_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, ExecutionError> {
    a.checked_add(b).ok_or(ExecutionError::TooLarge)
}
fn bytes<T>(count: usize) -> Result<usize, ExecutionError> {
    count
        .checked_mul(size_of::<T>())
        .ok_or(ExecutionError::TooLarge)
}

impl Plan {
    pub(crate) fn new(
        publics: usize,
        height: usize,
        cap: &p3_batch_stark::Commitment<Config>,
        limits: Limits,
    ) -> Result<Self, ExecutionError> {
        Self::from_shape(publics, height, cap.roots().len(), cap.root_capacity(), limits)
    }

    /// Public metadata only; suitable before cap/shape/symbolic allocation.
    pub(crate) fn from_shape(
        publics: usize,
        height: usize,
        cap_roots: usize,
        cap_capacity: usize,
        limits: Limits,
    ) -> Result<Self, ExecutionError> {
        limits.validate().map_err(|_| ExecutionError::TooLarge)?;
        if publics > MAX_PUBLIC_VALUES {
            return Err(ExecutionError::TooLarge);
        }
        if !(8..=1 << 24).contains(&height) || !height.is_power_of_two() {
            return Err(ExecutionError::InvalidHeight);
        }
        let log_lde = height.ilog2() as usize + 1 + profile::LOG_BLOWUP;
        if cap_roots != 1 << log_lde.min(profile::CAP_HEIGHT) {
            return Err(ExecutionError::InvalidHeight);
        }
        let cap_bytes = bytes::<[super::Val; 4]>(cap_capacity)?;
        if cap_capacity < cap_roots || cap_bytes > CAP_LIMIT_BYTES {
            return Err(ExecutionError::TooLarge);
        }
        // ProgramBuilder(publics).finish(height) has zero operations and no
        // constant-folding calls: empty intern maps and CPU Folding allocate
        // nothing. Packing requests exact defined/reference/public-row buffers.
        // Padding changes only the height scalar; there is no height-sized Vec.
        let shape_retained_bytes = add(
            profile::verification::arc_bytes::<Program>(),
            add(
                bytes::<u32>(publics)?,
                bytes::<Row>(publics.div_ceil(PUBLICS_PER_ROW))?,
            )?,
        )?;
        // Counting the Arc even before packing drops its defined vector is
        // conservative; construction never needs more than their sum.
        let shape_construction = add(shape_retained_bytes, bytes::<bool>(publics)?)?;
        // common_from_prepared first stores one LookupLayout in a Vec, then
        // moves its lookup ownership into three exact-capacity vectors. It
        // neither replays the AIR nor clones the graph/cap.
        let common_vectors = add(
            bytes::<Option<PreprocessedInstanceMeta>>(1)?,
            add(bytes::<usize>(1)?, bytes::<Lookups<super::Val>>(1)?)?,
        )?;
        let common_construction = add(common_vectors, bytes::<LookupLayout>(1)?)?;
        let graph_workspace_bytes = limits.workspace();
        let metadata_retained_bytes = add(
            size_of::<RegisteredVerifier>(),
            add(
                cap_bytes,
                add(shape_retained_bytes, add(limits.retained, common_vectors)?)?,
            )?,
        )?;
        // The two symbolic recordings do not coexist. While deriving lookup
        // degree, the first normalized lookups can coexist with the second
        // recording and normalization. Packing overlaps only the old lookups
        // with its checked packing workspace, which includes its census.
        let setup_workspace = shape_construction
            .max(add(shape_retained_bytes, graph_workspace_bytes)?)
            .max(add(
                shape_retained_bytes,
                add(limits.retained, common_construction)?,
            )?);
        let construction_peak_bytes = add(
            verification_call::PROOF_LIMIT_BYTES,
            add(
                size_of::<RegisteredVerifier>(),
                add(cap_bytes, setup_workspace)?,
            )?,
        )?;
        let verification_peak_bytes = add(
            metadata_retained_bytes,
            add(
                verification_call::PROOF_LIMIT_BYTES,
                verification_call::TEMPORARY_LIMIT_BYTES,
            )?,
        )?;
        let peak_bytes = construction_peak_bytes.max(verification_peak_bytes);
        if peak_bytes > LIMIT_BYTES {
            return Err(ExecutionError::TooLarge);
        }
        Ok(Self {
            cap_bytes,
            shape_retained_bytes,
            graph_workspace_bytes,
            metadata_retained_bytes,
            construction_peak_bytes,
            verification_peak_bytes,
            peak_bytes,
        })
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
