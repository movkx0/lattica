//! Bounded CPU registry approval for sequential intake and session startup.
//! This accounts for requested heap payload, not allocator/runtime/stack costs.
//! The caller retains registry/input owners in its separate shared reservation.

use super::*;
use crate::block_v2::machine::{
    program::{Program, Row, PUBLICS_PER_ROW},
    symbolic::verifier::{self, Limits},
};
use core::mem::size_of;

// This trusted empty MachineAir has the same symbolic shape at every admitted
// height. Every recorder, normalizer and packer checks its quota before requests.
const LIMITS: Limits = Limits {
    recording: 4 << 20,
    normalization: 4 << 20,
    packing: 4 << 20,
    retained: 4 << 20,
};
const DIAGNOSTIC_BYTES: usize = 1024 + size_of::<String>();
// Two four-round external vectors and one 22-round internal vector.
const HASH_REQUEST_BYTES: usize = (2 * 4 * 8 + 22) * size_of::<Val>();
pub(super) const PREFIX_WORDS: usize = 64;

// A portable coarse payload ceiling for startup admission. Each symbolic
// phase already enforces byte quotas. The fixed empty shape is far smaller
// than this ceiling; the assertion includes Arc counters/alignment and all
// exact public-index, row and temporary defined-bit allocations. No trace is
// allocated by padding. Allocator/runtime/stack costs remain separate.
const SHAPE_STORAGE_BYTES: usize = 64 << 10;
const SHAPE_REQUEST_UPPER: usize = size_of::<Program>()
    + 2 * size_of::<usize>()
    + core::mem::align_of::<Program>()
    + PUBLIC_VALUES * size_of::<u32>()
    + PUBLIC_VALUES.div_ceil(PUBLICS_PER_ROW) * size_of::<Row>()
    + PUBLIC_VALUES * size_of::<bool>();
const FINGERPRINT_PHASE_BYTES: usize =
    LIMITS.retained + LIMITS.normalization + fingerprint::bounded::HOST_BYTES + HASH_REQUEST_BYTES;
pub(crate) const INITIAL_STORAGE_BYTES: usize =
    SHAPE_STORAGE_BYTES + FINGERPRINT_PHASE_BYTES + DIAGNOSTIC_BYTES;
const _: () = {
    assert!(SHAPE_REQUEST_UPPER <= SHAPE_STORAGE_BYTES);
    assert!(LIMITS.recording + 2 * LIMITS.normalization <= FINGERPRINT_PHASE_BYTES);
    assert!(LIMITS.normalization + LIMITS.packing <= FINGERPRINT_PHASE_BYTES);
    assert!(LIMITS.retained + LIMITS.recording + LIMITS.normalization <= FINGERPRINT_PHASE_BYTES);
    assert!(
        (2 * PREFIX_WORDS + 12 * (1 << profile::CAP_HEIGHT) * 4) * size_of::<u64>()
            + HASH_REQUEST_BYTES
            <= FINGERPRINT_PHASE_BYTES
    );
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
pub(crate) struct Plan {
    pub shape_retained_bytes: usize,
    pub graph_workspace_bytes: usize,
    pub fingerprint_peak_bytes: usize,
    pub peak_bytes: usize,
    pub cumulative_requested_bytes: usize,
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b).ok_or("registry setup storage overflow")
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
impl Plan {
    pub(crate) fn new() -> Result<Self, &'static str> {
        // Empty ProgramBuilder: exact public indices/public rows and temporary
        // defined bits; padding changes a scalar, never a height-sized vector.
        let shape_retained_bytes = add(
            profile::verification::arc_bytes::<Program>(),
            add(
                PUBLIC_VALUES * size_of::<u32>(),
                PUBLIC_VALUES.div_ceil(PUBLICS_PER_ROW) * size_of::<Row>(),
            )?,
        )?;
        let shape_construction = add(shape_retained_bytes, PUBLIC_VALUES * size_of::<bool>())?;
        let graph_workspace_bytes = LIMITS.workspace().max(add(
            LIMITS.retained,
            add(LIMITS.recording, LIMITS.normalization)?,
        )?);
        // Final normalized constraints and packed lookups survive encoding.
        // The fingerprint envelope includes both memo tables, encoded output,
        // root arrays and a fixed traversal/object allowance. Its output lives
        // through hashing, so include the permutation's requested backing too.
        let fingerprint_peak_bytes = add(
            add(LIMITS.retained, LIMITS.normalization)?,
            add(fingerprint::bounded::HOST_BYTES, HASH_REQUEST_BYTES)?,
        )?;
        // Prefix realloc can overlap the old allocation. Exact reservation
        // precedes appending at most 12 admitted caps (64 four-field roots each).
        // The 3/5/6-key families share this conservative 12-key envelope.
        let fields_requests = (2 * PREFIX_WORDS + 12 * (1 << profile::CAP_HEIGHT) * 4)
            .checked_mul(size_of::<u64>())
            .ok_or("registry setup field storage overflow")?;
        let workspace = graph_workspace_bytes
            .max(fingerprint_peak_bytes)
            .max(add(fields_requests, HASH_REQUEST_BYTES)?);
        let peak_bytes = add(
            DIAGNOSTIC_BYTES,
            shape_construction.max(add(shape_retained_bytes, workspace)?),
        )?;
        // First lookup pass, degree pass, packing, final ordered constraints,
        // fingerprint encoding, prefix/caps and two sequential hash calls.
        // Each graph quota counts cumulative requests; no live-peak comparison
        // is used for the independent allocation observer in tests.
        let mut cumulative_requested_bytes = add(DIAGNOSTIC_BYTES, shape_construction)?;
        for component in [
            LIMITS.recording,
            LIMITS.normalization,
            LIMITS.recording,
            LIMITS.normalization,
            LIMITS.packing,
            LIMITS.recording,
            LIMITS.normalization,
            fingerprint::bounded::HOST_BYTES,
            fields_requests,
            2 * HASH_REQUEST_BYTES,
        ] {
            cumulative_requested_bytes = add(cumulative_requested_bytes, component)?;
        }
        Ok(Self {
            shape_retained_bytes,
            graph_workspace_bytes,
            fingerprint_peak_bytes,
            peak_bytes,
            cumulative_requested_bytes,
        })
    }
}

pub(crate) fn profile_id<const N: usize>(
    height: usize,
    caps: &Caps<N>,
) -> Result<[u8; 32], CompileError> {
    profile_id_with_limits(height, caps, LIMITS, fingerprint::bounded::HOST_BYTES)
}

fn profile_id_with_limits<const N: usize>(
    height: usize,
    caps: &Caps<N>,
    limits: Limits,
    fingerprint_bytes: usize,
) -> Result<[u8; 32], CompileError> {
    // Reject unsupported geometry before any symbolic allocation.
    if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
        return Err(CompileError::Shape("registered height"));
    }
    check_caps(caps)?;
    let air = shape(height)?;
    let prepared = verifier::prepare_registry(&air, limits)?;
    let analysis = analysis::analyze_prepared(&air, &prepared)
        .map_err(|_| CompileError::Shape("registered AIR geometry"))?;
    let air_id = {
        let constraints = &prepared.constraints;
        let encoded = fingerprint::bounded::encode(
            &constraints.base,
            &constraints.extension,
            &constraints.order,
            fingerprint_bytes,
        )
        .map_err(|_| CompileError::Shape("registry fingerprint storage"))?;
        commitment::hash_fields(AIR_DOMAIN, &encoded)
            .map_err(|_| CompileError::Shape("registry fingerprint hash"))?
    };
    drop(prepared);
    let mut fields = registry_fields(height, &air, &analysis, air_id);
    extend_registry_kind(&mut fields, N);
    let cap_words = N * (1 << profile::CAP_HEIGHT) * 4;
    fields
        .try_reserve_exact(cap_words)
        .map_err(|_| CompileError::Shape("registry fields allocation"))?;
    fields.extend(
        caps.iter()
            .flatten()
            .flatten()
            .map(|x| x.as_canonical_u64()),
    );
    let digest = commitment::hash_fields(REGISTRY_DOMAIN, &fields)
        .map_err(|_| CompileError::Shape("registry hash"))?;
    let mut out = [0; 32];
    for (chunk, value) in out.chunks_exact_mut(8).zip(digest) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

#[cfg(all(test, feature = "stream"))]
mod tests;
