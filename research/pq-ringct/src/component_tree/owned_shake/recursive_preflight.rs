//! Closed CPU/full-storage lower-bound inspection of an owned SHAKE wrapper.
//!
//! This test-only prerequisite cannot register, allocate a trace, prove, or
//! issue admission. A fitting partial bound remains incomplete. Native fixture
//! production and wrapper compilation precede this inspection; this is not a
//! transaction-wide pre-dispatch check. See recursive_preflight/BOUNDS.md.

use super::{Category, Ledger, OwnedCompiledShake, PhaseReportOwner, HEADER, MAX_ROWS};
use core::mem::size_of;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{
            Val, EXT_LANES, LANES, MAX_PUBLIC_VALUES, MAX_WIRES, OPCODE_BITS, PUBLICS_PER_ROW,
        },
        WIDTH,
    },
    profile,
};
use p3_field::BasedVectorSpace;

const PUBLIC_VALUES: usize = 46;
const MAX_DEGREE: usize = 8;
const LOG_QUOTIENT_CHUNKS: usize = 3;
const INCLUDED_MMCS_TREES: u64 = 2;
const DIGEST_ELEMENTS: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    UnsupportedProfile,
    Authority,
    Geometry,
    Overflow,
}

fn selected_profile() -> Result<(), Error> {
    // The isolated research manifest maps opencl to core/gpu. Only this pinned
    // CPU feature selection is covered; compact/device storage is not modeled.
    if !cfg!(feature = "recursive-wide")
        || cfg!(feature = "opencl")
        || LANES != 23
        || WIDTH != 94
        || OPCODE_BITS != 3
        || EXT_LANES != 7
        || PUBLICS_PER_ROW != 32
        || MAX_PUBLIC_VALUES != 64
        || MAX_WIRES != 1 << 26
        || HEADER + 8 != PUBLIC_VALUES
        || size_of::<Val>() != 8
        || <profile::Challenge as BasedVectorSpace<Val>>::DIMENSION != 3
        || profile::LOG_BLOWUP != 4
        || profile::NUM_RANDOM_CODEWORDS != 4
        || profile::CAP_HEIGHT != 6
        || profile::NUM_QUERIES != 128
        || profile::QUERY_POW_BITS != 16
        || profile::CHALLENGE_FIELD_BITS != 191
        || profile::HASH_COLLISION_BITS != 127
        || profile::NODE_CODEC_REVISION != 2
        || profile::MAX_TRANSACTIONS != 64
    {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

// Source-order greedy same-bus packing. Each lane emits A/B/D reads with
// degree-three multiplicity, then a degree-one write; tuple degree is one.
// Public tuples have degree zero and degree-three multiplicity. For tuple
// degree sum S, LogUp's fraction pin is max(S+1, max(count_i+S-tuple_i)).
fn packed_lookups() -> usize {
    let mut groups = 1;
    let mut sum = 0;
    let mut numerator = 0;
    for index in 0..4 * LANES + PUBLIC_VALUES {
        let tuple = usize::from(index < 4 * LANES);
        let count = if index < 4 * LANES && index % 4 == 3 {
            1
        } else {
            3
        };
        let next_sum = sum + tuple;
        let next_numerator = (numerator + tuple).max(count + sum);
        if (next_sum + 1).max(next_numerator) > MAX_DEGREE {
            groups += 1;
            sum = tuple;
            numerator = count;
        } else {
            sum = next_sum;
            numerator = next_numerator;
        }
    }
    groups
}

fn storage_bytes(lde_rows: u64, columns: u64) -> Result<(u64, u64, u64), Error> {
    let lde = lde_rows
        .checked_mul(columns)
        .and_then(|n| n.checked_mul(size_of::<Val>() as u64))
        .ok_or(Error::Overflow)?;
    // MerkleTree retains every binary digest layer, including its root. Cap
    // selection does not discard layers in this pinned full-storage backend.
    let trees = lde_rows
        .checked_mul(2)
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| n.checked_mul(DIGEST_ELEMENTS))
        .and_then(|n| n.checked_mul(size_of::<Val>() as u64))
        .and_then(|n| n.checked_mul(INCLUDED_MMCS_TREES))
        .ok_or(Error::Overflow)?;
    Ok((lde, trees, lde.checked_add(trees).ok_or(Error::Overflow)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Geometry {
    pub(super) height: usize,
    pub(super) main_width: usize,
    pub(super) preprocessed_width: usize,
    pub(super) packed_lookups: usize,
    pub(super) permutation_width_base: usize,
    pub(super) quotient_chunks: usize,
    pub(super) lde_rows: u64,
    pub(super) lde_columns: usize,
    pub(super) retained_lde_bytes: u64,
    pub(super) included_mmcs_trees: u64,
    pub(super) retained_tree_bytes: u64,
    pub(super) partial_lower_bound_bytes: u64,
}

impl Geometry {
    fn for_program_shape(height: usize, wires: usize, publics: usize) -> Result<Self, Error> {
        selected_profile()?;
        if !(8..=MAX_ROWS).contains(&height)
            || !height.is_power_of_two()
            || wires > MAX_WIRES
            || publics != PUBLIC_VALUES
        {
            return Err(Error::Geometry);
        }
        let packed_lookups = packed_lookups();
        let permutation_width_base = (packed_lookups + 1) * 3;
        let preprocessed_width = (OPCODE_BITS + 5) * LANES + 2 * EXT_LANES + 2;
        let quotient_chunks = 1 << (LOG_QUOTIENT_CHUNKS + 1);
        let random = profile::NUM_RANDOM_CODEWORDS;
        let lde_columns = WIDTH
            + random
            + preprocessed_width
            + permutation_width_base
            + random
            + quotient_chunks * (3 + random)
            + 3
            + random;
        let lde_rows = (height as u64)
            .checked_mul(2 << profile::LOG_BLOWUP)
            .ok_or(Error::Overflow)?;
        let (retained_lde_bytes, retained_tree_bytes, partial_lower_bound_bytes) =
            storage_bytes(lde_rows, lde_columns as u64)?;
        Ok(Self {
            height,
            main_width: WIDTH,
            preprocessed_width,
            packed_lookups,
            permutation_width_base,
            quotient_chunks,
            lde_rows,
            lde_columns,
            retained_lde_bytes,
            included_mmcs_trees: INCLUDED_MMCS_TREES,
            retained_tree_bytes,
            partial_lower_bound_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    RefusedUnderExistingLedgerCharges,
    IncompleteFullPhaseBound,
}

impl Decision {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RefusedUnderExistingLedgerCharges => "partial_bound_exceeds_remaining_ledger",
            Self::IncompleteFullPhaseBound => "incomplete_full_phase_bound",
        }
    }
}

/// Fixed snapshot evidence, never an admission token or a dispatch capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) geometry: Geometry,
    pub(super) charged_program_host_bytes: u64,
    pub(super) charged_input_host_bytes: u64,
    pub(super) charged_report_host_bytes: u64,
    pub(super) charged_worker_host_bytes: u64,
    pub(super) worker_host_allowance: u64,
    pub(super) remaining_worker_host_bytes: u64,
    pub(super) decision: Decision,
}

/// Borrows the exact immutable compiled owner and its ledger. No caller geometry,
/// allowance, raw program, proof, or reservation is accepted or returned.
pub(super) struct Plan<'scope, 'request> {
    output: &'scope OwnedCompiledShake<'request>,
    ledger: &'scope Ledger,
    geometry: Geometry,
}

impl<'scope, 'request> Plan<'scope, 'request> {
    pub(super) fn new(
        output: &'scope OwnedCompiledShake<'request>,
        ledger: &'scope Ledger,
    ) -> Result<Self, Error> {
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device != 0
            || !output._program.belongs_to(ledger)
            || !output._inputs.belongs_to(ledger)
            || !output.report.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        let program = &output.compiled.program;
        if program.height() != output.summary.padded_rows
            || program.active_rows() != output.summary.active_rows
            || program.wire_count() != output.summary.wires
            || program.witness_values() != output.summary.input_values
            || output.compiled.public.len() != program.public_values()
            || output.compiled.witness.len() != program.witness_values()
            || output.summary.independent_native_verifications != output.summary.span.segment_count
            || !(1..=2).contains(&output.summary.span.segment_count)
        {
            return Err(Error::Geometry);
        }
        Ok(Self {
            output,
            ledger,
            geometry: Geometry::for_program_shape(
                program.height(),
                program.wire_count(),
                program.public_values(),
            )?,
        })
    }

    pub(super) fn inspect(&self) -> Evidence {
        let snapshot = self.ledger.snapshot();
        let remaining = snapshot.allowance.host - snapshot.current.host;
        Evidence {
            geometry: self.geometry,
            charged_program_host_bytes: self
                .output
                ._program
                .requirements()
                .get(Category::SymbolicCompiler)
                .host,
            charged_input_host_bytes: self
                .output
                ._inputs
                .requirements()
                .get(Category::CompilerInputs)
                .host,
            charged_report_host_bytes: PhaseReportOwner::requirements().get(Category::Report).host,
            charged_worker_host_bytes: snapshot.current.host,
            worker_host_allowance: snapshot.allowance.host,
            remaining_worker_host_bytes: remaining,
            decision: if self.geometry.partial_lower_bound_bytes > remaining {
                Decision::RefusedUnderExistingLedgerCharges
            } else {
                Decision::IncompleteFullPhaseBound
            },
        }
    }
}

#[cfg(all(feature = "recursive-wide", not(feature = "opencl")))]
#[test]
fn exact_cpu_profile_geometry_and_partial_bound_are_checked() {
    let singleton = Geometry::for_program_shape(131_072, 1_503_593, 46).unwrap();
    let paired = Geometry::for_program_shape(262_144, 3_004_067, 46).unwrap();
    assert_eq!(paired.packed_lookups, 16);
    assert_eq!(paired.preprocessed_width, 200);
    assert_eq!(paired.permutation_width_base, 51);
    assert_eq!(paired.quotient_chunks, 16);
    assert_eq!(paired.lde_columns, 472);
    assert_eq!(paired.lde_rows, 8_388_608);
    assert_eq!(paired.retained_lde_bytes, 31_675_383_808);
    assert_eq!(paired.retained_tree_bytes, 1_073_741_760);
    assert_eq!(paired.partial_lower_bound_bytes, 32_749_125_568);
    assert_eq!(singleton.retained_lde_bytes, 15_837_691_904);
    assert_eq!(singleton.retained_tree_bytes, 536_870_848);
    assert_eq!(singleton.partial_lower_bound_bytes, 16_374_562_752);
    for (height, wires, publics) in [
        (0, 1, 46),
        (7, 1, 46),
        (9, 1, 46),
        (MAX_ROWS * 2, 1, 46),
        (usize::MAX, 1, 46),
        (8, MAX_WIRES + 1, 46),
        (8, usize::MAX, 46),
        (8, 1, 45),
        (8, 1, 47),
    ] {
        assert_eq!(
            Geometry::for_program_shape(height, wires, publics),
            Err(Error::Geometry)
        );
    }
    assert_eq!(storage_bytes(0, 472), Err(Error::Overflow));
    assert_eq!(storage_bytes(u64::MAX, 472), Err(Error::Overflow));
    assert_eq!(storage_bytes(8, u64::MAX), Err(Error::Overflow));
}

#[cfg(any(not(feature = "recursive-wide"), feature = "opencl"))]
#[test]
fn unsupported_storage_profile_cannot_supply_cpu_lower_bound() {
    assert_eq!(
        Geometry::for_program_shape(131_072, 1_503_593, 46),
        Err(Error::UnsupportedProfile)
    );
}
