//! Qualified immutable numerical tables. A stale source/profile/content digest
//! causes ordinary bounded computation, never acceptance of stale geometry.
use super::{
    CompileError, ConstructionLimits, OperationCounts, PlanningStorage, RegisteredChildShape,
    VerifierCoreBound, VerifierHeightEnvelope, MAX_WIRES,
};
use crate::block_v2::{
    machine::{
        program::{EXT_LANES, LANES, PUBLICS_PER_ROW},
        WIDTH,
    },
    profile,
};
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;
include!(concat!(env!("OUT_DIR"), "/metadata-source.rs"));
mod data;

#[derive(Clone, Copy, Debug)]
struct Row {
    public_values: usize,
    log_height: usize,
    values: [usize; 9],
}
pub(super) const RESERVED_BYTES: usize = 72 * core::mem::size_of::<Row>() + 4096;
fn signature() -> [usize; 12] {
    [
        LANES,
        EXT_LANES,
        PUBLICS_PER_ROW,
        WIDTH,
        profile::LOG_BLOWUP,
        profile::CAP_HEIGHT,
        profile::NUM_QUERIES,
        profile::NUM_RANDOM_CODEWORDS,
        profile::QUERY_POW_BITS as usize,
        profile::CHALLENGE_FIELD_BITS as usize,
        MAX_WIRES,
        1 << 20,
    ]
}
fn checksum(rows: &[Row]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/qualified-numeric-planning-rows/v1\0");
    for row in rows {
        for value in [row.public_values, row.log_height]
            .into_iter()
            .chain(row.values)
        {
            hash.update((value as u64).to_le_bytes());
        }
    }
    hash.finalize().into()
}
fn valid(
    rows: &[Row],
    source: [u8; 32],
    profile_id: [u8; 32],
    shape: [usize; 12],
    digest: [u8; 32],
) -> bool {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64"))
        || rows.len() != 72
        || source != COMPILED_SOURCE_DIGEST
        || profile_id != profile::CANDIDATE_PROFILE_ID
        || shape != signature()
        || checksum(rows) != digest
    {
        return false;
    }
    for (i, row) in rows.iter().enumerate() {
        if row.public_values != [25, 28, 38, 46][i / 18] || row.log_height != 3 + i % 18 {
            return false;
        }
        let operations = OperationCounts {
            scalar: row.values[0],
            cubic: row.values[1],
            poseidon: row.values[2],
        };
        if operations.active_rows(0) != Ok(row.values[6])
            || operations.padded_rows(0) != Ok(row.values[7])
            || row.values[3] > MAX_WIRES
            || row.values[4] > 1 << 20
            || row.values[8] > 2 << 30
        {
            return false;
        }
    }
    true
}
pub(super) fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        valid(
            data::ROWS,
            data::SOURCE_DIGEST,
            data::PROFILE_ID,
            data::SIGNATURE,
            data::ROWS_DIGEST,
        )
    })
}

pub(super) fn lookup(
    public_values: usize,
    maximum_height: usize,
    construction: ConstructionLimits,
    auxiliary: usize,
) -> Result<Option<VerifierHeightEnvelope>, CompileError> {
    if ![25, 28, 38, 46].contains(&public_values)
        || !(8..=1 << 20).contains(&maximum_height)
        || !maximum_height.is_power_of_two()
        || construction.max_requested_program_bytes != 2 << 30
        || construction.max_wires != MAX_WIRES
        || construction.max_input_values != 1 << 20
        || !available()
    {
        return Ok(None);
    }
    let shape = |height: usize| RegisteredChildShape {
        public_values,
        height,
        preprocessing_cap_roots: 1
            << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT),
    };
    let storage = PlanningStorage::for_children(0, &[shape(maximum_height)], construction)?;
    if storage.auxiliary_peak_bytes > auxiliary {
        return Err(CompileError::ResourceAdmission(
            "registered height envelope auxiliary allowance",
        ));
    }
    let mut bounds = [None; super::metadata_planning::MAX_HEIGHTS];
    for row in data::ROWS.iter().filter(|r| {
        r.public_values == public_values && r.log_height <= maximum_height.ilog2() as usize
    }) {
        let n = row.values;
        bounds[row.log_height - 3] = Some(VerifierCoreBound {
            operations: OperationCounts {
                scalar: n[0],
                cubic: n[1],
                poseidon: n[2],
            },
            wire_upper_bound: n[3],
            input_values_upper_bound: n[4],
            selection_hint_words_upper_bound: n[5],
            active_rows_upper_bound: n[6],
            padded_rows_upper_bound: n[7],
            planner_requested_program_bytes_peak: n[8],
            storage: PlanningStorage::for_children(0, &[shape(1 << row.log_height)], construction)?,
        });
    }
    Ok(Some(super::envelope::assemble(
        public_values,
        maximum_height,
        storage,
        bounds.into_iter().flatten(),
    )?))
}

#[cfg(test)]
pub(super) fn emit_row(public_values: usize, log_height: usize, bound: VerifierCoreBound) {
    if available() {
        let row = data::ROWS
            .iter()
            .find(|row| row.public_values == public_values && row.log_height == log_height)
            .unwrap();
        assert_eq!(
            row.values,
            [
                bound.operations.scalar,
                bound.operations.cubic,
                bound.operations.poseidon,
                bound.wire_upper_bound,
                bound.input_values_upper_bound,
                bound.selection_hint_words_upper_bound,
                bound.active_rows_upper_bound,
                bound.padded_rows_upper_bound,
                bound.planner_requested_program_bytes_peak
            ],
            "qualified table row differs from fresh numeric compilation"
        );
    }
    eprintln!(
        "METADATA_TABLE_ROW {}",
        serde_json::json!({ "public_values": public_values, "log_height": log_height,
        "values": [bound.operations.scalar, bound.operations.cubic, bound.operations.poseidon,
            bound.wire_upper_bound, bound.input_values_upper_bound, bound.selection_hint_words_upper_bound,
            bound.active_rows_upper_bound, bound.padded_rows_upper_bound, bound.planner_requested_program_bytes_peak] })
    );
}
#[cfg(test)]
pub(super) fn emit_identity() {
    eprintln!(
        "METADATA_TABLE_IDENTITY {}",
        serde_json::json!({ "source_digest": COMPILED_SOURCE_DIGEST,
        "profile_id": profile::CANDIDATE_PROFILE_ID, "signature": signature(), "available": available() })
    );
}

#[cfg(test)]
mod tests;
