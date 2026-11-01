//! Source-qualified, read-only numerical bounds. Never proof/admission objects.
use super::{
    key::{self, DescriptorKey},
    ConstructionLimits, NativeCoreBound, NativeCoreCounts, NativePlanningStorage,
};
use lattica_prover_p3::block_v2::{
    machine::{program::MAX_WIRES, verifier::batch::shape::OperationCounts},
    profile,
};
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;

pub(super) struct Row {
    pub key: [u8; 32],
    pub geometry: [usize; 5],
    pub values: [usize; 8],
}
mod data;
pub(super) fn content_digest() -> [u8; 32] {
    digest(data::SOURCE, data::PROFILE, data::ROWS)
}
fn digest(source: [u8; 32], profile_id: [u8; 32], rows: &[Row]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"ringct/native-numeric-table/v1\0");
    h.update(source);
    h.update(profile_id);
    h.update((rows.len() as u64).to_le_bytes());
    for row in rows {
        h.update(row.key);
        for n in row.geometry.into_iter().chain(row.values) {
            h.update((n as u64).to_le_bytes());
        }
    }
    h.finalize().into()
}
pub(super) fn available() -> bool {
    static VALID: OnceLock<bool> = OnceLock::new();
    *VALID.get_or_init(|| qualified(data::SOURCE, data::PROFILE, data::CONTENT, data::ROWS))
}
fn qualified(source: [u8; 32], profile_id: [u8; 32], content: [u8; 32], rows: &[Row]) -> bool {
    !rows.is_empty()
        && rows.len() <= 256
        && source == crate::graph_proofs::native_numeric_source_fingerprint()
        && profile_id == profile::CANDIDATE_PROFILE_ID
        && digest(source, profile_id, rows) == content
        && rows.windows(2).all(|r| r[0].key < r[1].key)
}
pub(super) fn lookup<D: DescriptorKey>(
    family: u8,
    descriptor: &D,
    limits: ConstructionLimits,
    storage: NativePlanningStorage,
) -> Option<NativeCoreBound> {
    if limits.max_requested_program_bytes != 2 << 30
        || limits.max_wires != MAX_WIRES
        || limits.max_input_values != 1 << 20
        || !available()
    {
        return None;
    }
    let key = key::descriptor(family, descriptor);
    let row = &data::ROWS[data::ROWS.binary_search_by_key(&key, |r| r.key).ok()?];
    let g = storage.geometry;
    if row.geometry
        != [
            g.width,
            g.height,
            g.public_values,
            g.periodic_columns,
            g.maximum_period,
        ]
    {
        return None;
    }
    let [quotient_chunks, scalar, cubic, poseidon, wires, input_values, selection_hint_words, peak] =
        row.values;
    if quotient_chunks == 0
        || !quotient_chunks.is_power_of_two()
        || quotient_chunks > 32
        || wires > limits.max_wires
        || input_values > limits.max_input_values
        || peak > limits.max_requested_program_bytes
    {
        return None;
    }
    Some(NativeCoreBound {
        storage,
        counts: NativeCoreCounts {
            quotient_chunks,
            operations: OperationCounts {
                scalar,
                cubic,
                poseidon,
            },
            wires,
            input_values,
            selection_hint_words,
            planner_requested_program_bytes_peak: peak,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_tables_reject_stale_source_profile_content_and_duplicates() {
        let source = crate::graph_proofs::native_numeric_source_fingerprint();
        let profile = profile::CANDIDATE_PROFILE_ID;
        let digest = content_digest();
        assert!(!qualified([0; 32], profile, digest, data::ROWS));
        assert!(!qualified(source, [0; 32], digest, data::ROWS));
        assert!(!qualified(source, profile, [0; 32], data::ROWS));
        let rows = [
            Row {
                key: [1; 32],
                geometry: [1; 5],
                values: [1; 8],
            },
            Row {
                key: [1; 32],
                geometry: [1; 5],
                values: [1; 8],
            },
        ];
        assert!(!qualified(source, profile, digest, &rows));
        assert!(!qualified(source, profile, digest, &[]));
    }
}
