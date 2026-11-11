use super::*;
use crate::block_v2::profile;
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks, get_max_constraint_degree,
};
use p3_lookup::{LogUpGadget, Lookups};

#[derive(Clone, Debug, serde::Serialize)]
pub struct TableGeometry {
    pub table: &'static str,
    pub height: usize,
    pub active_rows: usize,
    pub first_row: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub permutation_width: usize,
    pub quotient_chunks: usize,
    pub constraint_degree: usize,
    pub constraints: usize,
    pub committed_lde_fields: u64,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct ArchitectureGeometry {
    pub template_identity: [u8; 32],
    pub tables: Vec<TableGeometry>,
    pub committed_lde_fields: u64,
    pub lde_payload_bytes: u64,
    pub degree_gate: bool,
    pub quotient_gate: bool,
    pub typed: TypedVerifierStats,
}

pub(super) fn analyze(template: &RecursionTemplate) -> Result<ArchitectureGeometry, String> {
    let gadget = LogUpGadget::new();
    let mut tables = Vec::new();
    let mut count_weight = 0u64;
    for air in template.airs() {
        let layout = AirLayout::from_air::<Val>(&air);
        let unpacked = Lookups::<Val>::from_air::<profile::Challenge, _>(&air);
        let log_chunks = get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
            &air, layout, &unpacked, 1, &gadget,
        );
        if log_chunks > profile::LOG_BLOWUP {
            return Err("recursion quotient exceeds pinned profile".into());
        }
        let packed = unpacked.pack_same_bus(&gadget, 1 << log_chunks);
        let degree = get_max_constraint_degree::<Val, profile::Challenge, _, _>(
            &air, layout, &packed, &gadget,
        );
        let height = air.height;
        count_weight = count_weight
            .checked_add(
                packed
                    .total_count_weight()
                    .checked_mul(height as u64)
                    .ok_or("recursion multiplicity overflow")?,
            )
            .ok_or("recursion multiplicity overflow")?;
        let quotient_chunks = 1 << (log_chunks + 1);
        let permutation_width = if packed.is_empty() {
            0
        } else {
            (packed.len() + 1) * 3
        };
        let r = profile::NUM_RANDOM_CODEWORDS;
        let columns = air.width()
            + r
            + air.preprocessed_width()
            + permutation_width
            + r
            + quotient_chunks * (3 + r)
            + 3
            + r;
        let fields = (height as u64)
            .checked_mul(2 << profile::LOG_BLOWUP)
            .and_then(|n| n.checked_mul(columns as u64))
            .ok_or("recursion LDE overflow")?;
        tables.push(TableGeometry {
            table: [
                "arithmetic",
                "cubic-extension",
                "poseidon2",
                "public-bindings",
                "typed-opening-reductions",
            ][air.kind],
            height,
            active_rows: air.active_rows,
            first_row: air.first_row,
            main_width: air.width(),
            preprocessed_width: air.preprocessed_width(),
            permutation_width,
            quotient_chunks,
            constraint_degree: degree,
            constraints: get_constraint_layout::<Val, profile::Challenge, _, _>(
                &air, layout, &packed, &gadget,
            )
            .total_constraints(),
            committed_lde_fields: fields,
        });
    }
    if count_weight >= crate::block_v2::commitment::MODULUS {
        return Err("recursion lookup multiplicity bound".into());
    }
    let fields = tables
        .iter()
        .try_fold(0u64, |a, t| a.checked_add(t.committed_lde_fields))
        .ok_or("recursion total LDE overflow")?;
    Ok(ArchitectureGeometry {
        template_identity: template.id,
        typed: template.typed.stats().clone(),
        degree_gate: tables.iter().all(|t| t.constraint_degree <= 4),
        quotient_gate: tables.iter().all(|t| t.quotient_chunks <= 8),
        lde_payload_bytes: fields.checked_mul(8).ok_or("recursion byte overflow")?,
        committed_lde_fields: fields,
        tables,
    })
}
