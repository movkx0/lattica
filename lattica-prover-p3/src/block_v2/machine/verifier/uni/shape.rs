//! Counts-only native verifier compilation for separately admitted trusted AIRs.
//!
//! This is a lower-level bounded compiler, not a generic AIR memory-admission
//! API. The closed caller must reserve its own descriptor/callback allocations,
//! periodic table, invalid template, ProofInputs and returned-wire backing
//! before entry. `ConstructionLimits` enforces compiler storage independently.
//! The private template has exactly three PCS rounds, at most 32 quotient
//! matrices, 128 queries and binary FRI under the unchanged hiding profile.
use super::{BoundedSymbolicAllowance, BoundedSymbolicBuilder, CompileError, Val};
use crate::block_v2::machine::{
    program::{ConstructionLimits, ProgramBuilder},
    verifier::{batch::shape::OperationCounts, ProofInputs},
};
use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCoreCounts {
    pub quotient_chunks: usize,
    pub operations: OperationCounts,
    pub wires: usize,
    pub input_values: usize,
    /// Streaming canonical-encoding diagnostic, never registration authority.
    pub manifest_sha3_256: [u8; 32],
    /// Observation of this planner only; not a different compiler's admission.
    pub planner_requested_program_bytes_peak: usize,
}

/// Compile a fresh-public/fresh-proof-input native core and return only counts.
/// All invalid objects are dropped internally. Numeric proof values cannot
/// influence this program: each becomes a fresh unknown witness input. Exact
/// trusted AIR geometry, periodic values and protocol parameters still matter.
///
/// Before this call the closed caller must account for two complete template
/// backings (construction overlap), both bounded symbolic components, twice
/// `max_input_values * size_of::<Val>()`, cumulative returned wire payload of
/// `max_input_values * size_of::<Wire>()`, template/helper Vec headers and AIR
/// callback allocations. There is no unbounded fallback or proof verification.
pub fn verifier_core_counts<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
) -> Result<NativeCoreCounts, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let width = air.width();
    let publics = air.num_public_values();
    if !(1..=1024).contains(&width)
        || publics > 216
        || !(8..=1 << 24).contains(&height)
        || !height.is_power_of_two()
        || columns.len() != air.num_periodic_columns()
        || columns.len() > 128
        || columns
            .iter()
            .any(|c| !c.len().is_power_of_two() || c.len() > height || c.len() > 256)
    {
        return Err(CompileError::Shape("native core planner geometry"));
    }
    let chunks = super::quotient_chunks_bounded(air, height, symbolic)?;
    let next = !air.main_next_row_columns().is_empty();
    let template = super::super::template::uni_bounded_shape(width, height, next, chunks)?;
    let mut builder = ProgramBuilder::new_with_construction_limits(0, construction)
        .map_err(|e| CompileError::from_builder_admission(e, "native core builder allowance"))?;
    let mut inputs = ProofInputs::default();
    let values = [Val::ZERO; 216];
    let public = inputs.bases(&mut builder, &values[..publics])?;
    super::verify_bounded(
        &mut builder,
        &mut inputs,
        air,
        height,
        &public,
        &template,
        columns,
        symbolic,
    )?;
    let program = builder
        .finish(None)
        .map_err(|e| CompileError::from_builder_admission(e, "native core packing allowance"))?;
    let mut digest = Sha3_256::new();
    program
        .visit_manifest_fields(&mut |word| {
            digest.update(word.to_le_bytes());
            Ok(())
        })
        .map_err(|_| CompileError::Shape("native core manifest encoding"))?;
    let result = NativeCoreCounts {
        quotient_chunks: chunks,
        operations: OperationCounts::from_program(&program),
        wires: program.wire_count(),
        input_values: program.witness_values(),
        manifest_sha3_256: digest.finalize().into(),
        planner_requested_program_bytes_peak: program.construction_host_bytes(),
    };
    debug_assert_eq!(result.input_values, inputs.values.len());
    // Template, program, witness inputs and callback handles never escape.
    Ok(result)
}
