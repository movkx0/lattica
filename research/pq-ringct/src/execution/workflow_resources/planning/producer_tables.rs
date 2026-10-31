//! Named original transfers for the concrete source-derived metadata tables.
//! There is no caller count/budget, generic public table issuer or new admission.
use super::WorkflowPlanning;
use crate::{
    execution::{retained_resources::{Bytes, Category, Error as QuotaError,
        Requirements, Reservation}, workflow_resources::WorkflowError},
    spend_pipeline::full_workflow::{
        fresh_generation::{FreshGenerationError,
            case_lifetime::{CaseOwnerTable, CaseOwnerTableFailure, CaseRetirementState}},
        metadata_planning::{ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::{algebra, crypto, final_aggregation, graph, native},
    },
};
use core::mem::size_of;
mod reports;
mod final_runtime;
use std::cell::RefCell;

/// Admission refusal leaves originals in the permanently failed installation.
/// Construction refusal owns the actual partial table and all its originals.
pub(crate) enum TableTransferFailure<'case, T> {
    Admission(WorkflowError),
    Construction(CaseOwnerTableFailure<'case, T>),
}
pub(crate) type TableTransferResult<'case, T> =
    Result<CaseOwnerTable<'case, T>, TableTransferFailure<'case, T>>;

const ORDINARY_TABLE_COUNT: usize = 111;
const PARENT_TABLE_BASE: usize = 128;
const PARENT_LEVELS: usize = 32;

enum TableCount {
    Family(ProducerFamily), ShakeNative, ShakeRecursive, AesNative, AesRecursive,
    One, FinalMerges, Parent(usize),
}
fn count(plan: &SourceMetadataPlanningPlan, selector: TableCount) -> Result<usize, WorkflowError> {
    let counts = plan.counts();
    match selector {
        TableCount::Family(family) => Ok(counts.family(family)),
        TableCount::ShakeNative => Ok(counts.shake_native()),
        TableCount::ShakeRecursive => Ok(counts.shake_recursive()),
        TableCount::AesNative => Ok(counts.aes_native()),
        TableCount::AesRecursive => Ok(counts.aes_recursive()),
        TableCount::One => Ok(1),
        TableCount::FinalMerges => plan.members().len().checked_sub(1)
            .filter(|n| *n != 0).ok_or(WorkflowError::Planning),
        TableCount::Parent(level) => counts.parent_level(level)
            .filter(|n| *n != 0).ok_or(WorkflowError::Planning),
    }
}
fn parent_id(level: usize, route: usize) -> Result<usize, WorkflowError> {
    if level >= PARENT_LEVELS || route >= 4 { return Err(WorkflowError::Planning); }
    Ok(PARENT_TABLE_BASE + 4 * level + route)
}

impl WorkflowPlanning<'_> {
    // Only the named methods below can choose T/id/count. The source installation
    // authenticates the exact plan, original member/scope and case-state pointer.
    fn transfer_metadata_table<'case, T>(&mut self, plan: &SourceMetadataPlanningPlan,
        case: &'case CaseRetirementState, id: usize, selector: TableCount)
        -> TableTransferResult<'case, T>
    {
        // This marks failed and issued before any split or table construction.
        // Every later error/unwind therefore permanently prevents new issuance.
        self.begin_metadata_table(plan, case, id).map_err(TableTransferFailure::Admission)?;
        let count = count(plan, selector).map_err(TableTransferFailure::Admission)?;
        let requirements = CaseOwnerTable::<T>::requirements(count)
            .map_err(|_| TableTransferFailure::Admission(WorkflowError::Planning))?;
        let original = self.original.split(requirements)
            .map_err(|error| TableTransferFailure::Admission(WorkflowError::from(error)))?;
        match CaseOwnerTable::from_original(case, count, original) {
            Ok(table) => {
                self.finish_metadata_table_success();
                Ok(table)
            }
            Err(failure) => Err(TableTransferFailure::Construction(failure)),
        }
    }
}

// These actual forwarding/return owners are separate from the exact table
// original. The installed metadata residual retains their claim permanently.
fn transfer_frames<T>() -> Result<Requirements, WorkflowError> {
    let bytes = [size_of::<CaseOwnerTable<'static, T>>(),
        size_of::<Option<CaseOwnerTable<'static, T>>>(),
        size_of::<CaseOwnerTableFailure<'static, T>>(),
        size_of::<TableTransferFailure<'static, T>>(),
        size_of::<TableTransferResult<'static, T>>(),
        size_of::<Result<CaseOwnerTable<'static, T>, CaseOwnerTableFailure<'static, T>>>(),
        size_of::<Result<Requirements, FreshGenerationError>>(),
        size_of::<Result<Requirements, WorkflowError>>(),
        size_of::<Result<Reservation, QuotaError>>(),
        size_of::<Result<(), WorkflowError>>(), size_of::<Result<usize, WorkflowError>>(),
        size_of::<Reservation>(), size_of::<Requirements>(), size_of::<TableCount>(),
        size_of::<&SourceMetadataPlanningPlan>(), size_of::<&CaseRetirementState>(),
        size_of::<[usize; 8]>(), size_of::<[Requirements; 4]>(),
    ].into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
fn add_frames(total: &mut Requirements, additional: Requirements) -> Result<(), WorkflowError> {
    for category in Category::ALL { total.add(category, additional.get(category))?; }
    Ok(())
}

macro_rules! named_tables {
    ($($id:literal => $method:ident<$case:lifetime $(, $life:lifetime)*>:
        $item:ty, $census:ty => $selector:expr;)*) => {
        impl WorkflowPlanning<'_> {
            $(pub(crate) fn $method<$case $(, $life)*>(&mut self,
                plan: &SourceMetadataPlanningPlan, case: &$case CaseRetirementState)
                -> TableTransferResult<$case, $item>
            { self.transfer_metadata_table::<$item>(plan, case, $id, $selector) })*
        }
        fn ordinary_transfer_frames() -> Result<Requirements, WorkflowError> {
            let mut total = Requirements::default();
            $(add_frames(&mut total, transfer_frames::<$census>()?)?;)*
            Ok(total)
        }
        #[cfg(test)]
        const ORDINARY_IDS: [usize; ORDINARY_TABLE_COUNT] = [$($id),*];
    };
}

// Stable IDs 0..110 are part of the one-shot source installation inventory.
named_tables! {
    0 => metadata_source_native_plans<'case, 'a>:
        native::SourcePlanResult<'a>, native::SourcePlanResult<'static> => TableCount::Family(ProducerFamily::Source);
    1 => metadata_source_native_outputs<'case, 'a>:
        RefCell<Option<native::SourceNativeResult<'a>>>, RefCell<Option<native::SourceNativeResult<'static>>> => TableCount::Family(ProducerFamily::Source);
    2 => metadata_source_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::SourceNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::SourceNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Source);
    3 => metadata_uniform_native_plans<'case, 'a>:
        native::UniformPlanResult<'a>, native::UniformPlanResult<'static> => TableCount::Family(ProducerFamily::Uniform);
    4 => metadata_uniform_native_outputs<'case, 'a>:
        RefCell<Option<native::UniformNativeResult<'a>>>, RefCell<Option<native::UniformNativeResult<'static>>> => TableCount::Family(ProducerFamily::Uniform);
    5 => metadata_uniform_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::UniformNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::UniformNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Uniform);
    6 => metadata_sparse_native_plans<'case, 'a>:
        native::SparsePlanResult<'a>, native::SparsePlanResult<'static> => TableCount::Family(ProducerFamily::Sparse);
    7 => metadata_sparse_native_outputs<'case, 'a>:
        RefCell<Option<native::SparseNativeResult<'a>>>, RefCell<Option<native::SparseNativeResult<'static>>> => TableCount::Family(ProducerFamily::Sparse);
    8 => metadata_sparse_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::SparseNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::SparseNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Sparse);
    9 => metadata_transcript_native_plans<'case, 'a>:
        native::TranscriptPlanResult<'a>, native::TranscriptPlanResult<'static> => TableCount::Family(ProducerFamily::Transcript);
    10 => metadata_transcript_native_outputs<'case, 'a>:
        RefCell<Option<native::TranscriptNativeResult<'a>>>, RefCell<Option<native::TranscriptNativeResult<'static>>> => TableCount::Family(ProducerFamily::Transcript);
    11 => metadata_transcript_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::TranscriptNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::TranscriptNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Transcript);
    12 => metadata_affine_native_plans<'case, 'a>:
        native::AffinePlanResult<'a>, native::AffinePlanResult<'static> => TableCount::Family(ProducerFamily::Affine);
    13 => metadata_affine_native_outputs<'case, 'a>:
        RefCell<Option<native::AffineNativeResult<'a>>>, RefCell<Option<native::AffineNativeResult<'static>>> => TableCount::Family(ProducerFamily::Affine);
    14 => metadata_affine_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::AffineNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::AffineNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Affine);
    15 => metadata_ntt_native_plans<'case, 'a>:
        native::NttPlanResult<'a>, native::NttPlanResult<'static> => TableCount::Family(ProducerFamily::Ntt);
    16 => metadata_ntt_native_outputs<'case, 'a>:
        RefCell<Option<native::NttNativeResult<'a>>>, RefCell<Option<native::NttNativeResult<'static>>> => TableCount::Family(ProducerFamily::Ntt);
    17 => metadata_ntt_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::NttNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::NttNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Ntt);
    18 => metadata_mul_native_plans<'case, 'a>:
        native::MulPlanResult<'a>, native::MulPlanResult<'static> => TableCount::Family(ProducerFamily::Mul);
    19 => metadata_mul_native_outputs<'case, 'a>:
        RefCell<Option<native::MulNativeResult<'a>>>, RefCell<Option<native::MulNativeResult<'static>>> => TableCount::Family(ProducerFamily::Mul);
    20 => metadata_mul_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::MulNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::MulNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Mul);
    21 => metadata_g_bound_native_plans<'case, 'a>:
        native::GBoundPlanResult<'a>, native::GBoundPlanResult<'static> => TableCount::Family(ProducerFamily::GBound);
    22 => metadata_g_bound_native_outputs<'case, 'a>:
        RefCell<Option<native::GBoundNativeResult<'a>>>, RefCell<Option<native::GBoundNativeResult<'static>>> => TableCount::Family(ProducerFamily::GBound);
    23 => metadata_g_bound_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::GBoundNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::GBoundNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::GBound);
    24 => metadata_permutation_native_plans<'case, 'a>:
        native::PermutationPlanResult<'a>, native::PermutationPlanResult<'static> => TableCount::Family(ProducerFamily::Permutation);
    25 => metadata_permutation_native_outputs<'case, 'a>:
        RefCell<Option<native::PermutationNativeResult<'a>>>, RefCell<Option<native::PermutationNativeResult<'static>>> => TableCount::Family(ProducerFamily::Permutation);
    26 => metadata_permutation_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::PermutationNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::PermutationNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::Permutation);
    27 => metadata_linear_map_native_plans<'case, 'a>:
        native::LinearMapPlanResult<'a>, native::LinearMapPlanResult<'static> => TableCount::Family(ProducerFamily::LinearMap);
    28 => metadata_linear_map_native_outputs<'case, 'a>:
        RefCell<Option<native::LinearMapNativeResult<'a>>>, RefCell<Option<native::LinearMapNativeResult<'static>>> => TableCount::Family(ProducerFamily::LinearMap);
    29 => metadata_linear_map_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<native::LinearMapNativePreissueResult<'plan, 'a>>>, RefCell<Option<native::LinearMapNativePreissueResult<'static, 'static>>> => TableCount::Family(ProducerFamily::LinearMap);
    30 => metadata_affine_blueprints<'case, 'a, 'graph>:
        algebra::AffineBlueprintResult<'a, 'graph>, algebra::AffineBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::Affine);
    31 => metadata_affine_compiler_plans<'case, 'a>:
        algebra::AffineCompilerPlanResult<'a>, algebra::AffineCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::Affine);
    32 => metadata_affine_outer_plans<'case, 'source, 'a>:
        algebra::AffineOuterPlanResult<'source, 'a>, algebra::AffineOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Affine);
    33 => metadata_affine_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::AffineCompiledResult<'a>>>, RefCell<Option<algebra::AffineCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Affine);
    34 => metadata_affine_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::AffineOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::AffineOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Affine);
    35 => metadata_affine_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Affine);
    36 => metadata_ntt_blueprints<'case, 'a, 'graph>:
        algebra::NttBlueprintResult<'a, 'graph>, algebra::NttBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::Ntt);
    37 => metadata_ntt_compiler_plans<'case, 'a>:
        algebra::NttCompilerPlanResult<'a>, algebra::NttCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::Ntt);
    38 => metadata_ntt_outer_plans<'case, 'source, 'a>:
        algebra::NttOuterPlanResult<'source, 'a>, algebra::NttOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Ntt);
    39 => metadata_ntt_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::NttCompiledResult<'a>>>, RefCell<Option<algebra::NttCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Ntt);
    40 => metadata_ntt_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::NttOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::NttOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Ntt);
    41 => metadata_ntt_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Ntt);
    42 => metadata_mul_blueprints<'case, 'a, 'graph>:
        algebra::MulBlueprintResult<'a, 'graph>, algebra::MulBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::Mul);
    43 => metadata_mul_compiler_plans<'case, 'a>:
        algebra::MulCompilerPlanResult<'a>, algebra::MulCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::Mul);
    44 => metadata_mul_outer_plans<'case, 'source, 'a>:
        algebra::MulOuterPlanResult<'source, 'a>, algebra::MulOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Mul);
    45 => metadata_mul_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::MulCompiledResult<'a>>>, RefCell<Option<algebra::MulCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Mul);
    46 => metadata_mul_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::MulOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::MulOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Mul);
    47 => metadata_mul_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Mul);
    48 => metadata_g_bound_blueprints<'case, 'a, 'graph>:
        algebra::GBoundBlueprintResult<'a, 'graph>, algebra::GBoundBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::GBound);
    49 => metadata_g_bound_compiler_plans<'case, 'a>:
        algebra::GBoundCompilerPlanResult<'a>, algebra::GBoundCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::GBound);
    50 => metadata_g_bound_outer_plans<'case, 'source, 'a>:
        algebra::GBoundOuterPlanResult<'source, 'a>, algebra::GBoundOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::GBound);
    51 => metadata_g_bound_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::GBoundCompiledResult<'a>>>, RefCell<Option<algebra::GBoundCompiledResult<'static>>> => TableCount::Family(ProducerFamily::GBound);
    52 => metadata_g_bound_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::GBoundOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::GBoundOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::GBound);
    53 => metadata_g_bound_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::GBound);
    54 => metadata_permutation_blueprints<'case, 'a, 'graph>:
        algebra::PermutationBlueprintResult<'a, 'graph>, algebra::PermutationBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::Permutation);
    55 => metadata_permutation_compiler_plans<'case, 'a>:
        algebra::PermutationCompilerPlanResult<'a>, algebra::PermutationCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::Permutation);
    56 => metadata_permutation_outer_plans<'case, 'source, 'a>:
        algebra::PermutationOuterPlanResult<'source, 'a>, algebra::PermutationOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Permutation);
    57 => metadata_permutation_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::PermutationCompiledResult<'a>>>, RefCell<Option<algebra::PermutationCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Permutation);
    58 => metadata_permutation_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::PermutationOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::PermutationOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Permutation);
    59 => metadata_permutation_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Permutation);
    60 => metadata_linear_map_blueprints<'case, 'a, 'graph>:
        algebra::LinearMapBlueprintResult<'a, 'graph>, algebra::LinearMapBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::LinearMap);
    61 => metadata_linear_map_compiler_plans<'case, 'a>:
        algebra::LinearMapCompilerPlanResult<'a>, algebra::LinearMapCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::LinearMap);
    62 => metadata_linear_map_outer_plans<'case, 'source, 'a>:
        algebra::LinearMapOuterPlanResult<'source, 'a>, algebra::LinearMapOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::LinearMap);
    63 => metadata_linear_map_compiled_outputs<'case, 'a>:
        RefCell<Option<algebra::LinearMapCompiledResult<'a>>>, RefCell<Option<algebra::LinearMapCompiledResult<'static>>> => TableCount::Family(ProducerFamily::LinearMap);
    64 => metadata_linear_map_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<algebra::LinearMapOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<algebra::LinearMapOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::LinearMap);
    65 => metadata_linear_map_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::LinearMap);
    66 => metadata_fixed_plans<'case, 'a>:
        graph::FixedPlanResult<'a>, graph::FixedPlanResult<'static> => TableCount::Family(ProducerFamily::Fixed);
    67 => metadata_fixed_outer_plans<'case, 'source, 'a>:
        graph::FixedOuterPlanResult<'source, 'a>, graph::FixedOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Fixed);
    68 => metadata_fixed_compiled_outputs<'case, 'a>:
        RefCell<Option<graph::FixedCompiledResult<'a>>>, RefCell<Option<graph::FixedCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Fixed);
    69 => metadata_fixed_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<graph::FixedOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<graph::FixedOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Fixed);
    70 => metadata_fixed_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Fixed);
    71 => metadata_source_blueprints<'case, 'a, 'graph>:
        graph::SourceBlueprintResult<'a, 'graph>, graph::SourceBlueprintResult<'static, 'static> => TableCount::Family(ProducerFamily::Source);
    72 => metadata_source_compiler_plans<'case, 'a>:
        graph::SourceCompilerPlanResult<'a>, graph::SourceCompilerPlanResult<'static> => TableCount::Family(ProducerFamily::Source);
    73 => metadata_source_outer_plans<'case, 'source, 'a>:
        graph::SourceOuterPlanResult<'source, 'a>, graph::SourceOuterPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Source);
    74 => metadata_source_compiled_outputs<'case, 'a>:
        RefCell<Option<graph::SourceCompiledResult<'a>>>, RefCell<Option<graph::SourceCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Source);
    75 => metadata_source_outer_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<graph::SourceOuterPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<graph::SourceOuterPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Source);
    76 => metadata_source_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Source);
    77 => metadata_parameters_plans<'case, 'source, 'a>:
        graph::ParametersPlanResult<'source, 'a>, graph::ParametersPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Parameters);
    78 => metadata_parameters_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<graph::ParametersPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<graph::ParametersPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Parameters);
    79 => metadata_parameters_compiled_outputs<'case, 'a>:
        RefCell<Option<graph::GraphCompiledResult<'a>>>, RefCell<Option<graph::GraphCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Parameters);
    80 => metadata_parameters_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Parameters);
    81 => metadata_auxiliary_plans<'case, 'source, 'a>:
        graph::AuxiliaryPlanResult<'source, 'a>, graph::AuxiliaryPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Auxiliary);
    82 => metadata_auxiliary_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<graph::AuxiliaryPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<graph::AuxiliaryPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Auxiliary);
    83 => metadata_auxiliary_compiled_outputs<'case, 'a>:
        RefCell<Option<graph::GraphCompiledResult<'a>>>, RefCell<Option<graph::GraphCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Auxiliary);
    84 => metadata_auxiliary_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Auxiliary);
    85 => metadata_equality_plans<'case, 'source, 'a>:
        graph::EqualityPlanResult<'source, 'a>, graph::EqualityPlanResult<'static, 'static> => TableCount::Family(ProducerFamily::Equality);
    86 => metadata_equality_preissues<'case, 'plan, 'source, 'a>:
        RefCell<Option<graph::EqualityPreissueResult<'plan, 'source, 'a>>>, RefCell<Option<graph::EqualityPreissueResult<'static, 'static, 'static>>> => TableCount::Family(ProducerFamily::Equality);
    87 => metadata_equality_compiled_outputs<'case, 'a>:
        RefCell<Option<graph::GraphCompiledResult<'a>>>, RefCell<Option<graph::GraphCompiledResult<'static>>> => TableCount::Family(ProducerFamily::Equality);
    88 => metadata_equality_outer_outputs<'case, 'a>:
        RefCell<Option<graph::GraphOuterResult<'a>>>, RefCell<Option<graph::GraphOuterResult<'static>>> => TableCount::Family(ProducerFamily::Equality);
    89 => metadata_shake_plans<'case, 'a>:
        crypto::ShakePlanResult<'a>, crypto::ShakePlanResult<'static> => TableCount::Family(ProducerFamily::Shake);
    90 => metadata_shake_native_outputs<'case, 'a>:
        RefCell<Option<crypto::ShakeNativeResult<'a>>>, RefCell<Option<crypto::ShakeNativeResult<'static>>> => TableCount::ShakeNative;
    91 => metadata_shake_endpoint_outputs<'case, 'a>:
        RefCell<Option<crypto::ShakeEndpointResult<'a>>>, RefCell<Option<crypto::ShakeEndpointResult<'static>>> => TableCount::Family(ProducerFamily::Shake);
    92 => metadata_shake_compiled_outputs<'case, 'a>:
        RefCell<Option<crypto::ComponentCompiledResult<'a>>>, RefCell<Option<crypto::ComponentCompiledResult<'static>>> => TableCount::ShakeRecursive;
    93 => metadata_shake_outer_outputs<'case, 'a>:
        RefCell<Option<crypto::ComponentOuterResult<'a>>>, RefCell<Option<crypto::ComponentOuterResult<'static>>> => TableCount::ShakeRecursive;
    94 => metadata_shake_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<crypto::ShakeNativePreissueResult<'plan, 'a>>>, RefCell<Option<crypto::ShakeNativePreissueResult<'static, 'static>>> => TableCount::ShakeNative;
    95 => metadata_shake_outer_preissues<'case, 'plan, 'a>:
        RefCell<Option<crypto::ShakeOuterPreissueResult<'plan, 'a>>>, RefCell<Option<crypto::ShakeOuterPreissueResult<'static, 'static>>> => TableCount::ShakeRecursive;
    96 => metadata_shake_request_outputs<'case, 'a>:
        RefCell<Option<crypto::ShakeRequestResult<'a>>>, RefCell<Option<crypto::ShakeRequestResult<'static>>> => TableCount::Family(ProducerFamily::Shake);
    97 => metadata_aes_plans<'case, 'a>:
        crypto::AesPlanResult<'a>, crypto::AesPlanResult<'static> => TableCount::Family(ProducerFamily::Aes);
    98 => metadata_aes_native_outputs<'case, 'a>:
        RefCell<Option<crypto::AesNativeResult<'a>>>, RefCell<Option<crypto::AesNativeResult<'static>>> => TableCount::AesNative;
    99 => metadata_aes_endpoint_outputs<'case, 'a>:
        RefCell<Option<crypto::AesEndpointResult<'a>>>, RefCell<Option<crypto::AesEndpointResult<'static>>> => TableCount::Family(ProducerFamily::Aes);
    100 => metadata_aes_compiled_outputs<'case, 'a>:
        RefCell<Option<crypto::ComponentCompiledResult<'a>>>, RefCell<Option<crypto::ComponentCompiledResult<'static>>> => TableCount::AesRecursive;
    101 => metadata_aes_outer_outputs<'case, 'a>:
        RefCell<Option<crypto::ComponentOuterResult<'a>>>, RefCell<Option<crypto::ComponentOuterResult<'static>>> => TableCount::AesRecursive;
    102 => metadata_aes_native_preissues<'case, 'plan, 'a>:
        RefCell<Option<crypto::AesNativePreissueResult<'plan, 'a>>>, RefCell<Option<crypto::AesNativePreissueResult<'static, 'static>>> => TableCount::AesNative;
    103 => metadata_aes_outer_preissues<'case, 'plan, 'a>:
        RefCell<Option<crypto::AesOuterPreissueResult<'plan, 'a>>>, RefCell<Option<crypto::AesOuterPreissueResult<'static, 'static>>> => TableCount::AesRecursive;
    104 => metadata_aes_request_outputs<'case, 'a>:
        RefCell<Option<crypto::AesRequestResult<'a>>>, RefCell<Option<crypto::AesRequestResult<'static>>> => TableCount::Family(ProducerFamily::Aes);
    105 => metadata_final_sources<'case, 'a>:
        final_aggregation::FinalSourceResult<'a>, final_aggregation::FinalSourceResult<'static> => TableCount::One;
    106 => metadata_final_plans<'case, 'a>:
        final_aggregation::FinalPlanResult<'a>, final_aggregation::FinalPlanResult<'static> => TableCount::One;
    107 => metadata_final_compiled_outputs<'case, 'a>:
        RefCell<Option<final_aggregation::FinalCompiledResult<'a>>>, RefCell<Option<final_aggregation::FinalCompiledResult<'static>>> => TableCount::FinalMerges;
    108 => metadata_final_outer_outputs<'case, 'a>:
        RefCell<Option<final_aggregation::FinalOuterResult<'a>>>, RefCell<Option<final_aggregation::FinalOuterResult<'static>>> => TableCount::FinalMerges;
    109 => metadata_final_verify_outputs<'case, 'root, 'a>:
        RefCell<Option<final_aggregation::FinalVerifyResult<'root, 'a>>>, RefCell<Option<final_aggregation::FinalVerifyResult<'static, 'static>>> => TableCount::One;
    110 => metadata_final_preissues<'case, 'plan, 'a>:
        RefCell<Option<final_aggregation::FinalPreissueResult<'plan, 'a>>>, RefCell<Option<final_aggregation::FinalPreissueResult<'static, 'static>>> => TableCount::FinalMerges;
}

macro_rules! parent_table {
    ($method:ident<$case:lifetime $(, $life:lifetime)*>: $item:ty, $route:literal) => {
        impl WorkflowPlanning<'_> {
            pub(crate) fn $method<$case $(, $life)*>(&mut self,
                plan: &SourceMetadataPlanningPlan, case: &$case CaseRetirementState,
                level: usize) -> TableTransferResult<$case, $item>
            {
                let id = parent_id(level, $route).map_err(TableTransferFailure::Admission)?;
                self.transfer_metadata_table::<$item>(plan, case, id, TableCount::Parent(level))
            }
        }
    };
}
parent_table!(metadata_parent_plans<'case, 'source, 'a>: graph::ParentPlanResult<'source, 'a>, 0);
parent_table!(metadata_parent_compiled_outputs<'case, 'a>: RefCell<Option<graph::GraphCompiledResult<'a>>>, 1);
parent_table!(metadata_parent_outer_outputs<'case, 'a>: RefCell<Option<graph::GraphOuterResult<'a>>>, 2);
parent_table!(metadata_parent_preissues<'case, 'plan, 'source, 'a>:
    RefCell<Option<graph::ParentPreissueResult<'plan, 'source, 'a>>>, 3);

/// Pure typed forwarding census, never admission or a recursive plan query.
/// Counts/member inventory must already be derived under bootstrap inspection.
/// This remains in the installed original residual, separately from table splits.
pub(crate) fn producer_table_transfer_requirements(plan: &SourceMetadataPlanningPlan)
    -> Result<Requirements, WorkflowError>
{
    if plan.counts().parent_level(PARENT_LEVELS).is_some() {
        return Err(WorkflowError::Planning);
    }
    let mut total = ordinary_transfer_frames()?;
    add_frames(&mut total, reports::forwarding_requirements()?)?;
    add_frames(&mut total, final_runtime::forwarding_requirements()?)?;
    for level in 0..PARENT_LEVELS {
        if !plan.counts().parent_level(level).is_some_and(|n| n != 0) { continue; }
        add_frames(&mut total, transfer_frames::<graph::ParentPlanResult<'static, 'static>>()?)?;
        add_frames(&mut total, transfer_frames::<RefCell<Option<graph::GraphCompiledResult<'static>>>>()?)?;
        add_frames(&mut total, transfer_frames::<RefCell<Option<graph::GraphOuterResult<'static>>>>()?)?;
        add_frames(&mut total, transfer_frames::<RefCell<Option<graph::ParentPreissueResult<'static, 'static, 'static>>>>()?)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_table_ids_are_disjoint_through_the_last_parent_route() {
        let mut seen = [false; 256];
        for id in ORDINARY_IDS {
            assert!(id < PARENT_TABLE_BASE && !seen[id]);
            seen[id] = true;
        }
        // Complete result, final contract, and both request report tables.
        for id in [111, 112, 113, 114, 115, 116] {
            assert!(id < PARENT_TABLE_BASE && !seen[id]);
            seen[id] = true;
        }
        for level in 0..PARENT_LEVELS { for route in 0..4 {
            let id = parent_id(level, route).unwrap();
            assert!(id < seen.len() && !seen[id]);
            seen[id] = true;
        } }
        assert_eq!(parent_id(31, 3).unwrap(), 255);
        assert!(parent_id(32, 0).is_err());
        assert!(parent_id(0, 4).is_err());
        assert!(parent_id(usize::MAX, usize::MAX).is_err());
        assert_eq!(seen.into_iter().filter(|set| *set).count(), ORDINARY_TABLE_COUNT + 6 + 4 * PARENT_LEVELS);
    }
}
