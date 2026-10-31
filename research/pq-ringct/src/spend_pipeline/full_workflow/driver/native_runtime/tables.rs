use super::*;

/// Concrete case-owned tables, borrowed without copying or moving payloads.
#[derive(Clone, Copy)]
pub(crate) struct NativeOutputs<'tables, 'case, 'a> {
    pub(crate) source: &'tables native_tables::SourceNativeOutputs<'case, 'a>,
    pub(crate) uniform: &'tables native_tables::UniformNativeOutputs<'case, 'a>,
    pub(crate) sparse: &'tables native_tables::SparseNativeOutputs<'case, 'a>,
    pub(crate) transcript: &'tables native_tables::TranscriptNativeOutputs<'case, 'a>,
    pub(crate) affine: &'tables native_tables::AffineNativeOutputs<'case, 'a>,
    pub(crate) ntt: &'tables native_tables::NttNativeOutputs<'case, 'a>,
    pub(crate) mul: &'tables native_tables::MulNativeOutputs<'case, 'a>,
    pub(crate) g_bound: &'tables native_tables::GBoundNativeOutputs<'case, 'a>,
    pub(crate) permutation: &'tables native_tables::PermutationNativeOutputs<'case, 'a>,
    pub(crate) linear_map: &'tables native_tables::LinearMapNativeOutputs<'case, 'a>,
}

/// Concrete case-owned tables, borrowed without copying or moving payloads.
#[derive(Clone, Copy)]
pub(crate) struct NativePackets<'tables, 'case, 'plans, 'a> {
    pub(crate) source: &'tables native_tables::SourceNativePreissues<'case, 'plans, 'a>,
    pub(crate) uniform: &'tables native_tables::UniformNativePreissues<'case, 'plans, 'a>,
    pub(crate) sparse: &'tables native_tables::SparseNativePreissues<'case, 'plans, 'a>,
    pub(crate) transcript: &'tables native_tables::TranscriptNativePreissues<'case, 'plans, 'a>,
    pub(crate) affine: &'tables native_tables::AffineNativePreissues<'case, 'plans, 'a>,
    pub(crate) ntt: &'tables native_tables::NttNativePreissues<'case, 'plans, 'a>,
    pub(crate) mul: &'tables native_tables::MulNativePreissues<'case, 'plans, 'a>,
    pub(crate) g_bound: &'tables native_tables::GBoundNativePreissues<'case, 'plans, 'a>,
    pub(crate) permutation: &'tables native_tables::PermutationNativePreissues<'case, 'plans, 'a>,
    pub(crate) linear_map: &'tables native_tables::LinearMapNativePreissues<'case, 'plans, 'a>,
}

/// Concrete case-owned tables, borrowed without copying or moving payloads.
#[derive(Clone, Copy)]
pub(crate) struct CompiledOutputs<'tables, 'case, 'a> {
    pub(crate) source: &'tables graph_tables::SourceCompiledOutputs<'case, 'a>,
    pub(crate) affine: &'tables algebra_tables::AffineCompiledOutputs<'case, 'a>,
    pub(crate) ntt: &'tables algebra_tables::NttCompiledOutputs<'case, 'a>,
    pub(crate) mul: &'tables algebra_tables::MulCompiledOutputs<'case, 'a>,
    pub(crate) g_bound: &'tables algebra_tables::GBoundCompiledOutputs<'case, 'a>,
    pub(crate) permutation: &'tables algebra_tables::PermutationCompiledOutputs<'case, 'a>,
    pub(crate) linear_map: &'tables algebra_tables::LinearMapCompiledOutputs<'case, 'a>,
}

/// Concrete case-owned tables, borrowed without copying or moving payloads.
#[derive(Clone, Copy)]
pub(crate) struct OuterOutputs<'tables, 'case, 'a> {
    pub(crate) source: &'tables graph_tables::SourceOuterOutputs<'case, 'a>,
    pub(crate) affine: &'tables graph_tables::AffineOuterOutputs<'case, 'a>,
    pub(crate) ntt: &'tables graph_tables::NttOuterOutputs<'case, 'a>,
    pub(crate) mul: &'tables graph_tables::MulOuterOutputs<'case, 'a>,
    pub(crate) g_bound: &'tables graph_tables::GBoundOuterOutputs<'case, 'a>,
    pub(crate) permutation: &'tables graph_tables::PermutationOuterOutputs<'case, 'a>,
    pub(crate) linear_map: &'tables graph_tables::LinearMapOuterOutputs<'case, 'a>,
}

/// Concrete case-owned tables, borrowed without copying or moving payloads.
#[derive(Clone, Copy)]
pub(crate) struct OuterPackets<'tables, 'case, 'plans, 'source, 'a> {
    pub(crate) source: &'tables graph_tables::SourceOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) affine: &'tables algebra_tables::AffineOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) ntt: &'tables algebra_tables::NttOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) mul: &'tables algebra_tables::MulOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) g_bound: &'tables algebra_tables::GBoundOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) permutation: &'tables algebra_tables::PermutationOuterPreissues<'case, 'plans, 'source, 'a>,
    pub(crate) linear_map: &'tables algebra_tables::LinearMapOuterPreissues<'case, 'plans, 'source, 'a>,
}

impl OuterOutputs<'_, '_, '_> {
    /// These seven aliases have the same payload type. Reject duplicate table
    /// identities before installing even the first runtime cell.
    pub(super) fn distinct(&self) -> Result<()> {
        let tables = [self.source, self.affine, self.ntt, self.mul, self.g_bound,
            self.permutation, self.linear_map];
        for (index, table) in tables.iter().enumerate() {
            if tables[..index].iter().any(|other| core::ptr::eq(*table, *other)) {
                return Err(WorkflowError::Identity);
            }
        }
        Ok(())
    }
}
