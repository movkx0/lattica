use super::*;
/// Borrowed projection of actual concrete graph output tables. No owner is
/// copied or erased, and parent levels retain separate original tables.
#[derive(Clone, Copy)]
pub(crate) struct GraphOutputs<'tables, 'case, 'graph> {
    pub(crate) fixed: &'tables FixedOuterOutputs<'case, 'graph>,
    pub(crate) source: &'tables SourceOuterOutputs<'case, 'graph>,
    pub(crate) affine: &'tables AffineOuterOutputs<'case, 'graph>,
    pub(crate) ntt: &'tables NttOuterOutputs<'case, 'graph>,
    pub(crate) mul: &'tables MulOuterOutputs<'case, 'graph>,
    pub(crate) g_bound: &'tables GBoundOuterOutputs<'case, 'graph>,
    pub(crate) permutation: &'tables PermutationOuterOutputs<'case, 'graph>,
    pub(crate) linear_map: &'tables LinearMapOuterOutputs<'case, 'graph>,
    pub(crate) parameters: &'tables ParametersOuterOutputs<'case, 'graph>,
    pub(crate) auxiliary: &'tables AuxiliaryOuterOutputs<'case, 'graph>,
    pub(crate) equality: &'tables EqualityOuterOutputs<'case, 'graph>,
    pub(crate) parents: [Option<&'tables ParentOuterOutputs<'case, 'graph>>; 32],
}
impl<'tables, 'case, 'graph> GraphOutputs<'tables, 'case, 'graph> {
    pub(crate) fn validate(&self, metadata: &SourceMetadataPlanningPlan<'_>,
        case: &CaseRetirementState) -> Result<()>
    { self.validate_counts(metadata.counts(), case) }
    pub(crate) fn validate_inventory(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState) -> Result<()>
    { self.validate_counts(inventory.producer_counts(), case) }
    fn validate_counts(&self, counts: ProducerCounts, case: &CaseRetirementState) -> Result<()>
    {
        self.distinct_tables()?;
        original_table(self.fixed, case, counts.family(ProducerFamily::Fixed))?;
        original_table(self.source, case, counts.family(ProducerFamily::Source))?;
        original_table(self.affine, case, counts.family(ProducerFamily::Affine))?;
        original_table(self.ntt, case, counts.family(ProducerFamily::Ntt))?;
        original_table(self.mul, case, counts.family(ProducerFamily::Mul))?;
        original_table(self.g_bound, case, counts.family(ProducerFamily::GBound))?;
        original_table(self.permutation, case, counts.family(ProducerFamily::Permutation))?;
        original_table(self.linear_map, case, counts.family(ProducerFamily::LinearMap))?;
        original_table(self.parameters, case, counts.family(ProducerFamily::Parameters))?;
        original_table(self.auxiliary, case, counts.family(ProducerFamily::Auxiliary))?;
        original_table(self.equality, case, counts.family(ProducerFamily::Equality))?;
        for (level, table) in self.parents.iter().enumerate() {
            let count = counts.parent_level(level).ok_or(WorkflowError::Identity)?;
            match (count, table) {
                (0, None) => (),
                (0, Some(_)) | (_, None) => return Err(WorkflowError::Identity),
                (_, Some(table)) => original_table(table, case, count)?,
            }
        }
        Ok(())
    }
    fn distinct_tables(&self) -> Result<()> {
        // These aliases have the same concrete table type. Validate actual
        // original-table identity before proof zero, even when counts match.
        let mut tables: [Option<&ParentOuterOutputs<'case, 'graph>>; 43] = [None; 43];
        tables[..11].copy_from_slice(&[
            Some(self.fixed),
            Some(self.source),
            Some(self.affine),
            Some(self.ntt),
            Some(self.mul),
            Some(self.g_bound),
            Some(self.permutation),
            Some(self.linear_map),
            Some(self.parameters),
            Some(self.auxiliary),
            Some(self.equality),
        ]);
        tables[11..].copy_from_slice(&self.parents);
        for (index, table) in tables.iter().enumerate() {
            let Some(table) = table else { continue; };
            if tables[..index].iter().flatten().any(|prior| core::ptr::eq(*prior, *table)) {
                return Err(WorkflowError::Identity);
            }
        }
        Ok(())
    }
    pub(crate) fn cell(&self, route: ProducerRoute)
        -> Result<&'tables RefCell<Option<GraphOuterResult<'graph>>>>
    {
        match route {
            ProducerRoute::Fixed { ordinal, phase: GraphPhase::Outer } => cell(self.fixed, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::Source, ordinal, phase: GraphPhase::Outer } => cell(self.source, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::Affine, ordinal, phase: GraphPhase::Outer } => cell(self.affine, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::Ntt, ordinal, phase: GraphPhase::Outer } => cell(self.ntt, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::Mul, ordinal, phase: GraphPhase::Outer } => cell(self.mul, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::GBound, ordinal, phase: GraphPhase::Outer } => cell(self.g_bound, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::Permutation, ordinal, phase: GraphPhase::Outer } => cell(self.permutation, ordinal),
            ProducerRoute::Leaf { family: LeafFamily::LinearMap, ordinal, phase: GraphPhase::Outer } => cell(self.linear_map, ordinal),
            ProducerRoute::Direct { family: DirectFamily::Parameters, ordinal, phase: GraphPhase::Outer } => cell(self.parameters, ordinal),
            ProducerRoute::Direct { family: DirectFamily::Auxiliary, ordinal, phase: GraphPhase::Outer } => cell(self.auxiliary, ordinal),
            ProducerRoute::Direct { family: DirectFamily::Equality, ordinal, phase: GraphPhase::Outer } => cell(self.equality, ordinal),
            ProducerRoute::Parent { level, ordinal, phase: GraphPhase::Outer } =>
                cell(self.parents.get(level).copied().flatten().ok_or(WorkflowError::Identity)?, ordinal),
            _ => Err(WorkflowError::Identity),
        }
    }
}
