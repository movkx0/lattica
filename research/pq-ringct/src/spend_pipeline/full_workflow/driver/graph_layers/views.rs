//! Per-family sealed views preserve the graph lifetime across parent levels.
//! Each implementation reads one exact concrete owning Result table.
use super::*;
use crate::spend_pipeline::full_workflow::metadata_tables::algebra;

mod sealed {
    pub trait FixedChildren {} pub trait SourceChildren {} pub trait AffineChildren {}
    pub trait NttChildren {} pub trait MulChildren {} pub trait GBoundChildren {}
    pub trait PermutationChildren {} pub trait LinearMapChildren {} pub trait ParametersChildren {}
    pub trait AuxiliaryChildren {} pub trait EqualityChildren {} pub trait ParentChildren {}
}
macro_rules! child_view {
    ($trait:ident, $table:ty) => {
        pub(crate) trait $trait<'graph>: sealed::$trait {
            fn len(&self) -> usize;
            fn owns_case(&self, case: &CaseRetirementState) -> bool;
            fn child<'view>(&'view self, ordinal: usize, ledger: &Ledger)
                -> Result<GraphChildSource<'view, 'graph>> where 'graph: 'view;
        }
        impl<'case, 'source, 'graph> sealed::$trait for $table {}
        impl<'case, 'source, 'graph> $trait<'graph> for $table {
            fn len(&self) -> usize { self.slots().len() }
            fn owns_case(&self, case: &CaseRetirementState) -> bool { self.belongs_to_case(case) }
            fn child<'view>(&'view self, ordinal: usize, ledger: &Ledger)
                -> Result<GraphChildSource<'view, 'graph>> where 'graph: 'view
            {
                let plan = successful(self, ordinal)?;
                if !plan.belongs_to(ledger) { return Err(WorkflowError::Identity); }
                plan.child_source().map_err(|_| WorkflowError::Source)
            }
        }
    };
}
child_view!(FixedChildren, table::FixedOuterPlanTable<'case, 'source, 'graph>);
child_view!(SourceChildren, table::SourceOuterPlanTable<'case, 'source, 'graph>);
child_view!(AffineChildren, algebra::AffineOuterPlanTable<'case, 'source, 'graph>);
child_view!(NttChildren, algebra::NttOuterPlanTable<'case, 'source, 'graph>);
child_view!(MulChildren, algebra::MulOuterPlanTable<'case, 'source, 'graph>);
child_view!(GBoundChildren, algebra::GBoundOuterPlanTable<'case, 'source, 'graph>);
child_view!(PermutationChildren, algebra::PermutationOuterPlanTable<'case, 'source, 'graph>);
child_view!(LinearMapChildren, algebra::LinearMapOuterPlanTable<'case, 'source, 'graph>);
child_view!(ParametersChildren, table::ParametersPlanTable<'case, 'source, 'graph>);
child_view!(AuxiliaryChildren, table::AuxiliaryPlanTable<'case, 'source, 'graph>);
child_view!(EqualityChildren, table::EqualityPlanTable<'case, 'source, 'graph>);
child_view!(ParentChildren, table::ParentPlanTable<'case, 'source, 'graph>);

#[derive(Clone, Copy)]
pub(crate) struct LeafViews<'view, 'graph: 'view> {
    pub(crate) fixed: &'view dyn FixedChildren<'graph>,
    pub(crate) source: &'view dyn SourceChildren<'graph>,
    pub(crate) affine: &'view dyn AffineChildren<'graph>,
    pub(crate) ntt: &'view dyn NttChildren<'graph>,
    pub(crate) mul: &'view dyn MulChildren<'graph>,
    pub(crate) g_bound: &'view dyn GBoundChildren<'graph>,
    pub(crate) permutation: &'view dyn PermutationChildren<'graph>,
    pub(crate) linear_map: &'view dyn LinearMapChildren<'graph>,
    pub(crate) parameters: &'view dyn ParametersChildren<'graph>,
    pub(crate) auxiliary: &'view dyn AuxiliaryChildren<'graph>,
    pub(crate) equality: &'view dyn EqualityChildren<'graph>,
}
pub(crate) type PriorParentLevels<'view, 'graph> = [Option<&'view dyn ParentChildren<'graph>>; 32];

impl<'view, 'graph: 'view> LeafViews<'view, 'graph> {
    pub(super) fn validate(self, plan: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        macro_rules! check { ($field:ident, $family:ident) => {
            if !self.$field.owns_case(case) || self.$field.len() != plan.counts().family(ProducerFamily::$family) {
                return Err(WorkflowError::Identity);
            }
        }; }
        check!(fixed, Fixed); check!(source, Source); check!(affine, Affine); check!(ntt, Ntt);
        check!(mul, Mul); check!(g_bound, GBound); check!(permutation, Permutation); check!(linear_map, LinearMap);
        check!(parameters, Parameters); check!(auxiliary, Auxiliary); check!(equality, Equality);
        Ok(())
    }

    pub(super) fn leaf(self, prepared: &PreparedWorkflowSources<'_>, ordinal: usize, ledger: &Ledger)
        -> Result<GraphChildSource<'view, 'graph>>
    {
        let mut found = None;
        macro_rules! inspect { ($field:ident) => {
            for index in 0..self.$field.len() {
                let child = self.$field.child(index, ledger)?;
                if same_node(child, prepared, (ordinal, 1)) {
                    if found.is_some() { return Err(WorkflowError::Identity); }
                    found = Some(child);
                }
            }
        }; }
        inspect!(fixed); inspect!(source); inspect!(affine); inspect!(ntt); inspect!(mul); inspect!(g_bound);
        inspect!(permutation); inspect!(linear_map); inspect!(parameters); inspect!(auxiliary); inspect!(equality);
        found.ok_or(WorkflowError::Identity)
    }
}

pub(super) fn same_node(child: GraphChildSource<'_, '_>, prepared: &PreparedWorkflowSources<'_>,
    interval: (usize, usize)) -> bool
{
    let node = child.source();
    core::ptr::eq(node.graph_plan(), prepared.plan()) && core::ptr::eq(node.context(), prepared.context())
        && node.span().interval() == interval
}
