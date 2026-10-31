//! Final scope/arrays and final constructors retain their original backing.
use crate::{
    execution::{retained_resources::{Bytes, Category, Requirements, Reservation},
        workflow_resources::{WorkflowPlanning, WorkflowError}},
    graph_crypto::OuterProofCache,
    graph_tree::owned_parent::GraphChildSource,
    ordered_aggregation::{Plan as AggregatePlan, Error as AggregateError,
        source::{FinalAggregationPlan, GraphSource}, owned_final::FinalPhasePlan},
    recursive_aggregation::LeafStatement,
    spend_pipeline::full_workflow::{
        fresh_generation::case_lifetime::{CaseOwnerTable, CaseRetirementState},
        metadata_planning::SourceMetadataPlanningPlan,
        metadata_tables::final_aggregation::{FinalSourceResult, FinalPlanResult},
    },
};
use super::super::producer_tables::{TableTransferFailure, TableTransferResult};
use core::mem::size_of;
use p3_field::PrimeField64;
use sha3::Sha3_256;

type Result<T> = core::result::Result<T, WorkflowError>;
pub(crate) type FinalContractResult<'a> = core::result::Result<OwnedFinalContract<'a>, FinalContractFailure<'a>>;
pub(crate) type FinalContractTable<'case, 'a> = CaseOwnerTable<'case, FinalContractResult<'a>>;

enum Members<'a> {
    N3 { graphs: [GraphSource<'a>; 3], statements: [LeafStatement; 3] },
    N4 { graphs: [GraphSource<'a>; 4], statements: [LeafStatement; 4] },
}

pub(crate) struct OwnedFinalContract<'a> {
    scope: AggregatePlan,
    members: Members<'a>,
    inventory: *const (),
    original: Reservation,
}

pub(crate) struct FinalContractFailure<'a> {
    error: AggregateError,
    members: Members<'a>,
    original: Reservation,
}

impl OwnedFinalContract<'_> {
    /// The complete inventory authenticates this actual owning table before
    /// accepting a final source plan which borrows its scope and fixed arrays.
    pub(crate) fn matches_final_source(&self, inventory: &SourceMetadataPlanningPlan<'_>,
        source: &FinalAggregationPlan<'_>, ledger: &crate::execution::retained_resources::Ledger,
    ) -> bool {
        self.matches(inventory, ledger) && source.belongs_to(ledger)
            && core::ptr::eq(source.scope(), &self.scope)
            && core::ptr::eq(source.graphs(), self.graphs())
    }

    pub(crate) fn matches_final_phase(&self, inventory: &SourceMetadataPlanningPlan<'_>,
        phase: &FinalPhasePlan<'_>, ledger: &crate::execution::retained_resources::Ledger,
    ) -> bool {
        self.matches_final_source(inventory, phase.source(), ledger) && phase.belongs_to(ledger)
            && core::ptr::eq(phase.statements(), self.statements())
    }

    fn graphs(&self) -> &[GraphSource<'_>] {
        match &self.members { Members::N3 { graphs, .. } => graphs, Members::N4 { graphs, .. } => graphs }
    }
    fn statements(&self) -> &[LeafStatement] {
        match &self.members { Members::N3 { statements, .. } => statements, Members::N4 { statements, .. } => statements }
    }
    fn matches(&self, inventory: &SourceMetadataPlanningPlan<'_>, ledger: &crate::execution::retained_resources::Ledger) -> bool {
        self.inventory == inventory as *const _ as *const () && self.original.belongs_to(ledger)
            && self.graphs().len() == inventory.members().len()
            && self.graphs().iter().zip(inventory.members()).all(|(graph, member)|
                core::ptr::eq(graph.plan, member.get().plan()) && core::ptr::eq(graph.context, member.get().context()))
    }
}

fn contract_requirements() -> Result<Requirements> {
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(AggregatePlan::owned_scope_heap_bytes()).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

/// Permanent envelope for table 112 and the actual aggregate-scope Arc.
/// Table backing owns the exact N3/N4 graph/statement arrays, both full result
/// variants and the returned owner; the separate original follows the Arc.
pub(super) fn retained_requirements() -> Result<Requirements> {
    let mut total = FinalContractTable::<'static, 'static>::requirements(1)
        .map_err(|_| WorkflowError::Planning)?;
    let scope = contract_requirements()?;
    for category in Category::ALL { total.add(category, scope.get(category))?; }
    Ok(total)
}

pub(super) fn requirements() -> Result<Requirements> {
    let bytes = [
        size_of::<Result<FinalSourceResult<'static>>>(), size_of::<Result<FinalPlanResult<'static>>>(),
        size_of::<FinalSourceResult<'static>>(), size_of::<FinalPlanResult<'static>>(),
        size_of::<TableTransferResult<'static, FinalContractResult<'static>>>(),
        size_of::<FinalContractResult<'static>>(), size_of::<OwnedFinalContract<'static>>(),
        size_of::<FinalContractFailure<'static>>(), size_of::<Members<'static>>(),
        size_of::<core::result::Result<AggregatePlan, AggregateError>>(), size_of::<Sha3_256>(),
        size_of::<[GraphSource<'static>; 4]>(), size_of::<[LeafStatement; 4]>(),
        size_of::<[GraphChildSource<'static, 'static>; 4]>(),
        size_of::<&mut WorkflowPlanning<'static>>(), size_of::<&SourceMetadataPlanningPlan<'static>>(),
        size_of::<&CaseRetirementState>(), size_of::<&OuterProofCache>(),
        size_of::<[Requirements; 3]>(), size_of::<Reservation>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<[usize; 4]>(), size_of::<Result<()>>(),
    ].into_iter().try_fold(0usize, |sum, n| sum.checked_add(n))
        .and_then(|n| n.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

fn with_frames(mut scratch: Requirements) -> Result<Requirements> {
    let frames = requirements()?;
    for category in Category::ALL { scratch.add(category, frames.get(category))?; }
    Ok(scratch)
}

impl WorkflowPlanning<'_> {
    /// A single named transfer installs the full contract result into its
    /// actual owning table before inspecting it. No scope escapes naked.
    pub(crate) fn derive_metadata_final_contract<'case, 'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, case: &'case CaseRetirementState,
    ) -> TableTransferResult<'case, FinalContractResult<'a>> {
        use TableTransferFailure::Admission;
        self.begin_metadata_table(inventory, case, 112).map_err(Admission)?;
        if !super::super::super::types::contains(self.scratch.requirements(), requirements().map_err(Admission)?) {
            return Err(Admission(WorkflowError::Planning));
        }
        let members = inventory.members();
        if !matches!(members.len(), 3 | 4) { return Err(Admission(WorkflowError::Planning)); }
        let profile = members[0].get().plan().label();
        let context = members[0].get().context().context;
        if members.iter().any(|member| member.get().plan().label() != profile || member.get().context().context != context) {
            return Err(Admission(WorkflowError::Identity));
        }
        let table_original = self.original.split(FinalContractTable::requirements(1)
            .map_err(|_| Admission(WorkflowError::Planning))?)
            .map_err(|e| Admission(e.into()))?;
        let table = FinalContractTable::from_original(case, 1, table_original)
            .map_err(TableTransferFailure::Construction)?;
        let original = self.original.split(contract_requirements().map_err(Admission)?)
            .map_err(|e| Admission(e.into()))?;
        let graph = |index: usize| GraphSource {
            plan: members[index].get().plan(), context: members[index].get().context(),
        };
        let statement = |index: usize| LeafStatement {
            profile, context, digest: members[index].get().context().statement.map(|v| v.as_canonical_u64()),
        };
        let owned = match members.len() {
            3 => Members::N3 { graphs: core::array::from_fn(graph), statements: core::array::from_fn(statement) },
            4 => Members::N4 { graphs: core::array::from_fn(graph), statements: core::array::from_fn(statement) },
            _ => unreachable!("checked fixed case count"),
        };
        let outcome = match AggregatePlan::new(profile, context, members.len() as u32) {
            Ok(scope) => Ok(OwnedFinalContract { scope, members: owned, inventory: inventory as *const _ as *const (), original }),
            Err(error) => Err(FinalContractFailure { error, members: owned, original }),
        };
        let slot = table.get(0).map_err(|_| Admission(WorkflowError::Planning))?;
        slot.install(outcome).map_err(|_| Admission(WorkflowError::Planning))?;
        if slot.get().map_err(|_| Admission(WorkflowError::Planning))?.is_ok() {
            self.finish_metadata_table_success();
        }
        Ok(table)
    }

    pub(crate) fn derive_metadata_final_source<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, contract: &'a OwnedFinalContract<'a>,
    ) -> Result<FinalSourceResult<'a>> {
        self.begin_metadata_final(inventory, 0)?;
        if !contract.matches(inventory, self.capability.ledger()) { return Err(WorkflowError::Identity); }
        let metadata = FinalAggregationPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let scratch = with_frames(FinalAggregationPlan::planning_scratch_requirements().map_err(|_| WorkflowError::Planning)?)?;
        if !super::super::super::types::contains(self.scratch.requirements(), scratch) { return Err(WorkflowError::Planning); }
        let original = self.original.split(metadata)?;
        let outcome = FinalAggregationPlan::derive_pre_reserved(&contract.scope, contract.graphs(),
            original, &self.scratch, self.capability.ledger());
        if outcome.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(outcome)
    }

    pub(crate) fn derive_metadata_final_phase<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, contract: &'a OwnedFinalContract<'a>,
        source: &'a FinalAggregationPlan<'a>, graph_producers: &[GraphChildSource<'a, 'a>],
        cache: &'a OuterProofCache,
    ) -> Result<FinalPlanResult<'a>> {
        self.begin_metadata_final(inventory, 1)?;
        if !contract.matches_final_source(inventory, source, self.capability.ledger()) {
            return Err(WorkflowError::Identity);
        }
        let metadata = FinalPhasePlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let scratch = with_frames(FinalPhasePlan::planning_scratch_requirements().map_err(|_| WorkflowError::Planning)?)?;
        if !super::super::super::types::contains(self.scratch.requirements(), scratch) { return Err(WorkflowError::Planning); }
        let original = self.original.split(metadata)?;
        let outcome = FinalPhasePlan::derive_pre_reserved(source, contract.statements(), graph_producers,
            cache, original, &self.scratch, self.capability.ledger());
        if outcome.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(outcome)
    }
}
