use super::*;
use crate::{graph_auxiliary::{AuxiliaryRequest, Role},
    spend_pipeline::full_workflow::{uniform_native::UniformNativeOperationPlan,
        sparse_native::SparseNativeOperationPlan, transcript_native::TranscriptNativeOperationPlan}};

use crate::graph_tree::owned_parent::GraphParentFailure;

// Preserve the constructor Result in its original case slot before copying
// its fixed error for diagnostics. No owning plan or reservation is extracted.
fn install_auxiliary<T>(slot: &CaseOwnerSlot<'_, core::result::Result<T, GraphParentFailure>>,
    result: core::result::Result<T, GraphParentFailure>) -> Result<()>
{
    slot.install(result).map_err(|_| WorkflowError::Planning)?;
    slot.get().map_err(|_| WorkflowError::Planning)?.as_ref()
        .map_err(|cause| WorkflowError::AuxiliarySource(*cause))?;
    Ok(())
}

#[derive(Clone, Copy)]
// Crypto plans can be constructed after native compilers. Their invariant
// owning table payload lifetime need not equal the original native lifetime.
pub(crate) struct DirectDependencies<'view, 'case, 'crypto, 'native> {
    pub(crate) shake: &'view crypto_table::ShakePlanTable<'case, 'crypto>,
    pub(crate) aes: &'view crypto_table::AesPlanTable<'case, 'crypto>,
    pub(crate) uniform: &'view native_table::UniformPlanTable<'case, 'native>,
    pub(crate) sparse: &'view native_table::SparsePlanTable<'case, 'native>,
    pub(crate) transcript: &'view native_table::TranscriptPlanTable<'case, 'native>,
}
#[derive(Clone, Copy)]
pub(crate) struct DirectPlanTables<'view, 'case, 'source, 'a> {
    pub(crate) parameters: &'view table::ParametersPlanTable<'case, 'source, 'a>,
    pub(crate) auxiliary: &'view table::AuxiliaryPlanTable<'case, 'source, 'a>,
    pub(crate) equality: &'view table::EqualityPlanTable<'case, 'source, 'a>,
}

macro_rules! request_lookup {
    ($method:ident, $field:ident, $request:ty, $plan:ident, $payload:lifetime) => {
        fn $method<'a>(&self, request: &$request, ledger: &Ledger) -> Result<&'view $plan<'a>>
        where $payload: 'a, 'a: 'view
        {
            let mut found = None;
            for ordinal in 0..self.$field.slots().len() {
                // Only the immutable plan projection shortens. The invariant
                // owning table and its original reservations keep their scope.
                let plan: &'view $plan<'a> = successful(self.$field, ordinal)?;
                if core::ptr::eq(plan.request(), request) {
                    if found.is_some() || !plan.belongs_to(ledger) { return Err(WorkflowError::Identity); }
                    found = Some(plan);
                }
            }
            found.ok_or(WorkflowError::Identity)
        }
    };
}
impl<'view, 'crypto, 'native> DirectDependencies<'view, '_, 'crypto, 'native> {
    fn validate(&self, plan: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        macro_rules! input { ($field:ident, $family:ident) => {{
            checked_table(self.$field, case, plan.counts().family(ProducerFamily::$family), false)?;
            populated(self.$field)?;
        }}; }
        input!(shake, Shake); input!(aes, Aes); input!(uniform, Uniform);
        input!(sparse, Sparse); input!(transcript, Transcript);
        Ok(())
    }
    request_lookup!(shake, shake, Request, PairedRequestPlan, 'crypto);
    request_lookup!(aes, aes, Request, OwnedAesRequestPlan, 'crypto);
    request_lookup!(uniform, uniform, AuxiliaryRequest, UniformNativeOperationPlan, 'native);
    request_lookup!(sparse, sparse, AuxiliaryRequest, SparseNativeOperationPlan, 'native);
    request_lookup!(transcript, transcript, AuxiliaryRequest, TranscriptNativeOperationPlan, 'native);
}

fn crypto_request<'a>(member: MetadataMember<'_, 'a>, operation: usize, subrequest: u32)
    -> Result<&'a Request>
{
    let mut requests = member.prepared().get().crypto().requests().iter()
        .filter(|request| request.operation_index() == operation && request.subrequest() == subrequest);
    let result = requests.next().ok_or(WorkflowError::Identity)?;
    if requests.next().is_some() { return Err(WorkflowError::Identity); }
    Ok(result)
}
fn native_request<'a>(member: MetadataMember<'_, 'a>, operation: usize, role: Role)
    -> Result<&'a AuxiliaryRequest>
{
    let mut requests = member.prepared().get().auxiliary_factory().requests().iter()
        .filter(|request| request.operation_index() == operation && request.role() == role);
    let result = requests.next().ok_or(WorkflowError::Identity)?;
    if requests.next().is_some() { return Err(WorkflowError::Identity); }
    Ok(result)
}

fn auxiliary_sources<'metadata: 'a, 'crypto: 'a, 'native: 'a, 'source, 'a: 'source>(
    plan: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
    ordinal: usize, inputs: DirectDependencies<'source, '_, 'crypto, 'native>) -> Result<AuxiliaryGraphSources<'source, 'a>>
{
    let inventory: AuxiliaryPreparedInventory<'a> = AuxiliaryPreparedInventory::new(member.prepared(), ordinal)
        .map_err(|_| WorkflowError::Identity)?;
    let operation = inventory.operation_index();
    let ledger = plan.ledger();
    let sources = match inventory.kind() {
        AuxiliaryGraphKind::SampleG => AuxiliaryGraphSources::SampleG {
            aes: inputs.aes(crypto_request(member, operation, 0)?, ledger)?,
            uniform: inputs.uniform(native_request(member, operation, Role::SampleGUniform)?, ledger)?,
        },
        AuxiliaryGraphKind::ExpandAlpha => AuxiliaryGraphSources::ExpandAlpha {
            uniform_aes: inputs.aes(crypto_request(member, operation, 0)?, ledger)?,
            sparse_aes: inputs.aes(crypto_request(member, operation, 1)?, ledger)?,
            uniform: inputs.uniform(native_request(member, operation, Role::AlphaUniform)?, ledger)?,
            sparse: inputs.sparse(native_request(member, operation, Role::AlphaSparse)?, ledger)?,
        },
        AuxiliaryGraphKind::HashAlpha => AuxiliaryGraphSources::HashAlpha {
            shake: inputs.shake(crypto_request(member, operation, 0)?, ledger)?,
            transcript: inputs.transcript(native_request(member, operation, Role::HashAlphaTranscript)?, ledger)?,
        },
        AuxiliaryGraphKind::HashX => AuxiliaryGraphSources::HashX {
            shake: inputs.shake(crypto_request(member, operation, 0)?, ledger)?,
            transcript: inputs.transcript(native_request(member, operation, Role::HashXTranscript)?, ledger)?,
            sparse: inputs.sparse(native_request(member, operation, Role::HashXSparse)?, ledger)?,
        },
    };
    inventory.validate_plans(sources, plan.context()).map_err(|_| WorkflowError::Identity)?;
    Ok(sources)
}

pub(crate) fn fill_direct_leaves<'case, 'input_case, 'metadata: 'a, 'crypto: 'a, 'native: 'a, 'source, 'a: 'source>(
    planning: &mut WorkflowPlanning<'_>, plan: &SourceMetadataPlanningPlan<'metadata>, case: &CaseRetirementState,
    inputs: DirectDependencies<'source, 'input_case, 'crypto, 'native>, cache: &'source OuterProofCache,
    target: DirectPlanTables<'_, 'case, 'source, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_direct_leaves");
    run(planning, plan, case, |planning| {
        inputs.validate(plan, case)?;
        checked_table(target.parameters, case, plan.counts().family(ProducerFamily::Parameters), true)?;
        checked_table(target.auxiliary, case, plan.counts().family(ProducerFamily::Auxiliary), true)?;
        checked_table(target.equality, case, plan.counts().family(ProducerFamily::Equality), true)?;
        for member_ordinal in 0..plan.members().len() {
            stage.member(member_ordinal);
            let member = plan.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            for (leaf_ordinal, leaf) in member.prepared().get().plan().leaves().iter().enumerate().skip(3) {
                stage.ordinal(leaf_ordinal);
                let LeafKind::Operations(family) = leaf.kind() else { return Err(WorkflowError::Identity); };
                match family {
                    OperationFamily::ParametersPp => {
                        stage.source(ProducerFamily::Parameters, leaf_ordinal);
                        stage.action(DriverAction::Inputs);
                        let [operation] = leaf.operation_indices() else { return Err(WorkflowError::Identity); };
                        let request = inputs.shake(crypto_request(member, *operation, 0)?, plan.ledger())?;
                        stage.source(ProducerFamily::Parameters, leaf_ordinal);
                        let ordinal = position(plan, member, ProducerFamily::Parameters, leaf_ordinal)?;
                        stage.destination(ordinal);
                        let slot = target.parameters.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                        stage.action(DriverAction::Derive);
                        let result = planning.derive_metadata_parameters(plan, member, leaf_ordinal, request, cache)?;
                        stage.action(DriverAction::Install);
                        install(slot, result)?;
                    }
                    OperationFamily::SampleG | OperationFamily::ExpandAlpha | OperationFamily::HashAlpha | OperationFamily::HashX => {
                        stage.source(ProducerFamily::Auxiliary, leaf_ordinal);
                        stage.action(DriverAction::Inputs);
                        let sources = auxiliary_sources(plan, member, leaf_ordinal, inputs)?;
                        stage.source(ProducerFamily::Auxiliary, leaf_ordinal);
                        let ordinal = position(plan, member, ProducerFamily::Auxiliary, leaf_ordinal)?;
                        stage.destination(ordinal);
                        let slot = target.auxiliary.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                        stage.action(DriverAction::Derive);
                        let result = planning.derive_metadata_auxiliary(plan, member, leaf_ordinal, sources, cache)?;
                        stage.action(DriverAction::Install);
                        install_auxiliary(slot, result)?;
                    }
                    OperationFamily::Equality => {
                        stage.source(ProducerFamily::Equality, leaf_ordinal);
                        let ordinal = position(plan, member, ProducerFamily::Equality, leaf_ordinal)?;
                        stage.destination(ordinal);
                        let slot = target.equality.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                        stage.action(DriverAction::Derive);
                        let result = planning.derive_metadata_equality(plan, member, leaf_ordinal, cache)?;
                        stage.action(DriverAction::Install);
                        install(slot, result)?;
                    }
                    OperationFamily::Affine { .. } | OperationFamily::Ntt { .. } | OperationFamily::Mul { .. }
                    | OperationFamily::GBound | OperationFamily::Permutation | OperationFamily::LinearMap => (),
                }
            }
        }
        populated(target.parameters)?; populated(target.auxiliary)?; populated(target.equality)
    })
}
