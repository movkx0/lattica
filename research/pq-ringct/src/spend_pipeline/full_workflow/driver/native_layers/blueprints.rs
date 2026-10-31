use super::*;
use crate::graph_tree::native_sources::NativeSourceBlueprint;
use crate::graph_tree::affine_sources::AffineLeafBlueprint;
use crate::graph_tree::ntt_sources::NttLeafBlueprint;
use crate::graph_tree::mul_sources::MulLeafBlueprint;
use crate::graph_tree::g_bound_sources::GBoundLeafBlueprint;
use crate::graph_tree::permutation_sources::PermutationLeafBlueprint;
use crate::graph_tree::linear_map_sources::LinearMapLeafBlueprint;
use lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind;

/// Pure blueprints borrow the same original source selected by each native plan.
pub(crate) fn fill_blueprint_layer<'case, 'a>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'a>,
    case: &CaseRetirementState, native: NativePlanTables<'_, 'case, 'a>,
    tables: BlueprintTables<'_, 'case, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_blueprint_layer");
    run_layer(planning, inventory, case, |_planning| {
        native.validate(inventory, case)?;
        native.finish()?;
        tables.validate_empty(inventory, case)?;
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            let prepared = member.prepared().get();
            for (source_ordinal, kind) in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof].into_iter().enumerate() {
                stage.source(ProducerFamily::Source, source_ordinal);
                let ordinal = position(inventory, member, ProducerFamily::Source, source_ordinal)?;
                stage.destination(ordinal);
                let input = successful(native.source, ordinal)?;
                if !core::ptr::eq(input.sources(), member.prepared())
                    || !core::ptr::eq(input.context(), inventory.context())
                    || input.kind() != kind || !input.belongs_to(inventory.ledger())
                { return Err(WorkflowError::Identity); }
                let slot = tables.source.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                stage.action(DriverAction::Derive);
                let result = NativeSourceBlueprint::new(prepared.plan(), prepared.graph(),
                    prepared.context(), prepared.source_factory(), kind);
                stage.action(DriverAction::Install);
                install(slot, result)?;
            }
            for (source_ordinal, batch) in prepared.algebra().batches().iter().enumerate() {
                stage.ordinal(source_ordinal);
                macro_rules! blueprint {
                    ($field:ident, $family:ident, $blueprint:ident) => {{
                        stage.source(ProducerFamily::$family, source_ordinal);
                        let ordinal = position(inventory, member, ProducerFamily::$family, source_ordinal)?;
                        stage.destination(ordinal);
                        let input = successful(native.$field, ordinal)?;
                        if !core::ptr::eq(input.sources(), member.prepared())
                            || !core::ptr::eq(input.context(), inventory.context())
                            || !core::ptr::eq(input.batch(), batch) || input.batch_ordinal() != source_ordinal
                            || !input.belongs_to(inventory.ledger())
                        { return Err(WorkflowError::Identity); }
                        let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                        stage.action(DriverAction::Derive);
                        let result = $blueprint::new(prepared.plan(), prepared.graph(), prepared.context(), input.source());
                        stage.action(DriverAction::Install);
                        install(slot, result)?;
                    }};
                }
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => blueprint!(affine, Affine, AffineLeafBlueprint),
                    Some(ProducerFamily::Ntt) => blueprint!(ntt, Ntt, NttLeafBlueprint),
                    Some(ProducerFamily::Mul) => blueprint!(mul, Mul, MulLeafBlueprint),
                    Some(ProducerFamily::GBound) => blueprint!(g_bound, GBound, GBoundLeafBlueprint),
                    Some(ProducerFamily::Permutation) => blueprint!(permutation, Permutation, PermutationLeafBlueprint),
                    Some(ProducerFamily::LinearMap) => blueprint!(linear_map, LinearMap, LinearMapLeafBlueprint),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
