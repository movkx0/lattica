use super::*;

pub(crate) fn fill_fixed_sources<'case, 'metadata: 'a, 'a>(planning: &mut WorkflowPlanning<'_>,
    plan: &SourceMetadataPlanningPlan<'metadata>, case: &CaseRetirementState,
    target: &table::FixedPlanTable<'case, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_fixed_sources");
    run(planning, plan, case, |_planning| {
        checked_table(target, case, plan.counts().family(ProducerFamily::Fixed), true)?;
        for member_ordinal in 0..plan.members().len() {
            stage.member(member_ordinal);
            let member = plan.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            stage.source(ProducerFamily::Fixed, 0);
            let ordinal = position(plan, member, ProducerFamily::Fixed, 0)?;
            stage.destination(ordinal);
            let slot = target.get(ordinal).map_err(|_| WorkflowError::Identity)?;
            // This constructor is allocation-free. Its entire returned Result
            // reaches the original-backed slot before status is inspected.
            stage.action(DriverAction::Derive);
            let result = SourceOperationPlan::fixed_sources(plan.scope(), member.prepared());
            stage.action(DriverAction::Install);
            install(slot, result)?;
        }
        stage.action(DriverAction::Finish);
        populated(target)
    })
}

pub(crate) fn fill_fixed_outer<'case, 'input_case, 'metadata, 'source, 'a>(planning: &mut WorkflowPlanning<'_>,
    plan: &SourceMetadataPlanningPlan<'metadata>, case: &CaseRetirementState,
    input: &'source table::FixedPlanTable<'input_case, 'a>, cache: &'source OuterProofCache,
    target: &table::FixedOuterPlanTable<'case, 'source, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_fixed_outer");
    run(planning, plan, case, |planning| {
        let count = plan.counts().family(ProducerFamily::Fixed);
        checked_table(input, case, count, false)?;
        populated(input)?;
        checked_table(target, case, count, true)?;
        for member_ordinal in 0..plan.members().len() {
            stage.member(member_ordinal);
            let member = plan.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            stage.source(ProducerFamily::Fixed, 0);
            let ordinal = position(plan, member, ProducerFamily::Fixed, 0)?;
            stage.destination(ordinal);
            let compiler = successful(input, ordinal)?;
            let slot = target.get(ordinal).map_err(|_| WorkflowError::Identity)?;
            stage.action(DriverAction::Derive);
            let result = planning.derive_metadata_fixed(plan, member, compiler, cache)?;
            stage.action(DriverAction::Install);
            install(slot, result)?;
        }
        stage.action(DriverAction::Finish);
        populated(target)
    })
}
