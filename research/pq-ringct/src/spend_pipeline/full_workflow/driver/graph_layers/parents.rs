use super::*;

fn interval(leaves: usize, level: usize, ordinal: usize) -> Result<(usize, usize)> {
    let block = 1usize.checked_shl(u32::try_from(level).map_err(|_| WorkflowError::Overflow)?)
        .ok_or(WorkflowError::Overflow)?;
    let first = block.checked_mul(ordinal).ok_or(WorkflowError::Overflow)?;
    let remaining = leaves.checked_sub(first).filter(|count| *count != 0).ok_or(WorkflowError::Identity)?;
    Ok((first, block.min(remaining)))
}

fn child<'view, 'graph: 'view>(prepared: &PreparedWorkflowSources<'_>, span: (usize, usize),
    leaves: LeafViews<'view, 'graph>, prior: PriorParentLevels<'view, 'graph>, ledger: &Ledger)
    -> Result<GraphChildSource<'view, 'graph>>
{
    if span.1 == 1 { return leaves.leaf(prepared, span.0, ledger); }
    let mut found = None;
    for level in prior.into_iter().flatten() {
        for ordinal in 0..level.len() {
            let child = level.child(ordinal, ledger)?;
            if views::same_node(child, prepared, span) {
                if found.is_some() { return Err(WorkflowError::Identity); }
                found = Some(child);
            }
        }
    }
    found.ok_or(WorkflowError::Identity)
}

/// Invoke once per level, after all original leaves and earlier levels exist.
/// The target owns its own concrete table; all prior references are immutable.
pub(crate) fn fill_parent_level<'case, 'metadata, 'source, 'graph: 'source>(planning: &mut WorkflowPlanning<'_>,
    plan: &SourceMetadataPlanningPlan<'metadata>, case: &CaseRetirementState, level: usize,
    leaves: LeafViews<'source, 'graph>, prior: PriorParentLevels<'source, 'graph>,
    cache: &'source OuterProofCache, target: &table::ParentPlanTable<'case, 'source, 'graph>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_parent_level");
    stage.level(level);
    run(planning, plan, case, |planning| {
        let count = plan.counts().parent_level(level).filter(|count| *count != 0).ok_or(WorkflowError::Planning)?;
        leaves.validate(plan, case)?;
        checked_table(target, case, count, true)?;
        for (index, actual) in prior.iter().enumerate() {
            match (index < level, plan.counts().parent_level(index), actual) {
                (true, Some(expected), Some(table)) if expected != 0
                    && table.owns_case(case) && table.len() == expected => (),
                (true, Some(0), None) | (false, _, None) => (),
                _ => return Err(WorkflowError::Identity),
            }
        }
        let block = 1usize.checked_shl(u32::try_from(level).map_err(|_| WorkflowError::Overflow)?)
            .ok_or(WorkflowError::Overflow)?;
        let mut ordinal = 0usize;
        for (member_ordinal, owner) in plan.members().iter().enumerate() {
            stage.member(member_ordinal);
            let prepared = owner.get();
            let length = prepared.plan().leaves().len();
            let width = (length / block).checked_add(usize::from(length % block != 0))
                .ok_or(WorkflowError::Overflow)?;
            for pair in 0..width / 2 {
                stage.ordinal(pair);
                stage.destination(ordinal);
                let left_index = pair.checked_mul(2).ok_or(WorkflowError::Overflow)?;
                let right_index = left_index.checked_add(1).ok_or(WorkflowError::Overflow)?;
                let left = child(prepared, interval(length, level, left_index)?, leaves, prior, plan.ledger())?;
                let right = child(prepared, interval(length, level, right_index)?, leaves, prior, plan.ledger())?;
                let slot = target.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                stage.action(DriverAction::Derive);
                let result = planning.derive_metadata_parent(plan, level, ordinal, [left, right], cache)?;
                stage.action(DriverAction::Install);
                install(slot, result)?;
                ordinal = ordinal.checked_add(1).ok_or(WorkflowError::Overflow)?;
            }
        }
        if ordinal != count { return Err(WorkflowError::Identity); }
        stage.action(DriverAction::Finish);
        populated(target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parent_driver_keeps_the_original_odd_tail_interval() {
        assert_eq!(interval(5, 0, 4).unwrap(), (4, 1));
        assert_eq!(interval(5, 1, 2).unwrap(), (4, 1));
        assert_eq!(interval(5, 2, 1).unwrap(), (4, 1));
        assert_eq!(interval(6, 2, 1).unwrap(), (4, 2));
        assert!(interval(5, 1, 3).is_err());
        assert!(interval(5, usize::BITS as usize, 0).is_err());
        assert!(interval(5, 1, usize::MAX).is_err());
    }
}
