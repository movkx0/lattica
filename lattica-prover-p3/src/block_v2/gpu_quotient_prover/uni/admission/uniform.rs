//! Core-only continuation of recorded SampleG/ExpandAlpha uniform metadata.
use super::*;
use crate::block_v2::native_gpu::uniform_preparation::UniformPreparationPlan;

pub(crate) fn prepared_from_closed_uniform(
    recorded: symbolic::RecordedUni,
    columns: Vec<Vec<Val>>,
    census: UniformPreparationPlan,
    operation_host_budget: usize,
) -> Result<Prepared, String> {
    let geometry = census.geometry();
    let expected = AirLayout {
        main_width: geometry.width(),
        num_public_values: geometry.public_values(),
        num_periodic_columns: geometry.periodic_columns(),
        ..AirLayout::default()
    };
    if !recorded.matches_layout(expected) || operation_host_budget == 0 {
        return Err("closed uniform preparation layout or PCS partition".into());
    }
    let host_allowance = census.host().prepared_partition_bytes()
        .map_err(|_| "closed uniform prepared partition")?
        .checked_add(operation_host_budget)
        .ok_or("closed uniform host allowance overflow")?;
    let shape = ProgramShape::for_recording(&recorded, Extension::Cubic)?;
    let periodic = periodic::uniform::from_columns(columns, census)?;
    let prepared = Prepared {
        recorded, shape, rows: geometry.rows(), host_allowance, periodic: Some(periodic),
    };
    prepared.check_host_allowance(host_allowance)?;
    if prepared.operation_host_allowance()? != operation_host_budget {
        return Err("closed uniform operation partition changed".into());
    }
    Ok(prepared)
}
