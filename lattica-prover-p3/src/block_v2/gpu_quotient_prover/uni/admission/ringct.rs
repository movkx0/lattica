//! Core-only continuation from the closed, already recorded SHAKE source.
use super::*;
use crate::block_v2::native_gpu::shake_preparation::ShakePreparationPlan;

pub(crate) fn prepared_from_closed_shake(
    recorded: symbolic::RecordedUni,
    columns: Vec<Vec<Val>>,
    census: ShakePreparationPlan,
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
        return Err("closed SHAKE preparation layout or PCS partition".into());
    }
    let host_allowance = census
        .host()
        .prepared_partition_bytes()
        .map_err(|_| "closed SHAKE prepared partition")?
        .checked_add(operation_host_budget)
        .ok_or("closed SHAKE host allowance overflow")?;
    let shape = ProgramShape::for_recording(&recorded, Extension::Cubic)?;
    let periodic = periodic::ringct::from_columns(columns, census)?;
    let prepared = Prepared {
        recorded,
        shape,
        rows: geometry.rows(),
        host_allowance,
        periodic: Some(periodic),
    };
    prepared.check_host_allowance(host_allowance)?;
    if prepared.operation_host_allowance()? != operation_host_budget {
        return Err("closed SHAKE operation partition changed".into());
    }
    Ok(prepared)
}
