//! Consume internally constructed source columns; never call an AIR provider.
use super::*;
use crate::block_v2::native_gpu::mul_preparation::MulPreparationPlan;

pub(in crate::block_v2::gpu_quotient_prover::uni::admission) fn from_columns(
    columns: Vec<Vec<Val>>, census: MulPreparationPlan,
) -> Result<Source, String> {
    let geometry = census.geometry();
    let count = geometry.periodic_columns();
    if columns.len() != count || columns.capacity() != count || geometry.period() != geometry.rows()
        || columns.iter().enumerate().any(|(index, column)| {
            column.len() != geometry.period() || column.capacity() != geometry.period() || column.iter().enumerate()
                .any(|(row, value)| geometry.periodic_value(index, row).as_ref() != Ok(value))
        })
    {
        return Err("closed mul periodic geometry or values".into());
    }
    let shape = PeriodicShape::new(geometry.rows().ilog2(), columns.iter().map(Vec::len))?;
    Ok(Source { columns, shape, host_bytes: census.host().periodic_staging_bytes })
}
