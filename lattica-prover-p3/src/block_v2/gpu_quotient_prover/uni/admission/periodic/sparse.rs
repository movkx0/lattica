//! Consume internally constructed source columns; never call an AIR provider.
use super::*;
use crate::block_v2::native_gpu::sparse_preparation::SparsePreparationPlan;

pub(in crate::block_v2::gpu_quotient_prover::uni::admission) fn from_columns(
    columns: Vec<Vec<Val>>, census: SparsePreparationPlan,
) -> Result<Source, String> {
    let geometry = census.geometry();
    let count = geometry.periodic_columns();
    if columns.len() != count || columns.capacity() != count || geometry.periodic_values() != 6720
        || columns.iter().enumerate().any(|(index, column)| {
            geometry.periodic_length(index).as_ref() != Ok(&column.len()) || column.capacity() != column.len() || column.iter().enumerate()
                .any(|(row, value)| geometry.periodic_value(index, row).as_ref() != Ok(value))
        })
    {
        return Err("closed sparse periodic geometry or values".into());
    }
    let shape = PeriodicShape::new(geometry.rows().ilog2(), columns.iter().map(Vec::len))?;
    Ok(Source { columns, shape, host_bytes: census.host().periodic_staging_bytes })
}
