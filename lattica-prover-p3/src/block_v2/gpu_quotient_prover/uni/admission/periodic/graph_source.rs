//! Consume internally constructed source columns; never call an AIR provider.
use super::*;
use crate::block_v2::native_gpu::graph_source_preparation::GraphSourcePreparationPlan;

pub(in crate::block_v2::gpu_quotient_prover::uni::admission) fn from_columns(
    columns: Vec<Vec<Val>>, census: GraphSourcePreparationPlan,
) -> Result<Source, String> {
    let geometry = census.geometry();
    let count = geometry.periodic_columns();
    if columns.len() != count || columns.capacity() != count || geometry.period() != 64
        || columns.iter().enumerate().any(|(index, column)| {
            column.len() != 64 || column.capacity() != 64 || column.iter().enumerate()
                .any(|(row, value)| geometry.periodic_value(index, row).as_ref() != Ok(value))
        })
    {
        return Err("closed graph-source periodic geometry or values".into());
    }
    let shape = PeriodicShape::new(geometry.rows().ilog2(), columns.iter().map(Vec::len))?;
    Ok(Source { columns, shape, host_bytes: census.host().periodic_staging_bytes })
}
