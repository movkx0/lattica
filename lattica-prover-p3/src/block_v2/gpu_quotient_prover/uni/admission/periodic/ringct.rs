//! Consume the fixed borrowed-fill periodic owner; never call a provider.
use super::*;
use crate::block_v2::native_gpu::shake_preparation::ShakePreparationPlan;

pub(in crate::block_v2::gpu_quotient_prover::uni::admission) fn from_columns(
    columns: Vec<Vec<Val>>,
    census: ShakePreparationPlan,
) -> Result<Source, String> {
    let geometry = census.geometry();
    if columns.len() != 42
        || columns.capacity() != 42
        || geometry.periodic_columns() != 42
        || geometry.periodic_length() != 128
        || columns
            .iter()
            .any(|column| column.len() != 128 || column.capacity() != 128)
    {
        return Err("closed SHAKE periodic geometry".into());
    }
    let shape = PeriodicShape::new(geometry.rows().ilog2(), columns.iter().map(Vec::len))?;
    Ok(Source {
        columns,
        shape,
        host_bytes: census.host().periodic_staging_bytes(),
    })
}
