//! Consume the fixed borrowed-fill AES periodic owner; never call a provider.
use super::*;
use crate::block_v2::native_gpu::aes_preparation::AesPreparationPlan;

pub(in crate::block_v2::gpu_quotient_prover::uni::admission) fn from_columns(
    columns: Vec<Vec<Val>>,
    census: AesPreparationPlan,
) -> Result<Source, String> {
    let geometry = census.geometry();
    if columns.len() != 31
        || columns.capacity() != 31
        || geometry.periodic_columns() != 31
        || geometry.periodic_length() != 64
        || columns
            .iter()
            .any(|column| column.len() != 64 || column.capacity() != 64)
    {
        return Err("closed AES periodic geometry".into());
    }
    let shape = PeriodicShape::new(geometry.rows().ilog2(), columns.iter().map(Vec::len))?;
    Ok(Source {
        columns,
        shape,
        host_bytes: census.host().periodic_staging_bytes(),
    })
}
