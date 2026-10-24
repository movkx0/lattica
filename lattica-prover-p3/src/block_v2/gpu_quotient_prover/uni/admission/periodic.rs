//! Construct static periodic tables within an admitted storage allowance before
//! GPU arithmetic. Internal providers expose allocation-free geometry and fill
//! borrowed slices; the owned AIR table generator is never invoked here.
use super::*;
use crate::block_v2::gpu_hash::device::PeriodicShape;

pub(in crate::block_v2::gpu_quotient_prover::uni) struct Source {
    columns: Vec<Vec<Val>>,
    shape: PeriodicShape,
    host_bytes: usize,
}

impl Source {
    pub(super) fn new<A: Air<symbolic::Builder> + StaticPeriodicSource>(
        air: &A,
        rows: usize,
        allowance: usize,
    ) -> Result<Option<Self>, String> {
        Self::new_with_source(air, air, rows, allowance)
    }

    pub(super) fn new_with_source<A: Air<symbolic::Builder>, S: StaticPeriodicSource + ?Sized>(
        air: &A,
        source: &S,
        rows: usize,
        allowance: usize,
    ) -> Result<Option<Self>, String> {
        if !rows.is_power_of_two() {
            return Err("invalid periodic trace height".into());
        }
        let count = source.count();
        if count != air.num_periodic_columns() {
            return Err("periodic column count differs from AIR layout".into());
        }
        if count == 0 {
            return Ok(None);
        }
        // Validate every length and the total before allocating any table or
        // metadata. A missing column maps to the invalid zero-length period.
        let shape = PeriodicShape::new(
            rows.ilog2(),
            (0..count).map(|index| source.len(index).unwrap_or(0)),
        )?;
        // Retained fields, canonical word columns and flattened upload data,
        // both outer vectors, offset/length metadata, and captured lengths.
        // Summing both construction and expansion scratch is conservative.
        let staging = shape
            .input_words()
            .checked_mul(core::mem::size_of::<Val>() + 2 * core::mem::size_of::<u64>())
            .and_then(|n| {
                count
                    .checked_mul(
                        core::mem::size_of::<Vec<Val>>()
                            + core::mem::size_of::<Vec<u64>>()
                            + core::mem::size_of::<usize>(),
                    )
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                shape
                    .metadata_words()
                    .checked_mul(core::mem::size_of::<u64>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or("periodic host staging overflow")?;
        if staging > allowance {
            return Err("periodic source capacity and staging exceed host allowance".into());
        }
        let mut lengths = reserved(count)?;
        for index in 0..count {
            lengths.push(
                source
                    .len(index)
                    .ok_or("periodic source metadata changed")?,
            );
        }
        if PeriodicShape::new(rows.ilog2(), lengths.iter().copied())? != shape {
            return Err("periodic source metadata changed".into());
        }
        let mut columns = reserved(count)?;
        for &len in &lengths {
            let mut column = reserved(len)?;
            column.resize(len, Val::ZERO);
            columns.push(column);
        }
        // Validate the complete captured layout again before any fill callback.
        if source.count() != count
            || air.num_periodic_columns() != count
            || lengths
                .iter()
                .enumerate()
                .any(|(i, &len)| source.len(i) != Some(len))
        {
            return Err("periodic source metadata changed".into());
        }
        for (index, column) in columns.iter_mut().enumerate() {
            source
                .fill(index, column)
                .map_err(|e| format!("periodic source fill: {e:?}"))?;
        }
        Ok(Some(Self {
            columns,
            shape,
            host_bytes: staging,
        }))
    }
    pub(in crate::block_v2::gpu_quotient_prover::uni) fn columns(&self) -> &[Vec<Val>] {
        &self.columns
    }
    pub(super) fn shape(&self) -> PeriodicShape {
        self.shape
    }
    pub(super) fn host_bytes(&self) -> usize {
        self.host_bytes
    }
}

fn reserved<T>(count: usize) -> Result<Vec<T>, String> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| "periodic source allocation failed")?;
    if output.capacity() != count {
        return Err("periodic source capacity exceeds admitted storage".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
