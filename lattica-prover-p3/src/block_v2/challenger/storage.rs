//! Explicit backing for transcript batches and public scalar adapters. The
//! existing 1 MiB envelope covers these Rust buffers and allocation owners.
//! Session reservations compose concurrent operations and retained states;
//! caller-owned inputs, foreign allocations and escaped output lifetimes still
//! need their enclosing phase or caller to own their storage.
use super::{resources, DeviceSession, Val};
use p3_field::PrimeField64;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    pub bytes: usize,
}

fn vector<T>(count: usize) -> Result<usize, String> {
    count
        .checked_mul(core::mem::size_of::<T>())
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Vec<T>>()))
        .ok_or_else(|| "transcript host storage overflow".into())
}

impl Plan {
    fn new(buffers: &[usize]) -> Result<Self, String> {
        let bytes =
            buffers
                .iter()
                .try_fold(DeviceSession::transient_host_backing(), |sum, &bytes| {
                    sum.checked_add(bytes)
                        .ok_or("transcript host storage overflow")
                })?;
        let plan = Self { bytes };
        plan.admit(resources::HOST_BYTES)?;
        Ok(plan)
    }

    pub(crate) fn admit(self, allowance: usize) -> Result<(), String> {
        if self.bytes > allowance {
            return Err("transcript host storage exceeds allowance".into());
        }
        Ok(())
    }

    pub(crate) fn observation() -> Result<Self, String> {
        // The batch itself is fixed stack storage; include its full footprint.
        Self::new(&[vector::<u64>(resources::BATCH_WORDS)?])
    }

    pub(crate) fn grind() -> Result<Self, String> {
        Self::new(&[2 * core::mem::size_of::<u64>()])
    }

    pub(crate) fn sample(count: usize) -> Result<Self, String> {
        if !(1..=resources::BATCH_WORDS).contains(&count) {
            return Err("transcript sample host count exceeds admission".into());
        }
        Self::new(&[vector::<u64>(count)?, vector::<usize>(count)?])
    }

    pub(crate) fn scalar(input: usize, output: usize) -> Result<Self, String> {
        if input == 0
            || input > resources::SCALAR_OUTPUTS + 3
            || output == 0
            || output > resources::SCALAR_OUTPUTS * 3
        {
            return Err("scalar host words exceed admission".into());
        }
        Self::new(&[vector::<u64>(input)?, vector::<u64>(output)?])
    }

    pub(crate) fn next_points(count: usize, degree: usize) -> Result<Self, String> {
        if count > resources::SCALAR_OUTPUTS || !matches!(degree, 2 | 3) {
            return Err("next-point host shape exceeds admission".into());
        }
        Self::new(&[
            vector::<usize>(count)?,
            vector::<u64>(degree + count)?,
            vector::<u64>(degree * count)?,
            vector::<u64>(degree * count)?,
            3 * core::mem::size_of::<u64>(),
        ])
    }

    pub(crate) fn lookup(instances: usize, count: usize) -> Result<Self, String> {
        if instances > resources::SCALAR_OUTPUTS || count > resources::SCALAR_OUTPUTS {
            return Err("lookup host metadata exceeds admission".into());
        }
        // Conservatively overlap names, IDs, sampled fields, raw scalar words,
        // prefix tuples and final nested challenges, even across sequential
        // phases. Inner vector descriptors live in the counted outer arrays.
        Self::new(&[
            vector::<Vec<usize>>(instances)?,
            vector::<usize>(count)?,
            vector::<(&str, usize)>(count)?,
            vector::<Vec<super::super::profile::Challenge>>(instances)?,
            vector::<super::super::profile::Challenge>(2 * count)?,
            vector::<u64>(3 * count)?,
            vector::<[u64; 3]>(count)?,
            vector::<u64>(6)?,
            6 * core::mem::size_of::<u64>(),
        ])
    }

    pub(crate) fn domains(count: usize) -> Result<Self, String> {
        if count == 0 || count > resources::PARTITION_COSETS {
            return Err("domain host count exceeds admission".into());
        }
        Self::new(&[
            vector::<u64>(count)?,
            vector::<super::super::gpu_hash::device::DomainSpec>(count)?,
            2 * core::mem::size_of::<u64>(),
        ])
    }
}

/// Validate the maintained maximum shapes before composing the fixed envelope
/// into opening/FRI. No allocation, entropy draw, field arithmetic or GPU work.
pub(crate) fn reservation() -> Result<usize, String> {
    Plan::observation()?;
    Plan::grind()?;
    Plan::sample(resources::BATCH_WORDS)?;
    Plan::scalar(resources::SCALAR_OUTPUTS + 3, resources::SCALAR_OUTPUTS * 3)?;
    Plan::next_points(resources::SCALAR_OUTPUTS, 3)?;
    Plan::lookup(resources::SCALAR_OUTPUTS, resources::SCALAR_OUTPUTS)?;
    Plan::domains(resources::PARTITION_COSETS)?;
    Ok(resources::HOST_BYTES)
}

pub(crate) fn exact<T>(count: usize) -> Result<Vec<T>, String> {
    if (count != 0 && core::mem::size_of::<T>() == 0) || vector::<T>(count)? > resources::HOST_BYTES
    {
        return Err("transcript vector exceeds host allowance".into());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| "transcript host allocation failed")?;
    if output.capacity() != count {
        return Err("transcript host allocation exceeded exact capacity".into());
    }
    Ok(output)
}

pub(crate) fn zeroed_words(count: usize) -> Result<Vec<u64>, String> {
    let mut output = exact(count)?;
    output.resize(count, 0);
    Ok(output)
}

pub(crate) fn observe_batches(
    values: impl IntoIterator<Item = Val>,
    mut observe: impl FnMut(&[u64]) -> Result<(), String>,
) -> Result<(), String> {
    Plan::observation()?;
    let mut words = [0u64; resources::BATCH_WORDS];
    let mut values = values.into_iter();
    loop {
        let mut count = 0;
        for value in values.by_ref().take(resources::BATCH_WORDS) {
            words[count] = value.as_canonical_u64();
            count += 1;
        }
        observe(&words[..count])?;
        if count < resources::BATCH_WORDS {
            return Ok(());
        }
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
