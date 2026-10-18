//! Challenge-derived arithmetic remains on CUDA. Host inputs are bounded public
//! indices, dimensions and immutable root constants, never derived field values.
use super::{Argument, Buffer, FieldSpan, Kernel, Launch, Result, Runtime};
use crate::{
    gpu_matrix::{roots, DomainSpec, Extension},
    transcript_limits as limits,
};
use std::sync::Arc;

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("scalars.cu"));

pub(crate) struct Scalars {
    pub(super) runtime: Runtime,
    powers: Kernel,
    lookup: Kernel,
    next: Kernel,
    domains: Kernel,
}

/// Only the common subgroup size is host metadata. The shifts stay resident.
pub(crate) struct DomainValues {
    pub log_size: usize,
    pub shifts: Buffer,
}

/// Public bus mapping and fresh output backing, prepared before sampling.
/// Consumed exactly once; sampled challenges are never retained in a cache.
pub(crate) struct PreparedLookup {
    engine: Arc<Scalars>,
    ids: Buffer,
    output: Buffer,
    width: u32,
    count: usize,
    extension: Extension,
}

fn words(count: usize, extension: Extension) -> Result<usize> {
    if !(1..=limits::SCALAR_OUTPUTS).contains(&count) {
        return Err("CUDA scalar count exceeds allowance".into());
    }
    count
        .checked_mul(extension.degree())
        .ok_or_else(|| "CUDA scalar size overflow".into())
}

fn lookup_width(width: usize) -> Result<u32> {
    if width == 0 || width > u32::MAX as usize {
        return Err("CUDA lookup tuple width exceeds allowance".into());
    }
    Ok(width as u32)
}

fn launch(count: usize) -> Launch {
    Launch {
        blocks: count.div_ceil(128) as u32,
        threads: 128,
        shared_bytes: 0,
    }
}

impl Scalars {
    pub(crate) fn new(runtime: &Runtime) -> Result<Arc<Self>> {
        let module = runtime.compile(SOURCE)?;
        let result = Self {
            runtime: runtime.clone(),
            powers: module.kernel("scalar_powers")?,
            lookup: module.kernel("scalar_lookup")?,
            next: module.kernel("scalar_next_points")?,
            domains: module.kernel("scalar_domain_shifts")?,
        };
        for kernel in [
            &result.powers,
            &result.lookup,
            &result.next,
            &result.domains,
        ] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA scalar kernel exceeds private memory allowance".into());
            }
        }
        Ok(Arc::new(result))
    }

    fn admit(&self, allocations: &[usize]) -> Result<()> {
        let current = self.runtime.snapshot();
        super::transcript::admission(
            allocations,
            current.live_bytes,
            current.allocations,
            self.runtime.state.budget.limits,
        )?;
        Ok(())
    }

    fn input(&self, input: FieldSpan<'_>, count: usize) -> Result<()> {
        if !Arc::ptr_eq(input.buffer.owner(), &self.runtime.state)
            || input
                .first
                .checked_add(count)
                .is_none_or(|end| end > input.buffer.len())
        {
            return Err("CUDA scalar input has invalid ownership or range".into());
        }
        drop(self.runtime.state.enter()?);
        Ok(())
    }

    pub(crate) fn powers(
        &self,
        input: FieldSpan<'_>,
        extension: Extension,
        first_exponent: u64,
        count: usize,
    ) -> Result<Buffer> {
        let output_words = words(count, extension)?;
        first_exponent
            .checked_add(count as u64 - 1)
            .ok_or("CUDA scalar exponent overflow")?;
        self.input(input, extension.degree())?;
        self.admit(&[output_words])?;
        let output = self.runtime.allocate(output_words)?;
        // Input bounds, output size, and exponent addition are checked above.
        unsafe {
            self.powers.launch(
                launch(count),
                &[
                    Argument::Buffer(input.buffer),
                    Argument::Buffer(&output),
                    Argument::U64(input.first as u64),
                    Argument::U64(first_exponent),
                    Argument::U32(count as u32),
                    Argument::U32(extension.degree() as u32),
                ],
            )?
        }
        .finish()?;
        Ok(output)
    }

    pub(crate) fn lookup_prefixes(
        &self,
        sampled: FieldSpan<'_>,
        extension: Extension,
        width: usize,
        buses: usize,
    ) -> Result<Buffer> {
        let width = lookup_width(width)?;
        let output_words = words(buses, extension)?;
        self.input(sampled, 2 * extension.degree())?;
        self.admit(&[output_words])?;
        let output = self.runtime.allocate(output_words)?;
        // The unmapped variant does not read the placeholder IDs argument.
        unsafe {
            self.lookup.launch(
                launch(buses),
                &[
                    Argument::Buffer(sampled.buffer),
                    Argument::Buffer(sampled.buffer),
                    Argument::Buffer(&output),
                    Argument::U64(sampled.first as u64),
                    Argument::U32(width),
                    Argument::U32(buses as u32),
                    Argument::U32(extension.degree() as u32),
                    Argument::U32(0),
                ],
            )?
        }
        .finish()?;
        Ok(output)
    }

    pub(crate) fn prepare_lookup(
        self: &Arc<Self>,
        extension: Extension,
        width: usize,
        ids: &[usize],
    ) -> Result<PreparedLookup> {
        let width = lookup_width(width)?;
        let output_words = 2 * words(ids.len(), extension)?;
        if ids.iter().any(|&id| id >= limits::SCALAR_OUTPUTS) {
            return Err("CUDA lookup bus index exceeds allowance".into());
        }
        // Include the upcoming alpha/beta sample in whole-operation admission.
        self.admit(&[ids.len(), output_words, 2 * extension.degree()])?;
        let mapping = self.runtime.allocate(ids.len())?;
        let output = self.runtime.allocate(output_words)?;
        let mut public_ids = [0u64; limits::SCALAR_OUTPUTS];
        for (word, &id) in public_ids.iter_mut().zip(ids) {
            *word = id as u64;
        }
        mapping.write(0, &public_ids[..ids.len()])?;
        Ok(PreparedLookup {
            engine: self.clone(),
            ids: mapping,
            output,
            width,
            count: ids.len(),
            extension,
        })
    }

    pub(crate) fn next_points(
        &self,
        point: FieldSpan<'_>,
        extension: Extension,
        log_sizes: &[u32],
    ) -> Result<Buffer> {
        let output_words = words(log_sizes.len(), extension)?;
        if log_sizes.iter().any(|&log| log > 32) {
            return Err("CUDA next-point domain exceeds two-adicity".into());
        }
        self.input(point, extension.degree())?;
        self.admit(&[log_sizes.len(), output_words])?;
        let constants = self.runtime.allocate(log_sizes.len())?;
        let output = self.runtime.allocate(output_words)?;
        let mut selected = [0u64; limits::SCALAR_OUTPUTS];
        for (word, &log) in selected.iter_mut().zip(log_sizes) {
            *word = roots::root(log);
        }
        constants.write(0, &selected[..log_sizes.len()])?;
        // The host selects immutable roots only; multiplication runs on CUDA.
        unsafe {
            self.next.launch(
                launch(log_sizes.len()),
                &[
                    Argument::Buffer(point.buffer),
                    Argument::Buffer(&constants),
                    Argument::Buffer(&output),
                    Argument::U64(point.first as u64),
                    Argument::U32(log_sizes.len() as u32),
                    Argument::U32(extension.degree() as u32),
                ],
            )?
        }
        .finish()?;
        Ok(output)
    }

    fn domain_shifts(
        &self,
        domain: DomainSpec,
        log_size: usize,
        root: u64,
        first: u32,
        count: usize,
    ) -> Result<DomainValues> {
        self.admit(&[count])?;
        let shifts = self.runtime.allocate(count)?;
        // Public metadata is validated by DomainSpec and the two callers below.
        unsafe {
            self.domains.launch(
                launch(count),
                &[
                    Argument::Buffer(&shifts),
                    Argument::U64(domain.shift_word()),
                    Argument::U64(root),
                    Argument::U32(first),
                    Argument::U32(count as u32),
                ],
            )?
        }
        .finish()?;
        Ok(DomainValues { log_size, shifts })
    }

    pub(crate) fn split_domains(&self, domain: DomainSpec, chunks: usize) -> Result<DomainValues> {
        if !chunks.is_power_of_two() || chunks > limits::PARTITION_COSETS || chunks > domain.size()
        {
            return Err("CUDA domain partition exceeds allowance".into());
        }
        self.domain_shifts(
            domain,
            domain.log_size() - chunks.ilog2() as usize,
            roots::root(domain.log_size() as u32),
            0,
            chunks,
        )
    }

    pub(crate) fn disjoint_domain(
        &self,
        domain: DomainSpec,
        log_size: usize,
    ) -> Result<DomainValues> {
        DomainSpec::new(domain.shift_word(), log_size)?;
        self.domain_shifts(domain, log_size, 7, 1, 1)
    }
}

impl PreparedLookup {
    pub(crate) fn finish(self, sampled: &Buffer) -> Result<Buffer> {
        if sampled.len() != 2 * self.extension.degree() {
            return Err("CUDA lookup requires exactly alpha and beta".into());
        }
        self.engine.input(
            FieldSpan {
                buffer: sampled,
                first: 0,
            },
            sampled.len(),
        )?;
        // IDs were validated/uploaded at preparation; every lane owns one pair.
        unsafe {
            self.engine.lookup.launch(
                launch(self.count),
                &[
                    Argument::Buffer(sampled),
                    Argument::Buffer(&self.ids),
                    Argument::Buffer(&self.output),
                    Argument::U64(0),
                    Argument::U32(self.width),
                    Argument::U32(self.count as u32),
                    Argument::U32(self.extension.degree() as u32),
                    Argument::U32(1),
                ],
            )?
        }
        .finish()?;
        Ok(self.output)
    }
}

#[cfg(test)]
mod tests;
