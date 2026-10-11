//! Bounded public scalar arithmetic for the owned prover. Domain descriptors
//! contain metadata only; constructing one never computes a field inverse.
use super::*;
use p3_field::{coset::TwoAdicMultiplicativeCoset, PrimeField64};

pub(crate) const MAX_SCALARS: usize = crate::block_v2::challenger::resources::SCALAR_OUTPUTS;
const MAX_COSETS: usize = crate::block_v2::challenger::resources::PARTITION_COSETS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainSpec {
    log_size: usize,
    shift: u64,
}
impl DomainSpec {
    pub(crate) fn new(shift: u64, log_size: usize) -> Result<Self, String> {
        if shift == 0
            || shift >= GOLDILOCKS_MODULUS
            || log_size > 32
            || log_size >= usize::BITS as usize
        {
            return Err("invalid owned prover domain".into());
        }
        Ok(Self { log_size, shift })
    }
    pub(crate) fn log_size(self) -> usize {
        self.log_size
    }
    pub(crate) fn size(self) -> usize {
        1usize << self.log_size
    }
    pub(crate) fn shift(self) -> Val {
        Val::new(self.shift)
    }
}
impl From<TwoAdicMultiplicativeCoset<Val>> for DomainSpec {
    fn from(domain: TwoAdicMultiplicativeCoset<Val>) -> Self {
        Self {
            log_size: domain.log_size(),
            shift: domain.shift().as_canonical_u64(),
        }
    }
}

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_prover_scalars(__global const ulong *input,
    __global ulong *output, uint operation, uint count, ulong exponent) {
    uint i = get_global_id(0);
    if (i >= count) return;
    if (operation == 0) {
        ulong gamma[3] = {1UL, 0UL, 0UL};
        ulong base[3] = {input[3], input[4], input[5]};
        ulong e = exponent;
        while (e) {
            ulong product[3];
            if (e & 1UL) {
                opening_cubic_mul(gamma, base, product);
                for (uint c = 0; c < 3; ++c) gamma[c] = product[c];
            }
            e >>= 1;
            if (e) {
                opening_cubic_mul(base, base, product);
                for (uint c = 0; c < 3; ++c) base[c] = product[c];
            }
        }
        for (uint c = 0; c < 3; ++c)
            output[3 * i + c] = gl_canon(gl_add(input[c], gl_mul((ulong)i + 1UL, gamma[c])));
    } else if (operation == 1) {
        uint degree = (uint)exponent;
        for (uint c = 0; c < degree; ++c)
            output[degree * i + c] = gl_canon(gl_mul(input[c], input[degree + i]));
    } else if (operation == 2) {
        output[i] = gl_canon(gl_mul(input[0], gl_pow(input[1], (ulong)i)));
    } else if (operation == 3) {
        output[0] = gl_canon(gl_mul(input[0], input[1]));
    }
}
"#;

fn validate_lookup(width: usize, buses: usize) -> Result<(), String> {
    if width == 0 || width > u32::MAX as usize || buses == 0 || buses > MAX_SCALARS {
        return Err("GPU lookup scalar dimensions exceed admission".into());
    }
    Ok(())
}

impl DeviceSession {
    pub(crate) fn lookup_prefixes(
        &self,
        alpha: [u64; 3],
        beta: [u64; 3],
        width: usize,
        buses: usize,
    ) -> Result<Vec<[u64; 3]>, String> {
        validate_lookup(width, buses)?;
        let input: Vec<_> = alpha.into_iter().chain(beta).collect();
        let words = self.prover_scalars(&input, 0, buses, width as u64, buses * 3)?;
        Ok(words.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect())
    }

    pub(crate) fn next_points(
        &self,
        point: [u64; 3],
        log_sizes: &[usize],
    ) -> Result<Vec<[u64; 3]>, String> {
        let words = self.next_points_extension(Extension::Cubic, &point, log_sizes)?;
        Ok(words.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect())
    }

    pub(crate) fn next_points_extension(
        &self,
        extension: Extension,
        point: &[u64],
        log_sizes: &[usize],
    ) -> Result<Vec<u64>, String> {
        if extension == Extension::Base || point.len() != extension.degree() {
            return Err("GPU next point requires a compact pinned extension value".into());
        }
        if log_sizes.is_empty()
            || log_sizes.len() > MAX_SCALARS
            || log_sizes.iter().any(|&n| n > 32)
        {
            return Err("GPU next-point dimensions exceed admission".into());
        }
        let mut input = point.to_vec();
        // Pinned Goldilocks roots are a constant table, not host exponentiation.
        input.extend(
            log_sizes
                .iter()
                .map(|&n| Val::TWO_ADIC_GENERATORS[n].as_canonical_u64()),
        );
        self.prover_scalars(
            &input,
            1,
            log_sizes.len(),
            extension.degree() as u64,
            log_sizes.len() * extension.degree(),
        )
    }

    pub(crate) fn disjoint_domain(
        &self,
        domain: DomainSpec,
        log_size: usize,
    ) -> Result<DomainSpec, String> {
        DomainSpec::new(domain.shift, log_size)?;
        let words = self.prover_scalars(&[domain.shift, 7], 3, 1, 0, 1)?;
        DomainSpec::new(words[0], log_size)
    }

    pub(crate) fn split_domains(
        &self,
        domain: DomainSpec,
        chunks: usize,
    ) -> Result<Vec<DomainSpec>, String> {
        if !chunks.is_power_of_two() || chunks > MAX_COSETS || chunks > domain.size() {
            return Err("GPU coset partition exceeds admission".into());
        }
        let root = Val::TWO_ADIC_GENERATORS[domain.log_size].as_canonical_u64();
        self.prover_scalars(&[domain.shift, root], 2, chunks, 0, chunks)?
            .into_iter()
            .map(|shift| DomainSpec::new(shift, domain.log_size - chunks.ilog2() as usize))
            .collect()
    }

    fn prover_scalars(
        &self,
        input: &[u64],
        operation: u32,
        count: usize,
        exponent: u64,
        output_words: usize,
    ) -> Result<Vec<u64>, String> {
        if input.iter().any(|&n| n >= GOLDILOCKS_MODULUS) {
            return Err("GPU scalar input must be canonical".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (operation, count, exponent, output_words);
            Err("GPU prover scalars are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let specs = [
                MatrixSpec::new(0, input.len(), Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, output_words, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let input_buffer = self.allocate(engine, specs[0])?;
            let output_buffer = self.allocate(engine, specs[1])?;
            let mut output = vec![0u64; output_words];
            let fence = engine.fence();
            input_buffer
                .storage
                .buffer
                .write(input)
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: operation-specific callers bound counts and validate all
            // indices; both allocations and the host slices live past the fence.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_prover_scalars")
                    .arg(&input_buffer.storage.buffer)
                    .arg(&output_buffer.storage.buffer)
                    .arg(operation)
                    .arg(count as u32)
                    .arg(exponent)
                    .global_work_size(count)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = engine.timeline.record("device_prover_scalars", &event)?;
            output_buffer
                .storage
                .buffer
                .read(&mut output[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += input.len() as u64 * 8;
            engine.stats.downloaded_bytes += output_words as u64 * 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += input.len() as u64 * 8;
            stats.downloaded_bytes += output_words as u64 * 8;
            stats.scalar_calls += 1;
            stats.scalar_input_bytes += input.len() as u64 * 8;
            stats.scalar_output_bytes += output_words as u64 * 8;
            stats.scalar_device_ns += ns;
            match operation {
                0 => stats.scalar_lookup_prefixes += count as u64,
                1 => stats.scalar_next_points += count as u64,
                2 => stats.scalar_cosets += count as u64,
                3 => stats.scalar_disjoint_domains += 1,
                _ => unreachable!("private scalar operation"),
            }
            if output.iter().any(|&n| n >= GOLDILOCKS_MODULUS) {
                return Err("GPU scalar result is not canonical".into());
            }
            Ok(output)
        })
    }
}

#[cfg(test)]
mod tests;
