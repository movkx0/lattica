//! Bounded public compiler arithmetic. Every kernel fits the already admitted
//! public-hash scratch envelope and releases it before the next operation.
use super::*;
use crate::proving::{Backend, Run, Stage};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

pub(crate) const MAX_PERIOD: usize = 1 << 16;
const PERIOD_TILE: usize = 2048;
pub(crate) const MAX_SELECTORS: u64 = 64;
pub(crate) const MAX_QUOTIENT_CHUNKS: usize = crate::block_v2::profile::MAX_QUOTIENT_CHUNKS;
const CONSTANT_WORDS: usize = MAX_QUOTIENT_CHUNKS * (MAX_QUOTIENT_CHUNKS + 1);
// Staging coexists with the builder's fixed folding cache. Caller-owned
// coefficient arrays are charged separately to its construction allowance.
const _: () = assert!(MAX_SELECTORS as usize <= CONSTANT_WORDS);
const _: () = assert!(8192 + 16 + PERIOD_TILE as u64 * 8 <= public_hash::HOST_BYTES);
const _: () = assert!(8192 + 16 + CONSTANT_WORDS as u64 * 8 <= public_hash::HOST_BYTES);

pub(crate) const KERNEL_SRC: &str = r#"
inline ulong compiler_inv(ulong value) {
    return gl_pow(value, 0xfffffffeffffffffUL);
}
__kernel void device_compiler_constants(__global const ulong *input,
    __global ulong *output, uint operation, uint count, uint size, ulong exponent) {
    uint k = get_global_id(0);
    if (k >= count) return;
    if (operation == 0) {
        output[k] = gl_canon(compiler_inv(input[0]));
    } else if (operation == 1) {
        ulong denominator = 1UL;
        for (uint j = 0; j < count; ++j) {
            if (j != k)
                denominator = gl_mul(denominator, gl_sub(input[0] + (ulong)k, input[0] + (ulong)j));
        }
        output[k] = gl_canon(compiler_inv(denominator));
    } else if (operation == 3) {
        if (k < size) {
            output[k] = gl_canon(compiler_inv(gl_mul(7UL, gl_pow(input[0], (ulong)k))));
        } else {
            uint i = (k - size) / size, j = (k - size) % size;
            if (i == j) { output[k] = 0UL; return; }
            ulong a = gl_mul(7UL, gl_pow(input[0], (ulong)i));
            ulong b = gl_mul(7UL, gl_pow(input[0], (ulong)j));
            ulong den = gl_sub(gl_pow(gl_mul(a, compiler_inv(b)), exponent), 1UL);
            output[k] = gl_canon(compiler_inv(den));
        }
    }
}
__kernel void device_compiler_periodic(__global const ulong *input,
    __global ulong *output, ulong root, uint length, uint input_start,
    uint input_count, uint coefficient_start, uint count) {
    uint k = get_global_id(0);
    if (k >= count) return;
    ulong step = gl_pow(compiler_inv(root), (ulong)coefficient_start + (ulong)k);
    ulong power = gl_pow(step, (ulong)input_start);
    ulong sum = input_start == 0 ? 0UL : output[k];
    for (uint j = 0; j < input_count; ++j) {
        sum = gl_add(sum, gl_mul(power, input[j]));
        power = gl_mul(power, step);
    }
    if (input_start + input_count == length)
        sum = gl_mul(sum, compiler_inv((ulong)length));
    output[k] = gl_canon(sum);
}

"#;

impl DeviceSession {
    pub(crate) fn compiler_inverse_generator(
        &self,
        log_height: usize,
        run: &Run,
    ) -> Result<Val, String> {
        let root = Val::TWO_ADIC_GENERATORS
            .get(log_height)
            .ok_or("compiler subgroup height")?;
        let mut output = [Val::ZERO; 1];
        self.compiler_constants(&[root.as_canonical_u64()], 0, 1, 0, &mut output, run)?;
        Ok(output[0])
    }

    pub(crate) fn compiler_selectors_into(
        &self,
        first: u64,
        last: u64,
        output: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        if first > last || last >= GOLDILOCKS_MODULUS || last - first >= MAX_SELECTORS {
            return Err("GPU compiler selector range exceeds admission".into());
        }
        if output.len() != (last - first + 1) as usize {
            return Err("GPU compiler selector output length".into());
        }
        self.compiler_constants(&[first], 1, 0, 0, output, run)
    }

    pub(crate) fn compiler_periodic_into(
        &self,
        column: &[Val],
        log_height: usize,
        coefficients: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        let n = column.len();
        if log_height > 32 || !n.is_power_of_two() || n > MAX_PERIOD || n > 1usize << log_height {
            return Err("GPU compiler periodic column exceeds admission".into());
        }
        if coefficients.len() != n {
            return Err("GPU compiler periodic output length".into());
        }
        run.check_device_stage(Stage::Preprocessing, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        let root = Val::TWO_ADIC_GENERATORS[n.ilog2() as usize].as_canonical_u64();
        #[cfg(not(feature = "gpu"))]
        {
            let _ = root;
            Err("GPU compiler constants are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let tile = n.min(PERIOD_TILE);
            if tile as u64 * 16 > public_hash::WORKSPACE_BYTES
                || tile as u64 * 8 > public_hash::MAX_ALLOCATION_BYTES
            {
                return Err("GPU compiler periodic scratch exceeds admission".into());
            }
            let spec = MatrixSpec::new(0, tile, Extension::Base, RowOrder::Natural, 1)?;
            let _plan = Self::plan(engine, &[spec, spec])?;
            let input = self.allocate(engine, spec)?;
            let output = self.allocate(engine, spec)?;
            // Fixed staging is independent of period and cannot grow.
            let mut staging = [0u64; PERIOD_TILE];
            let fence = engine.fence();
            for coefficient_start in (0..n).step_by(tile) {
                let count = tile.min(n - coefficient_start);
                for input_start in (0..n).step_by(tile) {
                    let input_count = tile.min(n - input_start);
                    for (dst, src) in staging
                        .iter_mut()
                        .zip(&column[input_start..input_start + input_count])
                    {
                        *dst = src.as_canonical_u64();
                    }
                    input
                        .storage
                        .buffer
                        .write(&staging[..input_count])
                        .enq()
                        .map_err(|e| e.to_string())?;
                    let mut event = compute::Event::empty();
                    // SAFETY: all tile dimensions are bounded by both buffers;
                    // each work item owns one accumulator, initialized by tile 0.
                    // Event recording drains each batch before staging reuse.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_compiler_periodic")
                            .arg(&input.storage.buffer)
                            .arg(&output.storage.buffer)
                            .arg(root)
                            .arg(n as u32)
                            .arg(input_start as u32)
                            .arg(input_count as u32)
                            .arg(coefficient_start as u32)
                            .arg(count as u32)
                            .global_work_size(count)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    let ns = engine.timeline.record("device_compiler_periodic", &event)?;
                    run.observe_device(Stage::Preprocessing, Backend::OpenCl, 1, ns)
                        .map_err(|e| e.to_string())?;
                    engine.stats.uploaded_bytes += input_count as u64 * 8;
                    self.session.stats.lock().unwrap().uploaded_bytes += input_count as u64 * 8;
                }
                output
                    .storage
                    .buffer
                    .read(&mut staging[..count])
                    .enq()
                    .map_err(|e| e.to_string())?;
                fence.finish()?;
                if staging[..count].iter().any(|&v| v >= GOLDILOCKS_MODULUS) {
                    return Err("GPU compiler coefficient is not canonical".into());
                }
                for (dst, &word) in coefficients[coefficient_start..coefficient_start + count]
                    .iter_mut()
                    .zip(&staging[..count])
                {
                    *dst = Val::new(word);
                }
                engine.stats.downloaded_bytes += count as u64 * 8;
                self.session.stats.lock().unwrap().downloaded_bytes += count as u64 * 8;
            }
            Ok(())
        })
    }

    pub(crate) fn compiler_quotient_into(
        &self,
        chunks: usize,
        log_height: usize,
        output: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        if !chunks.is_power_of_two()
            || chunks > MAX_QUOTIENT_CHUNKS
            || log_height > 32
            || log_height + chunks.ilog2() as usize > 32
        {
            return Err("GPU compiler quotient domain exceeds admission".into());
        }
        if output.len() != chunks + chunks * chunks {
            return Err("GPU compiler quotient output length".into());
        }
        let root =
            Val::TWO_ADIC_GENERATORS[log_height + chunks.ilog2() as usize].as_canonical_u64();
        self.compiler_constants(&[root], 3, chunks, 1 << log_height, output, run)
    }

    fn compiler_constants(
        &self,
        input: &[u64],
        operation: u32,
        size: usize,
        exponent: u64,
        output: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        let count = output.len();
        run.check_device_stage(Stage::Preprocessing, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        // Defend the common envelope independently of operation-specific bounds.
        if input.len() != 1
            || count == 0
            || count > CONSTANT_WORDS
            || (input.len() + count) as u64 * 8 > public_hash::WORKSPACE_BYTES
            || input.len().max(count) as u64 * 8 > public_hash::MAX_ALLOCATION_BYTES
            || input.iter().any(|&n| n >= GOLDILOCKS_MODULUS)
        {
            return Err("GPU compiler constants exceed scratch admission".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (operation, size, exponent);
            Err("GPU compiler constants are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let specs = [
                MatrixSpec::new(0, input.len(), Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, count, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let input_buffer = self.allocate(engine, specs[0])?;
            let output_buffer = self.allocate(engine, specs[1])?;
            let mut staging = [0u64; CONSTANT_WORDS];
            let fence = engine.fence();
            input_buffer
                .storage
                .buffer
                .write(input)
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: private callers validate all dimensions, both buffers fit
            // admission, and the fence retains buffers/host slices until drained.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_compiler_constants")
                    .arg(&input_buffer.storage.buffer)
                    .arg(&output_buffer.storage.buffer)
                    .arg(operation)
                    .arg(count as u32)
                    .arg(size as u32)
                    .arg(exponent)
                    .global_work_size(count)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = engine
                .timeline
                .record("device_compiler_constants", &event)?;
            run.observe_device(Stage::Preprocessing, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())?;
            output_buffer
                .storage
                .buffer
                .read(&mut staging[..count])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += input.len() as u64 * 8;
            engine.stats.downloaded_bytes += count as u64 * 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += input.len() as u64 * 8;
            stats.downloaded_bytes += count as u64 * 8;
            if staging[..count].iter().any(|&n| n >= GOLDILOCKS_MODULUS) {
                return Err("GPU compiler constant is not canonical".into());
            }
            for (dst, &word) in output.iter_mut().zip(&staging[..count]) {
                *dst = Val::new(word);
            }
            Ok(())
        })
    }
}
