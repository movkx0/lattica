//! Bounded public compiler arithmetic. Constant kernels use admitted public-hash
//! scratch; periodic interpolation admits separate bounded scratch. Both retire
//! their temporary storage before the next compiler operation.
use super::*;
use crate::proving::{Backend, Run, Stage};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

mod periodic;
pub(crate) use periodic::{PERIODIC_MAX_ALLOCATION_BYTES, PERIODIC_WORKSPACE_BYTES};

pub(crate) const MAX_PERIOD: usize = 1 << 16;
const PERIOD_TILE: usize = 2048;
pub(crate) const MAX_SELECTORS: u64 = 64;
pub(crate) const MAX_QUOTIENT_CHUNKS: usize = crate::block_v2::profile::MAX_QUOTIENT_CHUNKS;
const CONSTANT_WORDS: usize = MAX_QUOTIENT_CHUNKS * (MAX_QUOTIENT_CHUNKS + 1);
// Fixed workgroup SRAM (two 64-entry u32 planes) is covered by the context
// reserve, separate from the unchanged managed input/output scratch.
const CONSTANT_LANES: usize = 32;
const _: () = assert!(MAX_SELECTORS == 64 && MAX_QUOTIENT_CHUNKS == 32);
// Staging coexists with the builder's fixed folding cache. Caller-owned
// coefficient arrays are charged separately to its construction allowance.
const _: () = assert!(MAX_SELECTORS as usize <= CONSTANT_WORDS);
const _: () = assert!(8192 + 16 + PERIOD_TILE as u64 * 8 <= public_hash::HOST_BYTES);
const _: () = assert!(8192 + 16 + CONSTANT_WORDS as u64 * 8 <= public_hash::HOST_BYTES);

macro_rules! compiler_constants_source {
    ($extra:expr) => {
        concat!(
            r#"
inline ulong compiler_inv(ulong value) {
    return gl_pow(value, 0xfffffffeffffffffUL);
}
"#,
            include_str!("compiler_constants/tables.cl"),
            include_str!("compiler_constants/lookup.cl"),
            include_str!("compiler_constants/periodic.cl"),
            $extra
        )
    };
}
#[cfg(not(test))]
pub(crate) const KERNEL_SRC: &str = compiler_constants_source!("");
#[cfg(test)]
pub(crate) const KERNEL_SRC: &str =
    compiler_constants_source!(include_str!("compiler_constants/reference.cl"));
#[cfg(test)]
mod tests;

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
        self.compiler_constants(
            &[root.as_canonical_u64()],
            0,
            1,
            log_height as u64,
            &mut output,
            run,
        )?;
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
        self.compiler_constants(
            &[root],
            3,
            chunks,
            (log_height + chunks.ilog2() as usize) as u64,
            output,
            run,
        )
    }

    fn compiler_constants(
        &self,
        input: &[u64],
        operation: u32,
        size: usize,
        log_root: u64,
        output: &mut [Val],
        run: &Run,
    ) -> Result<(), String> {
        self.dispatch_compiler_constants(
            input,
            operation,
            size,
            log_root,
            output,
            run,
            "device_compiler_constants",
        )
    }

    fn dispatch_compiler_constants(
        &self,
        input: &[u64],
        operation: u32,
        size: usize,
        parameter: u64,
        output: &mut [Val],
        run: &Run,
        kernel_name: &'static str,
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
            let _ = (operation, size, parameter, kernel_name);
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
                    .kernel_builder(kernel_name)
                    .arg(&input_buffer.storage.buffer)
                    .arg(&output_buffer.storage.buffer)
                    .arg(operation)
                    .arg(count as u32)
                    .arg(size as u32)
                    .arg(parameter)
                    .global_work_size(count.div_ceil(CONSTANT_LANES) * CONSTANT_LANES)
                    .local_work_size(CONSTANT_LANES)
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
