//! GPU input and coefficient scaling for reference-compatible trace hiding.
use super::*;
pub(crate) use crate::gpu_hiding::TraceCommitShape;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_trace_normalization(__global ulong *parameter, uint height) {
    parameter[0] = gl_pow((ulong)height, 0xfffffffeffffffffUL);
}
__kernel void device_trace_columns(__global const ulong *trace, __global const ulong *random, __global ulong *output, uint height, uint width, uint random_columns, uint first, uint columns) {
    size_t i = get_global_id(0);
    if (i >= (size_t)height * columns) return;
    size_t row = i / columns, original_row = row / 2;
    uint column = first + (uint)(i % columns);
    if ((row & 1) == 0 && column < width) output[i] = trace[original_row * width + column];
    else {
        size_t at = original_row * (width + 2 * random_columns);
        at += (row & 1) == 0 ? column - width : random_columns + column;
        output[i] = random[at];
    }
}
__kernel void device_trace_scale(__global ulong *coefficients, __global const ulong *parameter, uint height, uint columns, ulong generator) {
    size_t i = get_global_id(0);
    if (i >= (size_t)height * columns) return;
    coefficients[i] = gl_mul(gl_mul(coefficients[i], parameter[0]), gl_pow(generator, (ulong)(i / columns)));
}
__kernel void device_preprocessing_columns(__global const ulong *trace, __global ulong *output, uint height, uint width, uint first, uint columns) {
    size_t i = get_global_id(0);
    if (i >= (size_t)height * columns) return;
    size_t row = i / columns;
    uint column = first + (uint)(i % columns);
    output[i] = (row & 1) == 0 ? trace[(row / 2) * width + column] : 0;
}
"#;

pub(crate) struct TraceCommitInput {
    trace: DeviceMatrix,
    random: Option<super::random::SampleBuffer>,
    normalization: Allocation,
    pub(crate) shape: TraceCommitShape,
}

impl DeviceSession {
    pub(crate) fn prepare_trace_commit(
        &self,
        trace: &DeviceMatrix,
        random_columns: usize,
        random: &[u64],
    ) -> Result<TraceCommitInput, String> {
        self.check_owner(trace)?;
        let shape = TraceCommitShape::new(trace.spec, random_columns)?;
        if random.len() != shape.random_words || random.iter().any(|n| *n >= GOLDILOCKS_MODULUS) {
            return Err("invalid device trace hiding samples".into());
        }
        self.prepare_trace_input(trace, shape, Some(random), None)
    }

    pub(crate) fn prepare_trace_commit_with_random(
        &self,
        trace: &DeviceMatrix,
        random_columns: usize,
        random: RandomWords,
    ) -> Result<TraceCommitInput, String> {
        self.check_owner(trace)?;
        random.check_session(self)?;
        let shape = TraceCommitShape::new(trace.spec, random_columns)?;
        if random.len() != shape.random_words {
            return Err("device trace hiding sample count differs".into());
        }
        self.prepare_trace_input(trace, shape, None, Some(random))
    }

    pub(crate) fn prepare_preprocessing_commit(
        &self,
        trace: &PreprocessingTrace,
    ) -> Result<TraceCommitInput, String> {
        self.check_owner(trace.matrix())?;
        let shape = TraceCommitShape::preprocessing(trace.spec())?;
        self.prepare_trace_input(trace.matrix(), shape, None, None)
    }

    fn prepare_trace_input(
        &self,
        trace: &DeviceMatrix,
        shape: TraceCommitShape,
        random: Option<&[u64]>,
        generated: Option<RandomWords>,
    ) -> Result<TraceCommitInput, String> {
        #[cfg(not(feature = "gpu"))]
        {
            Err("device trace commitment is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            use super::random::SampleBuffer;
            let live = engine.accounting.lock().unwrap().live;
            let location = if generated.is_some() {
                SampleLocation::Resident
            } else {
                SampleLocation::Uploaded
            };
            let _plan = shape.storage_plan(
                location,
                live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            let alloc = |words| {
                let mut a = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    words,
                    compute::flags::MEM_READ_WRITE,
                )?;
                a._lease.mark_device()?;
                Ok::<_, String>(a)
            };
            let data = TraceCommitInput {
                trace: self.alias_private(trace)?,
                random: match generated {
                    Some(words) => Some(SampleBuffer::Generated(words)),
                    None => random
                        .map(|_| alloc(shape.random_words).map(SampleBuffer::Uploaded))
                        .transpose()?,
                },
                normalization: alloc(1)?,
                shape,
            };
            let fence = engine.fence();
            if let (Some(buffer), Some(words)) = (&data.random, random) {
                buffer
                    .buffer()
                    .write(words)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let mut event = compute::Event::empty();
            // SAFETY: one scalar output and a validated nonzero height.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_trace_normalization")
                    .arg(&data.normalization.buffer)
                    .arg(shape.height as u32)
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session.record_event(
                engine,
                if data.is_preprocessing() {
                    crate::proving::Stage::Preprocessing
                } else {
                    crate::proving::Stage::Hiding
                },
                "device_trace_normalization",
                &event,
            )?;
            fence.finish()?;
            let bytes = random.map_or(0, |words| words.len() as u64 * 8);
            engine.stats.uploaded_bytes += bytes;
            self.session.stats.lock().unwrap().uploaded_bytes += bytes;
            Ok(data)
        })
    }
}

impl TraceCommitInput {
    pub(crate) fn is_preprocessing(&self) -> bool {
        self.random.is_none()
    }
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        session.check_owner(&self.trace)
    }
    pub(in crate::block_v2::gpu_hash::engine) fn check_engine(
        &self,
        engine: &Engine,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&self.trace.session.context, &engine._job_lease) {
            return Err("trace commitment input belongs to another device context".into());
        }
        Ok(())
    }
    fn check_columns(
        &self,
        engine: &Engine,
        output: &compute::Buffer<u64>,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_engine(engine)?;
        if columns == 0
            || first
                .checked_add(columns)
                .is_none_or(|n| n > self.shape.width)
            || self
                .shape
                .height
                .checked_mul(columns)
                .is_none_or(|n| n > output.len())
        {
            return Err("invalid device trace commitment column tile".into());
        }
        Ok(())
    }
    pub(in crate::block_v2::gpu_hash::engine) fn load_columns(
        &self,
        engine: &mut Engine,
        output: &compute::Buffer<u64>,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_columns(engine, output, first, columns)?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("device trace commitment is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            let mut event = compute::Event::empty();
            let name = if self.is_preprocessing() {
                "device_preprocessing_columns"
            } else {
                "device_trace_columns"
            };
            let mut kernel = engine.pq.kernel_builder(name);
            kernel.arg(&self.trace.storage.buffer);
            if let Some(random) = &self.random {
                kernel.arg(random.buffer());
            }
            kernel
                .arg(output)
                .arg(self.shape.height as u32)
                .arg(self.shape.trace_width as u32);
            if self.random.is_some() {
                kernel.arg(self.shape.random_columns as u32);
            }
            // SAFETY: trace/sample layout and destination tile were validated.
            unsafe {
                kernel
                    .arg(first as u32)
                    .arg(columns as u32)
                    .global_work_size(self.shape.height * columns)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.trace.session.record_event(
                engine,
                if self.is_preprocessing() {
                    crate::proving::Stage::Preprocessing
                } else {
                    crate::proving::Stage::Hiding
                },
                name,
                &event,
            )?;
            Ok(())
        }
    }
    pub(in crate::block_v2::gpu_hash::engine) fn scale_columns(
        &self,
        engine: &mut Engine,
        output: &compute::Buffer<u64>,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_columns(engine, output, first, columns)?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("device trace commitment is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            use p3_field::{Field, PrimeField64};
            let mut event = compute::Event::empty();
            // SAFETY: scale only the checked coefficient tile, before forward NTT.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_trace_scale")
                    .arg(output)
                    .arg(&self.normalization.buffer)
                    .arg(self.shape.height as u32)
                    .arg(columns as u32)
                    .arg(Val::GENERATOR.as_canonical_u64())
                    .global_work_size(self.shape.height * columns)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.trace.session.record_event(
                engine,
                if self.is_preprocessing() {
                    crate::proving::Stage::Preprocessing
                } else {
                    crate::proving::Stage::Hiding
                },
                "device_trace_scale",
                &event,
            )?;
            Ok(())
        }
    }
}

impl TraceCommitShape {
    pub(crate) fn storage_plan(
        self,
        location: SampleLocation,
        live: usize,
        managed: usize,
        max_allocation: usize,
    ) -> Result<CommitInputStorage, String> {
        CommitInputStorage::new(
            [self.random_words, 0],
            1,
            location,
            live,
            managed,
            max_allocation,
        )
    }
    pub(crate) fn lde_shape(self) -> super::super::lde_plan::InputShape {
        super::super::lde_plan::InputShape {
            height: self.height,
            width: self.width,
            added_bits: crate::block_v2::profile::LOG_BLOWUP,
        }
    }
}
