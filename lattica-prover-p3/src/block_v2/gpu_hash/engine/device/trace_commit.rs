//! GPU input and coefficient scaling for reference-compatible trace hiding.
use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_commit_layout_accounts_for_reference_hiding_and_rejects_bad_geometry() {
        let spec = MatrixSpec::new(10, 17, Extension::Cubic, RowOrder::Natural, 1).unwrap();
        let shape = TraceCommitShape::new(spec, 4).unwrap();
        assert_eq!(
            (shape.height, shape.width, shape.trace_width),
            (2048, 55, 51)
        );
        assert_eq!(shape.random_words, 1024 * (51 + 8));
        assert_eq!(shape.allocation_bytes(), [1024 * 59 * 8, 8]);
        let quadratic = TraceCommitShape::new(
            MatrixSpec {
                extension: Extension::Quadratic,
                ..spec
            },
            4,
        )
        .unwrap();
        assert_eq!(
            (quadratic.height, quadratic.width, quadratic.trace_width),
            (2048, 38, 34)
        );
        assert_eq!(quadratic.random_words, 1024 * 42);
        assert_eq!(quadratic.allocation_bytes(), [1024 * 42 * 8, 8]);
        for invalid in [
            MatrixSpec {
                order: RowOrder::BitReversed,
                ..spec
            },
            MatrixSpec { shift: 7, ..spec },
            MatrixSpec {
                log_rows: 31,
                ..spec
            },
        ] {
            assert!(TraceCommitShape::new(invalid, 4).is_err());
        }
        let base = TraceCommitShape::new(
            MatrixSpec::new(10, 17, Extension::Base, RowOrder::Natural, 1).unwrap(),
            4,
        )
        .unwrap();
        assert_eq!((base.height, base.width, base.trace_width), (2048, 21, 17));
        assert_eq!(base.random_words, 1024 * 25);
        assert_eq!(base.allocation_bytes(), [1024 * 25 * 8, 8]);
        let preprocessing = TraceCommitShape::preprocessing(
            MatrixSpec::new(10, 17, Extension::Base, RowOrder::Natural, 1).unwrap(),
        )
        .unwrap();
        assert_eq!((preprocessing.height, preprocessing.width), (2048, 17));
        assert_eq!(preprocessing.random_columns, 0);
        assert_eq!(preprocessing.random_words, 0);
        assert_eq!(preprocessing.allocation_bytes(), [0, 8]);
        assert!(TraceCommitShape::preprocessing(spec).is_err());
        for random_columns in [0, 3, 5, usize::MAX] {
            assert!(TraceCommitShape::new(spec, random_columns).is_err());
        }
        assert!(TraceCommitShape::new(
            MatrixSpec::new(0, u32::MAX as usize, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
            4
        )
        .is_err());
    }
}

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceCommitShape {
    pub height: usize,
    pub width: usize,
    pub trace_width: usize,
    pub random_columns: usize,
    pub random_words: usize,
}

impl TraceCommitShape {
    pub(crate) fn new(spec: MatrixSpec, random_columns: usize) -> Result<Self, String> {
        Self::plan(spec, random_columns, false)
    }
    pub(crate) fn preprocessing(spec: MatrixSpec) -> Result<Self, String> {
        Self::plan(spec, 0, true)
    }
    fn plan(spec: MatrixSpec, random_columns: usize, preprocessing: bool) -> Result<Self, String> {
        if (preprocessing && spec.extension != Extension::Base)
            || spec.order != RowOrder::Natural
            || spec.shift != 1
            || spec.log_rows >= 31
            || random_columns
                != if preprocessing {
                    0
                } else {
                    crate::block_v2::profile::NUM_RANDOM_CODEWORDS
                }
        {
            return Err("unsupported device trace commitment geometry".into());
        }
        let trace_width = spec
            .columns
            .checked_mul(spec.extension.degree())
            .ok_or("trace width overflow")?;
        let width = trace_width
            .checked_add(random_columns)
            .filter(|n| *n <= u32::MAX as usize)
            .ok_or("hidden trace width overflow")?;
        let random_words = if preprocessing {
            0
        } else {
            trace_width
                .checked_add(2 * random_columns)
                .filter(|n| *n <= u32::MAX as usize)
                .and_then(|n| n.checked_mul(spec.rows()))
                .filter(|n| n.checked_mul(8).is_some())
                .ok_or("trace hiding samples overflow")?
        };
        let height = spec.rows() * 2;
        MatrixSpec::new(
            spec.log_rows + 1,
            width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        Ok(Self {
            height,
            width,
            trace_width,
            random_columns,
            random_words,
        })
    }
    pub(crate) fn allocation_bytes(self) -> [usize; 2] {
        [self.random_words * 8, 8]
    }
    pub(crate) fn lde_shape(self) -> super::super::lde_plan::InputShape {
        super::super::lde_plan::InputShape {
            height: self.height,
            width: self.width,
            added_bits: crate::block_v2::profile::LOG_BLOWUP,
        }
    }
}

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
            let pending_samples = if generated.is_some() {
                0
            } else {
                shape.random_words * 8
            };
            if live
                .checked_add(pending_samples)
                .and_then(|n| n.checked_add(8))
                .is_none_or(|n| n > engine.limits.managed_bytes)
                || shape
                    .allocation_bytes()
                    .iter()
                    .any(|n| *n > engine.max_alloc)
            {
                return Err("trace hiding samples exceed GPU admission".into());
            }
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
