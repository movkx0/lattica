//! Device input for committing the canonical quotient-domain coset partition.
//! Random samples retain the reference draw order; balancing and field
//! arithmetic run on the GPU. This is not a general arbitrary-domain API.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use p3_commit::PolynomialSpace;
    use p3_field::{coset::TwoAdicMultiplicativeCoset as Domain, PrimeCharacteristicRing};

    #[test]
    fn quotient_commit_shape_counts_raw_samples_and_rejects_noncanonical_partitions() {
        let spec = MatrixSpec::new(11, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap();
        let shape = QuotientCommitShape::new(spec, 16, 4).unwrap();
        assert_eq!(
            (
                shape.height,
                shape.width,
                shape.random_words,
                shape.mask_words
            ),
            (128, 7, 8192, 13440)
        );
        assert_eq!(shape.bytes().unwrap(), 173440);
        let quadratic = MatrixSpec::new(11, 1, Extension::Quadratic, RowOrder::Natural, 7).unwrap();
        let quadratic = QuotientCommitShape::new(quadratic, 16, 4).unwrap();
        assert_eq!(
            (
                quadratic.degree,
                quadratic.width,
                quadratic.random_words,
                quadratic.mask_words
            ),
            (2, 6, 8192, 11520)
        );
        assert_eq!(quadratic.bytes().unwrap(), 158080);
        assert!(QuotientCommitShape::new(spec, 32, 4).is_ok());
        assert!(QuotientCommitShape::new(
            MatrixSpec::new(11, 1, Extension::Quadratic, RowOrder::Natural, 7).unwrap(),
            32,
            4
        )
        .is_ok());
        for chunks in [0, 1, 3, 64, 2048] {
            assert!(QuotientCommitShape::new(spec, chunks, 4).is_err());
        }
        for random_columns in [0, 1, 3, 5] {
            assert!(QuotientCommitShape::new(spec, 16, random_columns).is_err());
        }
        for invalid in [
            MatrixSpec::new(11, 1, Extension::Cubic, RowOrder::BitReversed, 7).unwrap(),
            MatrixSpec::new(11, 3, Extension::Base, RowOrder::Natural, 7).unwrap(),
            MatrixSpec::new(11, 2, Extension::Cubic, RowOrder::Natural, 7).unwrap(),
            MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap(),
        ] {
            assert!(QuotientCommitShape::new(invalid, 16, 4).is_err());
        }
    }

    #[test]
    fn uniform_partition_has_equal_reference_normalized_vanishing_weights() {
        for shift in [7, 11] {
            for log_height in [1, 3, 13] {
                for log_chunks in [1, 2, 4, 5] {
                    let chunks = 1usize << log_chunks;
                    let domain =
                        Domain::new(Val::from_u64(shift), log_height + log_chunks).unwrap();
                    let parts = domain.split_domains(chunks);
                    for (i, part) in parts.iter().enumerate() {
                        let denominator: Val = parts
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j != i)
                            .map(|(_, other)| other.vanishing_poly_at_point(part.first_point()))
                            .product();
                        assert_eq!(denominator, -Val::from_usize(chunks));
                    }
                }
            }
        }
    }
}

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_quotient_hiding_parameters(__global ulong *parameters,
    uint height, uint chunks, ulong shift, ulong root, ulong generator) {
    uint chunk = get_global_id(0);
    if (chunk >= chunks) return;
    ulong chunk_shift = gl_mul(shift, gl_pow(root, (ulong)chunk));
    ulong ratio = gl_mul(generator, gl_inverse(chunk_shift));
    parameters[3 * chunk] = gl_inverse((ulong)height);
    parameters[3 * chunk + 1] = ratio;
    parameters[3 * chunk + 2] = gl_pow(ratio, (ulong)height);
}
__kernel void device_quotient_chunk_columns(__global const ulong *quotient,
    __global const ulong *random, __global ulong *output, uint height,
    uint chunks, uint chunk, uint random_columns, uint first, uint columns, uint degree) {
    size_t i = get_global_id(0);
    if (i >= (size_t)height * columns) return;
    size_t row = i / columns;
    uint column = first + (uint)(i % columns);
    output[i] = column < degree ? quotient[(row * chunks + chunk) * degree + column]
        : random[((size_t)chunk * height + row) * random_columns + column - degree];
}
__kernel void device_quotient_hide_chunk(__global ulong *coefficients,
    __global const ulong *masks, __global const ulong *parameters,
    uint height, uint chunks, uint chunk, uint width, uint first,
    uint columns, ulong generator) {
    size_t i = get_global_id(0), elements = (size_t)height * columns;
    if (i >= elements) return;
    size_t row = i / columns, column = first + i % columns;
    size_t at = row * width + column, chunk_elements = (size_t)height * width;
    ulong mask = 0UL;
    if (chunk + 1 < chunks) mask = masks[(size_t)chunk * chunk_elements + at];
    else {
        // For a complete uniform partition the normalized vanishing weights
        // are all -1/chunks. The last mask is therefore the negative sum.
        for (uint k = 0; k + 1 < chunks; ++k)
            mask = gl_sub(mask, masks[(size_t)k * chunk_elements + at]);
    }
    ulong scaled = gl_mul(gl_mul(coefficients[i], parameters[3 * chunk]),
        gl_pow(parameters[3 * chunk + 1], (ulong)row));
    ulong hidden = gl_mul(mask, gl_pow(generator, (ulong)row));
    coefficients[i] = gl_sub(scaled, hidden);
    coefficients[elements + i] = gl_mul(parameters[3 * chunk + 2], hidden);
}
"#;

#[derive(Clone, Copy, Debug)]
pub(crate) struct QuotientCommitShape {
    pub degree: usize,
    pub chunks: usize,
    pub height: usize,
    pub width: usize,
    pub random_columns: usize,
    pub random_words: usize,
    pub mask_words: usize,
}

impl QuotientCommitShape {
    pub(crate) fn new(
        spec: MatrixSpec,
        chunks: usize,
        random_columns: usize,
    ) -> Result<Self, String> {
        let max_chunks = crate::block_v2::profile::MAX_QUOTIENT_CHUNKS;
        if spec.extension == Extension::Base
            || spec.columns != 1
            || spec.order != RowOrder::Natural
            || spec.log_rows > 31
            || chunks < 2
            || chunks > max_chunks
            || !chunks.is_power_of_two()
            || spec.rows() / chunks < 2
            || random_columns != crate::block_v2::profile::NUM_RANDOM_CODEWORDS
        {
            return Err(format!("unsupported owned quotient commitment geometry: spec={spec:?} chunks={chunks} random_columns={random_columns}"));
        }
        let height = spec.rows() / chunks;
        let width = spec
            .extension
            .degree()
            .checked_add(random_columns)
            .ok_or("quotient width overflow")?;
        let random_words = spec
            .rows()
            .checked_mul(random_columns)
            .ok_or("quotient random column overflow")?;
        let mask_words = height
            .checked_mul(width)
            .and_then(|n| n.checked_mul(chunks - 1))
            .ok_or("quotient hiding mask overflow")?;
        let result = Self {
            degree: spec.extension.degree(),
            chunks,
            height,
            width,
            random_columns,
            random_words,
            mask_words,
        };
        result.bytes()?;
        Ok(result)
    }

    pub(crate) fn allocation_words(self) -> [usize; 3] {
        [self.random_words, self.mask_words, self.chunks * 3]
    }

    pub(crate) fn storage_plan(
        self,
        location: SampleLocation,
        live: usize,
        managed: usize,
        max_allocation: usize,
    ) -> Result<CommitInputStorage, String> {
        CommitInputStorage::new(
            [self.random_words, self.mask_words],
            self.chunks * 3,
            location,
            live,
            managed,
            max_allocation,
        )
    }

    pub(crate) fn bytes(self) -> Result<usize, String> {
        self.allocation_words()
            .into_iter()
            .try_fold(0usize, |total, n| {
                n.checked_mul(8)
                    .and_then(|n| total.checked_add(n))
                    .ok_or_else(|| "quotient sample storage overflow".into())
            })
    }
}

pub(crate) struct QuotientCommitInput {
    quotient: DeviceMatrix,
    random: super::random::SampleBuffer,
    masks: super::random::SampleBuffer,
    parameters: Allocation,
    pub(crate) shape: QuotientCommitShape,
}

impl DeviceSession {
    pub(crate) fn prepare_quotient_commit(
        &self,
        quotient: &DeviceMatrix,
        chunks: usize,
        random_columns: usize,
        random: &[u64],
        masks: &[u64],
    ) -> Result<QuotientCommitInput, String> {
        self.check_owner(quotient)?;
        let shape = QuotientCommitShape::new(quotient.spec, chunks, random_columns)?;
        if random.len() != shape.random_words
            || masks.len() != shape.mask_words
            || random.iter().chain(masks).any(|n| *n >= GOLDILOCKS_MODULUS)
        {
            return Err("invalid quotient commitment random samples".into());
        }
        self.prepare_quotient_input(quotient, shape, Some((random, masks)), None)
    }

    pub(crate) fn prepare_quotient_commit_with_random(
        &self,
        quotient: &DeviceMatrix,
        chunks: usize,
        random_columns: usize,
        random: RandomWords,
        masks: RandomWords,
    ) -> Result<QuotientCommitInput, String> {
        self.check_owner(quotient)?;
        random.check_session(self)?;
        masks.check_session(self)?;
        let shape = QuotientCommitShape::new(quotient.spec, chunks, random_columns)?;
        if random.len() != shape.random_words || masks.len() != shape.mask_words {
            return Err("device quotient hiding sample counts differ".into());
        }
        self.prepare_quotient_input(quotient, shape, None, Some((random, masks)))
    }

    fn prepare_quotient_input(
        &self,
        quotient: &DeviceMatrix,
        shape: QuotientCommitShape,
        uploaded: Option<(&[u64], &[u64])>,
        generated: Option<(RandomWords, RandomWords)>,
    ) -> Result<QuotientCommitInput, String> {
        #[cfg(not(feature = "gpu"))]
        {
            Err("owned quotient commitments are not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            use super::random::SampleBuffer;
            use p3_field::{Field, PrimeField64};
            let chunks = shape.chunks;
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
            let alloc = |words| -> Result<Allocation, String> {
                let mut a = allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    words,
                    compute::flags::MEM_READ_WRITE,
                )?;
                a._lease.mark_device()?;
                Ok(a)
            };
            let (random, masks) = match generated {
                Some((random, masks)) => (
                    SampleBuffer::Generated(random),
                    SampleBuffer::Generated(masks),
                ),
                None => (
                    SampleBuffer::Uploaded(alloc(shape.random_words)?),
                    SampleBuffer::Uploaded(alloc(shape.mask_words)?),
                ),
            };
            let data = QuotientCommitInput {
                quotient: self.alias_private(quotient)?,
                random,
                masks,
                parameters: alloc(chunks * 3)?,
                shape,
            };
            let fence = engine.fence();
            if let Some((random, masks)) = uploaded {
                data.random
                    .buffer()
                    .write(random)
                    .enq()
                    .map_err(|e| e.to_string())?;
                data.masks
                    .buffer()
                    .write(masks)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let mut event = compute::Event::empty();
            // SAFETY: all three words per chunk are allocated, and chunk/root
            // geometry is checked before any samples or kernels are consumed.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_quotient_hiding_parameters")
                    .arg(&data.parameters.buffer)
                    .arg(shape.height as u32)
                    .arg(chunks as u32)
                    .arg(quotient.spec.shift)
                    .arg(super::super::fri_fold::root(quotient.spec.log_rows))
                    .arg(Val::GENERATOR.as_canonical_u64())
                    .global_work_size(chunks)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            engine.stats.quotient_mask_ns += self.session.record_event(
                engine,
                crate::proving::Stage::Hiding,
                "device_quotient_hiding_parameters",
                &event,
            )?;
            fence.finish()?;
            let bytes =
                uploaded.map_or(0, |(random, masks)| (random.len() + masks.len()) * 8) as u64;
            engine.stats.uploaded_bytes += bytes;
            self.session.stats.lock().unwrap().uploaded_bytes += bytes;
            Ok(data)
        })
    }
}

impl QuotientCommitInput {
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        session.check_owner(&self.quotient)
    }

    pub(in crate::block_v2::gpu_hash::engine) fn check_engine(
        &self,
        engine: &Engine,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&self.quotient.session.context, &engine._job_lease) {
            return Err("quotient commitment input belongs to another device context".into());
        }
        Ok(())
    }

    pub(in crate::block_v2::gpu_hash::engine) fn load_columns(
        &self,
        engine: &mut Engine,
        output: &compute::Buffer<u64>,
        chunk: usize,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_slice(engine, output, chunk, first, columns, 1)?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("owned quotient loading is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            let mut event = compute::Event::empty();
            // SAFETY: immutable shape bounds source, random and output columns;
            // the executor's queue fence outlives all referenced allocations.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_quotient_chunk_columns")
                    .arg(&self.quotient.storage.buffer)
                    .arg(self.random.buffer())
                    .arg(output)
                    .arg(self.shape.height as u32)
                    .arg(self.shape.chunks as u32)
                    .arg(chunk as u32)
                    .arg(self.shape.random_columns as u32)
                    .arg(first as u32)
                    .arg(columns as u32)
                    .arg(self.shape.degree as u32)
                    .global_work_size(self.shape.height * columns)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.quotient.session.record_event(
                engine,
                crate::proving::Stage::Hiding,
                "device_quotient_chunk_columns",
                &event,
            )?;
            Ok(())
        }
    }

    pub(in crate::block_v2::gpu_hash::engine) fn hide_columns(
        &self,
        engine: &mut Engine,
        coefficients: &compute::Buffer<u64>,
        chunk: usize,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        self.check_slice(engine, coefficients, chunk, first, columns, 2)?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("owned quotient hiding is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        {
            use p3_field::{Field, PrimeField64};
            let mut event = compute::Event::empty();
            // SAFETY: the doubled coefficient slice and every raw mask sample
            // are covered by checked shape and slice bounds.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_quotient_hide_chunk")
                    .arg(coefficients)
                    .arg(self.masks.buffer())
                    .arg(&self.parameters.buffer)
                    .arg(self.shape.height as u32)
                    .arg(self.shape.chunks as u32)
                    .arg(chunk as u32)
                    .arg(self.shape.width as u32)
                    .arg(first as u32)
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
            engine.stats.quotient_mask_ns += self.quotient.session.record_event(
                engine,
                crate::proving::Stage::Hiding,
                "device_quotient_hide_chunk",
                &event,
            )?;
            Ok(())
        }
    }

    fn check_slice(
        &self,
        engine: &Engine,
        output: &compute::Buffer<u64>,
        chunk: usize,
        first: usize,
        columns: usize,
        rows_multiple: usize,
    ) -> Result<(), String> {
        self.check_engine(engine)?;
        if chunk >= self.shape.chunks
            || columns == 0
            || first
                .checked_add(columns)
                .is_none_or(|n| n > self.shape.width)
            || self
                .shape
                .height
                .checked_mul(columns)
                .and_then(|n| n.checked_mul(rows_multiple))
                .is_none_or(|n| n > output.len())
        {
            return Err("invalid device quotient commitment tile".into());
        }
        Ok(())
    }
}
