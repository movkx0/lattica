//! Binary cubic FRI views, input mixing and bounded final-proof gathers.
use super::*;

mod general;
pub(crate) use general::KERNEL_SRC as GENERAL_KERNEL_SRC;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_fri_mix(__global const ulong *folded,
    __global const ulong *input, __global ulong *output, uint rows,
    ulong b0, ulong b1, ulong b2) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong beta[3] = {b0, b1, b2}, square[3], value[3], product[3];
    opening_cubic_mul(beta, beta, square);
    for (uint i = 0; i < 3; ++i) value[i] = input[row * 3 + i];
    opening_cubic_mul(square, value, product);
    for (uint i = 0; i < 3; ++i)
        output[row * 3 + i] = gl_canon(gl_add(folded[row * 3 + i], product[i]));
}
__kernel void device_gather_rows(__global const ulong *input,
    __global const ulong *indices, __global ulong *output, uint width, uint count) {
    size_t i = get_global_id(0);
    if (i >= (size_t)width * count) return;
    output[i] = input[indices[i / width] * width + i % width];
}
"#;

fn vector(spec: MatrixSpec) -> Result<(), String> {
    if spec.extension != Extension::Cubic
        || spec.columns != 1
        || spec.log_rows > 25
        || spec.order != RowOrder::BitReversed
        || spec.shift != 1
    {
        return Err("FRI requires a bit-reversed cubic subgroup vector".into());
    }
    Ok(())
}

impl DeviceSession {
    /// Read-only row pairing for the binary FRI commitment. The storage is
    /// unchanged and immutable; subsequent folds/mixes allocate fresh outputs.
    pub(crate) fn fri_leaves(&self, input: &DeviceMatrix) -> Result<DeviceMatrix, String> {
        self.check_owner(input)?;
        vector(input.spec)?;
        let log_rows = input
            .spec
            .log_rows
            .checked_sub(1)
            .ok_or("FRI commitment needs two rows")?;
        Ok(DeviceMatrix {
            storage: input.storage.clone(),
            private_random: input.private_random.clone(),
            session: self.session.clone(),
            spec: MatrixSpec::new(log_rows, 2, Extension::Cubic, RowOrder::BitReversed, 1)?,
        })
    }

    pub(crate) fn mix_fri(
        &self,
        folded: &DeviceMatrix,
        input: &DeviceMatrix,
        beta: [u64; 3],
    ) -> Result<DeviceMatrix, String> {
        self.check_owner(folded)?;
        self.check_owner(input)?;
        vector(folded.spec)?;
        if input.spec != folded.spec || beta.iter().any(|word| *word >= GOLDILOCKS_MODULUS) {
            return Err("FRI input mixing requires equal domains and canonical beta".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("device FRI input mixing is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let output = self.allocate(engine, folded.spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: equal cubic vector shapes bound every access. Separate
            // output preserves inputs retained by earlier commitments.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_fri_mix")
                    .arg(&folded.storage.buffer)
                    .arg(&input.storage.buffer)
                    .arg(&output.storage.buffer)
                    .arg(folded.spec.rows() as u32)
                    .arg(beta[0])
                    .arg(beta[1])
                    .arg(beta[2])
                    .global_work_size(folded.spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self.session.record_event(
                engine,
                crate::proving::Stage::FriFold,
                "device_fri_mix",
                &event,
            )?;
            fence.finish()?;
            let mut stats = self.session.stats.lock().unwrap();
            stats.fri_mixes += 1;
            stats.fri_mix_device_ns += ns;
            Ok(output)
        })
    }

    /// Explicit final-proof egress only: indices preserve caller order and may
    /// repeat. No full layer is downloaded to obtain a few queried rows.
    pub(crate) fn gather_rows(
        &self,
        input: &DeviceMatrix,
        indices: &[usize],
        host_allowance: usize,
    ) -> Result<Vec<u64>, String> {
        self.gather_rows_stage(
            input,
            indices,
            host_allowance,
            crate::proving::Stage::FriQuery,
        )
    }

    pub(crate) fn final_polynomial(
        &self,
        input: &DeviceMatrix,
        log_blowup: usize,
    ) -> Result<Vec<u64>, String> {
        let rows = u32::try_from(log_blowup)
            .ok()
            .and_then(|bits| 1usize.checked_shl(bits))
            .ok_or("final polynomial geometry overflow")?;
        if input.spec.rows() != rows
            || input.spec.columns != 1
            || input.spec.extension != Extension::Cubic
        {
            return Err("final polynomial requires the final constant cubic FRI layer".into());
        }
        self.gather_rows_stage(input, &[0], 24, crate::proving::Stage::FinalPolynomial)
    }

    fn gather_rows_stage(
        &self,
        input: &DeviceMatrix,
        indices: &[usize],
        host_allowance: usize,
        stage: crate::proving::Stage,
    ) -> Result<Vec<u64>, String> {
        self.check_owner(input)?;
        let width = input
            .spec
            .columns
            .checked_mul(input.spec.extension.degree())
            .filter(|width| *width <= 16384)
            .ok_or("device gather width exceeds bound")?;
        if indices.is_empty()
            || indices.len() > 4096
            || indices.iter().any(|i| *i >= input.spec.rows())
        {
            return Err("device gather index count or row exceeds bound".into());
        }
        let words = indices.len() * width;
        if words * 8 > host_allowance {
            return Err("device gather exceeds host allowance".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            Err("device row gathering is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let live = engine.accounting.lock().unwrap().live;
            if words * 8 > engine.max_alloc
                || indices.len() * 8 > engine.max_alloc
                || live
                    .checked_add((words + indices.len()) * 8)
                    .is_none_or(|peak| peak > engine.limits.managed_bytes)
            {
                return Err("device gather exceeds GPU allowance".into());
            }
            let alloc = |words| {
                allocation(
                    &engine.pq,
                    &engine.accounting,
                    engine.limits,
                    engine.max_alloc,
                    words,
                    compute::flags::MEM_READ_WRITE,
                )
            };
            let index = alloc(indices.len())?;
            let output = alloc(words)?;
            let rows: Vec<_> = indices.iter().map(|i| *i as u64).collect();
            let mut values = vec![0u64; words];
            let fence = engine.fence();
            index.buffer.write(&rows).enq().map_err(|e| e.to_string())?;
            // SAFETY: all indices and dimensions were checked before upload;
            // the fence precedes release of input, index and output buffers.
            let mut event = compute::Event::empty();
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_gather_rows")
                    .arg(&input.storage.buffer)
                    .arg(&index.buffer)
                    .arg(&output.buffer)
                    .arg(width as u32)
                    .arg(indices.len() as u32)
                    .global_work_size(words)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.session
                .record_event(engine, stage, "device_gather_rows", &event)?;
            output
                .buffer
                .read(&mut values)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += rows.len() as u64 * 8;
            engine.stats.downloaded_bytes += words as u64 * 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += rows.len() as u64 * 8;
            stats.downloaded_bytes += words as u64 * 8;
            stats.gathered_rows += rows.len() as u64;
            stats.gathered_value_bytes += words as u64 * 8;
            if values.iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                return Err("device gather returned a noncanonical field value".into());
            }
            Ok(values)
        })
    }
}
