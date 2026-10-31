//! Bounded raw-byte uploads and resident AES/SHAKE witnesses.
use super::*;
use crate::block_v2::native_gpu::GeneratedTrace;
use crate::proving::{Backend, Run, Stage};

pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = concat!(
    include_str!("pq_crypto/common.cl"),
    include_str!("pq_crypto/aes.cl"),
    include_str!("pq_crypto/shake.cl"),
);
const STAGING_WORDS: usize = 2048;
const SHAKE_PREP_WORDS: usize = 133;
const AES_TABLE_WORDS: usize = 256 * 66;
// Packed AES lane state: 15*(32 key +16 state) bytes and 14*16 S-box bytes.
const AES_LANE_STATE_WORDS: usize = 15 * (4 + 2) + 14 * 2;
const AES_LANE_HEADER_WORDS: usize = 7 * 4;

fn aes_lane_checkpoint_words(units: usize, padded_units: usize) -> Result<usize, String> {
    units
        .checked_mul(AES_LANE_STATE_WORDS + 4)
        .and_then(|words| {
            padded_units
                .checked_mul(3)
                .and_then(|inverses| words.checked_add(inverses))
        })
        .and_then(|words| words.checked_add(AES_LANE_HEADER_WORDS))
        .ok_or_else(|| "AES lane checkpoint scratch overflow".into())
}

struct CryptoPlan {
    specs: [MatrixSpec; 5],
    geometry: [u64; 12],
    rows: usize,
    units: usize,
    pose_offset: usize,
    pose_count: usize,
}
impl CryptoPlan {
    fn new(
        kind: u32,
        input_len: usize,
        output_len: usize,
        first: usize,
        units: usize,
        domain: u64,
        counter: u32,
        host: usize,
    ) -> Result<Self, String> {
        if kind > 4
            || input_len > u32::MAX as usize
            || output_len > u32::MAX as usize
            || units == 0
            || host < STAGING_WORDS * 8 + 12 * 8
        {
            return Err("crypto trace geometry exceeds admission".into());
        }
        let end = first.checked_add(units).ok_or("crypto segment overflow")?;
        let (rows, width, publics, scratch, pose_offset, pose_count) = if kind <= 1 {
            let total = output_len.div_ceil(16);
            if input_len != 32
                || output_len == 0
                || end > total
                || (kind == 1 && (first != 0 || units != total))
            {
                return Err("AES trace descriptor differs from segment".into());
            }
            let rows = units
                .checked_mul(if kind == 0 { 1024 } else { 14 })
                .and_then(usize::checked_next_power_of_two)
                .ok_or("AES rows overflow")?;
            let scratch = end
                .checked_mul(16)
                .and_then(|n| n.checked_add((units + 1) * 8 + 64 + AES_TABLE_WORDS))
                .ok_or("AES scratch overflow")?;
            let scratch = if kind == 0 {
                scratch
                    .checked_add(aes_lane_checkpoint_words(units, rows / 1024)?)
                    .ok_or("AES lane total scratch overflow")?
            } else {
                scratch
            };
            (
                rows,
                if kind == 0 { 417 } else { 3084 },
                if kind == 0 { 12 } else { 8 },
                scratch,
                if kind == 0 { 323 } else { 2896 },
                if kind == 0 { 1 } else { 2 },
            )
        } else {
            let absorb = input_len / 136 + 1;
            let total = absorb + output_len.saturating_sub(1) / 136;
            if end > total
                || (kind == 2 && units != 1)
                || (kind == 3
                    && (!units.is_power_of_two()
                        || !(end <= input_len / 136
                            || (first >= absorb && end <= absorb - 1 + output_len / 136))))
            {
                return Err("SHAKE trace descriptor differs from segment".into());
            }
            let rows = units
                .checked_mul(if kind == 4 { 24 } else { 4096 })
                .and_then(usize::checked_next_power_of_two)
                .ok_or("SHAKE rows overflow")?;
            let scratch = units
                .checked_mul(SHAKE_PREP_WORDS)
                .and_then(|n| n.checked_add(216))
                .ok_or("SHAKE scratch overflow")?;
            (
                rows,
                if kind == 4 {
                    4033
                } else if kind == 3 {
                    518
                } else {
                    517
                },
                216,
                scratch,
                if kind == 4 { 3845 } else { 423 },
                if kind == 4 { 2 } else { 1 },
            )
        };
        if rows > 1 << 24 {
            return Err("crypto trace exceeds row ceiling".into());
        }
        let spec = |rows: usize, width| {
            MatrixSpec::new(rows.ilog2(), width, Extension::Base, RowOrder::Natural, 1)
        };
        Ok(Self {
            specs: [
                spec(rows, width)?,
                spec(1, publics)?,
                spec(1, input_len.max(1))?,
                spec(1, scratch)?,
                spec(1, 12)?,
            ],
            geometry: [
                kind as u64,
                input_len as u64,
                output_len as u64,
                first as u64,
                units as u64,
                rows as u64,
                width as u64,
                domain,
                counter as u64,
                pose_offset as u64,
                pose_count as u64,
                publics as u64,
            ],
            rows,
            units,
            pose_offset,
            pose_count,
        })
    }
}

#[cfg(feature = "gpu")]
struct SensitiveScratch {
    values: [DeviceMatrix; 2],
    queue: compute::Queue,
}
#[cfg(feature = "gpu")]
impl Drop for SensitiveScratch {
    fn drop(&mut self) {
        for value in &self.values {
            if let Err(e) = value.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("crypto_scratch_scrub", e);
            }
        }
        if let Err(e) = self.queue.finish() {
            super::super::fatal_cleanup("crypto_scratch_scrub_drain", e);
        }
    }
}

impl DeviceSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn crypto_trace(
        &self,
        kind: u32,
        input: &[u8],
        domain: u64,
        counter: u32,
        input_len: usize,
        output_len: usize,
        first: usize,
        units: usize,
        host: usize,
        run: &Run,
    ) -> Result<GeneratedTrace, String> {
        if input.len() != input_len {
            return Err("crypto private input length mismatch".into());
        }
        let plan = CryptoPlan::new(
            kind, input_len, output_len, first, units, domain, counter, host,
        )?;
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        run.check_device_stage(Stage::PublicValues, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = plan;
            Err("crypto traces require OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            Self::plan(engine, &plan.specs)?;
            let trace = self.allocate(engine, plan.specs[0])?;
            let public = self.allocate(engine, plan.specs[1])?;
            let scratch = SensitiveScratch {
                values: [
                    self.allocate(engine, plan.specs[2])?,
                    self.allocate(engine, plan.specs[3])?,
                ],
                queue: engine.pq.queue().clone(),
            };
            let geometry = self.allocate(engine, plan.specs[4])?;
            let fence = engine.fence();
            let [source, temporary] = &scratch.values;
            let mut staging = [0u64; STAGING_WORDS];
            for (index, chunk) in input.chunks(STAGING_WORDS).enumerate() {
                for (dst, byte) in staging.iter_mut().zip(chunk) {
                    *dst = u64::from(*byte);
                }
                source
                    .storage
                    .buffer
                    .write(&staging[..chunk.len()])
                    .offset(index * STAGING_WORDS)
                    .enq()
                    .map_err(|e| e.to_string())?;
                engine.stats.uploaded_bytes += chunk.len() as u64 * 8;
                self.session.stats.lock().unwrap().uploaded_bytes += chunk.len() as u64 * 8;
            }
            staging.fill(0);
            geometry
                .storage
                .buffer
                .write(&plan.geometry[..])
                .enq()
                .map_err(|e| e.to_string())?;
            engine.stats.uploaded_bytes += 12 * 8;
            self.session.stats.lock().unwrap().uploaded_bytes += 12 * 8;
            for matrix in [&trace, &public, temporary] {
                matrix
                    .storage
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let launches: &[(&str, usize)] = if kind <= 1 {
                &[
                    ("pq_crypto_aes_sboxes", 256),
                    (
                        "pq_crypto_aes_encrypt",
                        if kind == 0 {
                            (first + units).max(plan.rows / 1024)
                        } else {
                            first + units
                        },
                    ),
                    ("pq_crypto_aes_prepare", 1),
                    (
                        "pq_crypto_aes_trace",
                        if kind == 0 { plan.rows } else { units },
                    ),
                ]
            } else {
                &[
                    ("pq_crypto_shake_prepare", 1),
                    (
                        "pq_crypto_shake_trace",
                        if kind == 4 {
                            plan.rows.div_ceil(24)
                        } else {
                            units
                        },
                    ),
                ]
            };
            let mut events = event_batch::EventBatch::for_run(engine, run, Stage::WitnessTrace);
            for &(name, work) in launches {
                let mut event = compute::Event::empty();
                // SAFETY: geometry and all five buffers are admitted before any enqueue;
                // kernels use disjoint per-unit outputs or one bounded sequential chain.
                unsafe {
                    events
                        .engine
                        .pq
                        .kernel_builder(name)
                        .arg(&source.storage.buffer)
                        .arg(&geometry.storage.buffer)
                        .arg(&temporary.storage.buffer)
                        .arg(&trace.storage.buffer)
                        .arg(&public.storage.buffer)
                        .arg(&events.engine.constants[0].buffer)
                        .arg(&events.engine.constants[1].buffer)
                        .arg(&events.engine.constants[2].buffer)
                        .arg(&events.engine.constants[3].buffer)
                        .global_work_size(work)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                events.record(name, event)?;
            }
            let mut event = compute::Event::empty();
            unsafe {
                events
                    .engine
                    .pq
                    .kernel_builder("pq_crypto_poseidon_rows")
                    .arg(&trace.storage.buffer)
                    .arg(plan.specs[0].columns() as u32)
                    .arg(plan.pose_offset as u32)
                    .arg(plan.pose_count as u32)
                    .arg(plan.rows as u64)
                    .arg(&events.engine.constants[0].buffer)
                    .arg(&events.engine.constants[1].buffer)
                    .arg(&events.engine.constants[2].buffer)
                    .arg(&events.engine.constants[3].buffer)
                    .global_work_size(plan.rows * plan.pose_count)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            events.record("pq_crypto_poseidon_rows", event)?;
            events.finish()?;
            // Derive the exact public vector from the device-owned segment boundaries.
            // It never crosses the host before the adapter validates shape and owner.
            let mut events = event_batch::EventBatch::for_run(engine, run, Stage::PublicValues);
            let mut event = compute::Event::empty();
            unsafe {
                events
                    .engine
                    .pq
                    .kernel_builder("pq_crypto_public_values")
                    .arg(&geometry.storage.buffer)
                    .arg(&temporary.storage.buffer)
                    .arg(&public.storage.buffer)
                    .global_work_size(plan.specs[1].columns())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            events.record("pq_crypto_public_canonicalize", event)?;
            events.finish()?;
            fence.finish()?;
            Ok(GeneratedTrace { trace, public })
        })
    }
}

#[cfg(test)]
mod tests;
