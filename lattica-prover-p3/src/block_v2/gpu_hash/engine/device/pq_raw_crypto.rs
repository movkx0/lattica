//! Raw graph-witness crypto operations. No trace allocations or native proofs.
use super::*;
use crate::proving::{Backend, Run, Stage};

pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = include_str!("pq_raw_crypto.cl");
const STAGING_WORDS: usize = 2048;
const AES_TABLE_WORDS: usize = 256 * 66;

struct RawPlan {
    specs: [MatrixSpec; 4],
    geometry: [u64; 5],
    output_words: usize,
}
impl RawPlan {
    fn new(
        kind: u32,
        input_len: usize,
        count: usize,
        domain: u64,
        counter: u32,
        host: usize,
    ) -> Result<Self, String> {
        let output_words = count.checked_add(1).ok_or("raw output size overflow")?;
        let host_need = output_words
            .checked_mul(16)
            .and_then(|n| n.checked_add(input_len))
            .and_then(|n| n.checked_add(80 << 10))
            .ok_or("raw crypto host bound overflow")?;
        if kind > 5
            || input_len > u32::MAX as usize
            || count > u32::MAX as usize
            || host_need > host
            || (kind == 0 && input_len != 32)
            || (kind == 4 && (input_len != 127 || count != 256))
            || (kind == 5 && (input_len != 137 || count != 256))
        {
            return Err("raw crypto geometry or host allowance rejected".into());
        }
        let spec = |words| MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1);
        Ok(Self {
            specs: [
                spec(input_len.max(1))?,
                spec(5)?,
                spec(if kind == 0 { AES_TABLE_WORDS } else { 1 })?,
                spec(output_words)?,
            ],
            geometry: [
                kind as u64,
                input_len as u64,
                count as u64,
                domain,
                counter as u64,
            ],
            output_words,
        })
    }
}

#[cfg(feature = "gpu")]
struct Staging([u64; STAGING_WORDS]);
#[cfg(feature = "gpu")]
impl Drop for Staging {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: each word is exclusively borrowed until this scope ends.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(feature = "gpu")]
struct Readback(Vec<u64>);
#[cfg(feature = "gpu")]
impl Drop for Readback {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: these private readback words remain owned by this guard.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl DeviceSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn raw_crypto_output(
        &self,
        kind: u32,
        input: &[u8],
        domain: u64,
        counter: u32,
        count: usize,
        host: usize,
        run: &Run,
    ) -> Result<Vec<u64>, String> {
        let plan = RawPlan::new(kind, input.len(), count, domain, counter, host)?;
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = plan;
            Err("raw crypto operations require OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            Self::plan(engine, &plan.specs)?;
            // Each allocation scrubs independently, including partial allocation
            // failures. Only bounded raw outputs leave the GPU.
            let input_buffer = random::SecretAllocation::new(engine, plan.specs[0].words())?;
            let geometry = random::SecretAllocation::new(engine, plan.specs[1].words())?;
            let scratch = random::SecretAllocation::new(engine, plan.specs[2].words())?;
            let output = random::SecretAllocation::new(engine, plan.specs[3].words())?;
            let fence = engine.fence();
            let mut staging = Staging([0; STAGING_WORDS]);
            for (index, chunk) in input.chunks(STAGING_WORDS).enumerate() {
                for (dst, byte) in staging.0.iter_mut().zip(chunk) {
                    *dst = u64::from(*byte);
                }
                input_buffer
                    .buffer()
                    .write(&staging.0[..chunk.len()])
                    .offset(index * STAGING_WORDS)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            geometry
                .buffer()
                .write(&plan.geometry[..])
                .enq()
                .map_err(|e| e.to_string())?;
            output
                .buffer()
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            let uploaded = (input.len() as u64 + 5) * 8;
            engine.stats.uploaded_bytes += uploaded;
            self.session.stats.lock().unwrap().uploaded_bytes += uploaded;
            let launches: &[(&str, usize)] = match kind {
                0 => &[
                    ("pq_raw_aes_sboxes", 256),
                    ("pq_raw_aes", count.div_ceil(16).max(1)),
                ],
                1 => &[("pq_raw_shake", 1)],
                2 | 3 => &[("pq_raw_uniform", 1)],
                4 | 5 => &[("pq_raw_sparse", 1)],
                _ => unreachable!("admitted raw operation"),
            };
            let mut events = event_batch::EventBatch::for_run(engine, run, Stage::WitnessTrace);
            for &(name, work) in launches {
                let mut event = compute::Event::empty();
                // SAFETY: all four buffers and exact raw lengths were admitted;
                // AES block outputs are disjoint, other operations are serial.
                unsafe {
                    events
                        .engine
                        .pq
                        .kernel_builder(name)
                        .arg(input_buffer.buffer())
                        .arg(geometry.buffer())
                        .arg(scratch.buffer())
                        .arg(output.buffer())
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
            events.finish()?;
            let mut words = Readback(Vec::new());
            words
                .0
                .try_reserve_exact(plan.output_words)
                .map_err(|_| "raw crypto readback allocation")?;
            words.0.resize(plan.output_words, 0);
            output
                .buffer()
                .read(&mut words.0)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let downloaded = plan.output_words as u64 * 8;
            engine.stats.downloaded_bytes += downloaded;
            self.session.stats.lock().unwrap().downloaded_bytes += downloaded;
            if words.0[count] != 0 {
                return Err("raw crypto bounded sampling stream exhausted".into());
            }
            words.0.pop();
            Ok(std::mem::take(&mut words.0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_crypto_plan_admits_all_live_buffers_and_rejects_bad_profiles() {
        for (kind, input, count) in [
            (0, 32, 49),
            (1, 0, 137),
            (2, 4788, 1024),
            (3, 186160, 37120),
            (4, 127, 256),
            (5, 137, 256),
        ] {
            let plan = RawPlan::new(kind, input, count, 0, u32::MAX, 4 << 20).unwrap();
            assert_eq!(plan.output_words, count + 1);
            let bytes = plan.specs.iter().map(|s| s.bytes()).sum::<usize>();
            let max = plan.specs.iter().map(|s| s.bytes()).max().unwrap();
            assert!(MemoryPlan::new(&plan.specs, 0, bytes, max).is_ok());
            assert!(MemoryPlan::new(&plan.specs, 0, bytes - 1, max).is_err());
            assert!(RawPlan::new(kind, input, count, 0, 0, 0).is_err());
        }
        for (kind, input, count) in [
            (6, 1, 1),
            (0, 31, 1),
            (4, 126, 256),
            (4, 127, 255),
            (5, 138, 256),
        ] {
            assert!(RawPlan::new(kind, input, count, 0, 0, 4 << 20).is_err());
        }
        assert!(RawPlan::new(1, 0, usize::MAX, 0, 0, usize::MAX).is_err());
    }
}
