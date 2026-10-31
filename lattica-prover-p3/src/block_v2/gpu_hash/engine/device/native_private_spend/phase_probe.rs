//! Feature-only observation of the unchanged native spend schedule.
use super::*;
use crate::block_v2::native_gpu::private_spend::phase_oracle::{
    capacity_for, PrivatePhaseRecords, RECORD_WORDS,
};

const RECORD_BUFFER: usize = 6;
const CONTROL_BUFFER: usize = 7;
const CONTROL_WORDS: usize = 4;

pub(super) struct Capture {
    capacity: usize,
    record_words: usize,
    host_peak_bytes: usize,
    records: Option<PrivatePhaseRecords>,
}

impl Capture {
    pub(super) fn new(limits: SpendLimits) -> Result<Self, String> {
        let capacity = capacity_for(limits.max_attempts)?;
        let record_words = capacity
            .checked_mul(RECORD_WORDS)
            .ok_or("phase diagnostic record word overflow")?;
        let record_bytes = record_words
            .checked_mul(8)
            .ok_or("phase diagnostic record byte overflow")?;
        // The returned full-capacity owner and complete post-wipe readback
        // coexist. Include header/error staging and a conservative fixed pad.
        let host_peak_bytes = record_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * CONTROL_WORDS * 8 + 64 * 1024))
            .ok_or("phase diagnostic host staging overflow")?;
        Ok(Self {
            capacity,
            record_words,
            host_peak_bytes,
            records: None,
        })
    }

    pub(super) fn host_peak_bytes(&self) -> usize {
        self.host_peak_bytes
    }

    pub(super) fn extend_counts(&self, base: &[usize]) -> Result<Vec<usize>, String> {
        if base.len() != RECORD_BUFFER {
            return Err("phase diagnostic base buffer layout changed".into());
        }
        let mut counts = base.to_vec();
        counts.extend([self.record_words, CONTROL_WORDS]);
        Ok(counts)
    }

    pub(super) fn into_records(mut self) -> Result<PrivatePhaseRecords, String> {
        self.records
            .take()
            .ok_or_else(|| "phase diagnostic readback is incomplete".into())
    }

    fn event(
        &self,
        session: &DeviceSession,
        engine: &mut Engine,
        kernel: &ocl::Kernel,
        name: &'static str,
        run: &Run,
    ) -> Result<(), String> {
        let mut event = compute::Event::empty();
        // SAFETY: fixed, admitted disjoint buffers and one in-order owner;
        // capture's production arena, status and RNG arguments are read-only.
        unsafe {
            kernel
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = session
            .session
            .record_event(engine, Stage::WitnessTrace, name, &event)
            .map_err(|error| {
                run.observation_failed();
                error
            })?;
        run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns)
            .map_err(|e| e.to_string())
    }

    #[allow(deprecated)]
    pub(super) fn after_step(
        &self,
        session: &DeviceSession,
        engine: &mut Engine,
        program: &ocl::Program,
        scratch: &Scratch,
        step: usize,
        run: &Run,
    ) -> Result<(), String> {
        // In particular step21 norm rejection has no phase70 C checkpoint.
        if !matches!(step, 5 | 6 | 14 | 18 | 20 | 22 | 24) {
            return Ok(());
        }
        let kernel = ocl::Kernel::builder()
            .program(program)
            .queue(engine.pq.queue().clone())
            .name("pq_phase_capture")
            .global_work_size(1usize)
            .arg(&scratch.matrices[ARENA].storage.buffer)
            .arg(ARENA_WORDS as u64)
            .arg(&scratch.matrices[OFFSETS].storage.buffer)
            .arg(SLOT_OFFSETS.len() as u32)
            .arg(&scratch.matrices[RNG].storage.buffer)
            .arg_buf::<u32, _>(scratch.matrices[STATUS].storage.buffer.as_core())
            .arg(&scratch.matrices[RECORD_BUFFER].storage.buffer)
            .arg(self.record_words as u64)
            .arg(self.capacity as u64)
            .arg(&scratch.matrices[CONTROL_BUFFER].storage.buffer)
            .arg(CONTROL_WORDS as u64)
            .arg(step as u32)
            .build()
            .map_err(|e| e.to_string())?;
        self.event(session, engine, &kernel, "pq_phase_capture", run)?;
        // Do not return private record counts/cursors between attempts.
        let mut fatal = SecretReadback(vec![0; 1]);
        scratch.matrices[CONTROL_BUFFER]
            .storage
            .buffer
            .read(fatal.0.as_mut_slice())
            .offset(1)
            .enq()
            .map_err(|e| e.to_string())?;
        session.native_spend_transfers(engine, 0, 8)?;
        if fatal.0[0] != 0 {
            return Err("phase diagnostic capture failed".into());
        }
        Ok(())
    }

    pub(super) fn read_and_scrub(
        &mut self,
        session: &DeviceSession,
        engine: &mut Engine,
        program: &ocl::Program,
        scratch: &Scratch,
        run: &Run,
    ) -> Result<(), String> {
        let mut header = SecretReadback(vec![0; CONTROL_WORDS]);
        scratch.matrices[CONTROL_BUFFER]
            .storage
            .buffer
            .read(header.0.as_mut_slice())
            .enq()
            .map_err(|e| e.to_string())?;
        session.native_spend_transfers(engine, 0, (CONTROL_WORDS * 8) as u64)?;
        if header.0[1] != 0
            || header.0[2] != 0
            || header.0[3] != 24
            || header.0[0] < 16
            || header.0[0] > self.capacity as u64
        {
            return Err("phase diagnostic terminal record state is invalid".into());
        }
        let used = usize::try_from(header.0[0]).map_err(|_| "phase diagnostic count overflow")?;
        let mut output = PrivatePhaseRecords::zeroed(self.capacity, used)?;
        scratch.matrices[RECORD_BUFFER]
            .storage
            .buffer
            .read(output.words_mut())
            .enq()
            .map_err(|e| e.to_string())?;
        session.native_spend_transfers(engine, 0, (self.record_words * 8) as u64)?;
        drop(header);
        for (index, words) in [
            (RECORD_BUFFER, self.record_words),
            (CONTROL_BUFFER, CONTROL_WORDS),
        ] {
            let kernel = ocl::Kernel::builder()
                .program(program)
                .queue(engine.pq.queue().clone())
                .name("pq_wipe_words")
                .global_work_size(words)
                .arg(&scratch.matrices[index].storage.buffer)
                .arg(words as u64)
                .build()
                .map_err(|e| e.to_string())?;
            self.event(session, engine, &kernel, "pq_wipe_words", run)?;
        }
        for (index, words) in [
            (RECORD_BUFFER, self.record_words),
            (CONTROL_BUFFER, CONTROL_WORDS),
        ] {
            let mut zeros = SecretReadback(vec![0; words]);
            scratch.matrices[index]
                .storage
                .buffer
                .read(zeros.0.as_mut_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            session.native_spend_transfers(engine, 0, (words * 8) as u64)?;
            if zeros.0.iter().any(|&word| word != 0) {
                return Err("phase diagnostic record scrub failed".into());
            }
        }
        engine.pq.queue().finish().map_err(|e| e.to_string())?;
        // Original Scratch still owns all eight buffers and provides final
        // synchronous scrub/drain on every later error or unwind.
        self.records = Some(output);
        Ok(())
    }
}
