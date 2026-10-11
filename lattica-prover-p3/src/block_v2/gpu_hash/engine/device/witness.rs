//! GPU recursive witness and preprocessing construction. Immutable compiled
//! metadata can be reused across fresh sessions; private scratch cannot.
use super::*;
use crate::block_v2::machine::{
    gpu_program::{WitnessProgram, WitnessSchedule},
    ExecutionError,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WitnessError {
    Execution(ExecutionError),
    Device(String),
}
impl From<String> for WitnessError {
    fn from(error: String) -> Self {
        Self::Device(error)
    }
}

pub(crate) struct PreparedWitness {
    schedule: WitnessSchedule,
    metadata: Allocation,
    context: Arc<JobLease>,
}

/// Provenance for deterministic columns produced from immutable program
/// metadata. Private witness matrices cannot be supplied to this interface.
pub(crate) struct PreprocessingTrace {
    matrix: DeviceMatrix,
}
impl PreprocessingTrace {
    pub(crate) fn spec(&self) -> MatrixSpec {
        self.matrix.spec()
    }
    pub(super) fn matrix(&self) -> &DeviceMatrix {
        &self.matrix
    }
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        session.check_owner(&self.matrix)
    }
}

struct Plan {
    trace: MatrixSpec,
    scratch: [usize; 3],
    peak: usize,
}
impl Plan {
    fn new(
        program: &WitnessSchedule,
        live: usize,
        managed: usize,
        max_alloc: usize,
        host_allowance: usize,
    ) -> Result<Self, String> {
        let inputs = program
            .publics
            .checked_add(program.witnesses)
            .ok_or("witness input size overflow")?;
        if inputs
            .checked_mul(8)
            .and_then(|n| n.checked_add(8))
            .is_none_or(|n| n > host_allowance)
        {
            return Err("witness input/status staging exceeds host allowance".into());
        }
        let trace = MatrixSpec::new(
            program.height.ilog2(),
            program.trace_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let scratch = [program.wires.max(1), inputs.max(1), 1];
        let peak = admit(
            live,
            managed,
            max_alloc,
            &[trace.words(), scratch[0], scratch[1], scratch[2]],
        )?;
        Ok(Self {
            trace,
            scratch,
            peak,
        })
    }
}
fn admit(live: usize, managed: usize, max_alloc: usize, words: &[usize]) -> Result<usize, String> {
    let mut peak = live;
    for &n in words {
        let bytes = n.checked_mul(8).ok_or("witness allocation overflow")?;
        if bytes == 0 || bytes > max_alloc {
            return Err("witness allocation exceeds device limit".into());
        }
        peak = peak
            .checked_add(bytes)
            .ok_or("witness managed bytes overflow")?;
    }
    if peak > managed {
        return Err("witness work exceeds aggregate GPU allowance".into());
    }
    Ok(peak)
}
fn alloc(engine: &Engine, words: usize) -> Result<Allocation, String> {
    let mut output = allocation(
        &engine.pq,
        &engine.accounting,
        engine.limits,
        engine.max_alloc,
        words,
        compute::flags::MEM_READ_WRITE,
    )?;
    output._lease.mark_device()?;
    Ok(output)
}

// This scratch contains original witness words and evaluated wires. Drain and
// scrub before releasing its reservations, including errors and unwinds.
struct Scratch {
    buffers: [Allocation; 3],
    queue: compute::Queue,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for allocation in &self.buffers {
            if let Err(error) = allocation.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("witness_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("witness_scrub_drain", error);
        }
    }
}

impl DeviceSession {
    pub(crate) fn prepare_witness(
        &self,
        program: Arc<WitnessProgram>,
    ) -> Result<PreparedWitness, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = program;
            return Err("GPU witness construction is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            // Admit and allocate host launch storage before any device
            // allocation or instruction upload for this program.
            let schedule = WitnessSchedule::try_new(&program, program.schedule_host_bytes)
                .map_err(|e| format!("GPU witness schedule: {e:?}"))?;
            admit(
                engine.accounting.lock().unwrap().live,
                engine.limits.managed_bytes,
                engine.max_alloc,
                &[program.words.len()],
            )?;
            let metadata = alloc(engine, program.words.len())?;
            let fence = engine.fence();
            metadata
                .buffer
                .write(&program.words)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let bytes = program.words.len() as u64 * 8;
            engine.stats.uploaded_bytes += bytes;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += bytes;
            stats.witness_programs += 1;
            eprintln!(
                "bounded_gpu_witness_program instruction_upload_bytes={bytes} host_instruction_retained_bytes=0 host_schedule_bytes={}",
                schedule.storage_bytes()
            );
            Ok(PreparedWitness {
                schedule,
                metadata,
                context: engine._job_lease.clone(),
            })
        })
    }
}

impl PreparedWitness {
    pub(crate) fn preprocessing_trace(
        &self,
        session: &DeviceSession,
    ) -> Result<PreprocessingTrace, String> {
        Ok(PreprocessingTrace {
            matrix: self.preprocessing(session)?,
        })
    }

    fn check_context(&self, engine: &Engine) -> Result<(), String> {
        if !Arc::ptr_eq(&self.context, &engine._job_lease) {
            return Err("witness program belongs to another GPU context".into());
        }
        Ok(())
    }
    pub(crate) fn preprocessing(&self, session: &DeviceSession) -> Result<DeviceMatrix, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = session;
            return Err("GPU preprocessing is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        session.with_engine(|engine| {
            self.check_context(engine)?;
            let spec = MatrixSpec::new(
                self.schedule.height.ilog2(),
                self.schedule.preprocessing_width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?;
            let output = session.allocate(engine, spec)?;
            let fence = engine.fence();
            let mut event = compute::Event::empty();
            // SAFETY: the compiler validates every row/port address, the shared
            // context owns immutable metadata, and output geometry is admitted.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_preprocessing_rows")
                    .arg(&self.metadata.buffer)
                    .arg(&output.storage.buffer)
                    .global_work_size(spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            session.session.record_event(
                engine,
                crate::proving::Stage::Preprocessing,
                "device_preprocessing_rows",
                &event,
            )?;
            fence.finish()?;
            session.session.stats.lock().unwrap().preprocessing_rows += spec.rows() as u64;
            Ok(output)
        })
    }
    pub(crate) fn trace(
        &self,
        session: &DeviceSession,
        public: &[u64],
        witness: &[u64],
        host_allowance: usize,
    ) -> Result<DeviceMatrix, WitnessError> {
        if public.len() != self.schedule.publics {
            return Err(WitnessError::Execution(ExecutionError::PublicInputCount));
        }
        if witness.len() != self.schedule.witnesses {
            return Err(WitnessError::Execution(ExecutionError::WitnessCount));
        }
        if public
            .iter()
            .chain(witness)
            .any(|&v| v >= GOLDILOCKS_MODULUS)
        {
            return Err(WitnessError::Execution(ExecutionError::NonCanonicalField));
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (session, host_allowance);
            return Err(WitnessError::Device(
                "GPU witness construction is not implemented on Metal".into(),
            ));
        }
        #[cfg(feature = "gpu")]
        {
            let (output,status)=session.with_engine(|engine| {
                self.check_context(engine)?;
                let plan=Plan::new(&self.schedule,engine.accounting.lock().unwrap().live,
                    engine.limits.managed_bytes,engine.max_alloc,host_allowance)?;
                let output=session.allocate(engine,plan.trace)?;
                let scratch=Scratch {buffers:[alloc(engine,plan.scratch[0])?,alloc(engine,plan.scratch[1])?,alloc(engine,plan.scratch[2])?],queue:engine.pq.queue().clone()};
                let [wires,input,status]=&scratch.buffers;
                let fence=engine.fence();
                wires.buffer.cmd().fill(0u64,None).enq().map_err(|e|e.to_string())?;
                status.buffer.cmd().fill(0u64,None).enq().map_err(|e|e.to_string())?;
                if !public.is_empty() { input.buffer.write(public).offset(0).enq().map_err(|e|e.to_string())?; }
                if !witness.is_empty() { input.buffer.write(witness).offset(public.len()).enq().map_err(|e|e.to_string())?; }
                if !public.is_empty() {
 let mut event = compute::Event::empty();
                    // SAFETY: both buffers contain the complete public prefix.
                    unsafe { engine.pq.kernel_builder("device_witness_public")
                        .arg(&input.buffer).arg(&wires.buffer).arg(public.len() as u32)
                        .global_work_size(public.len()).build().map_err(|e|e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e|e.to_string())?; }
                session.session.record_event(engine, crate::proving::Stage::WitnessTrace, "device_witness_public", &event)?;
}
                for wave in &self.schedule.waves {
                    let mut event=compute::Event::empty();
                    // SAFETY: every instruction uses validated SSA addresses.
                    // Each wave reads only preceding waves/publics and writes
                    // disjoint wires; the in-order queue enforces dependencies.
                    unsafe { engine.pq.kernel_builder("device_witness_wave")
                        .arg(&self.metadata.buffer).arg(wave.start as u32).arg(wave.len() as u32)
                        .arg(&input.buffer).arg(&wires.buffer).arg(&status.buffer)
                        .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                        .global_work_size(wave.len()).build().map_err(|e|e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e|e.to_string())?; }
                    session.session.record_event(engine, crate::proving::Stage::WitnessTrace, "device_witness_wave",&event)?;
                }
                let mut status_word=[0u64;1];
                status.buffer.read(&mut status_word[..]).enq().map_err(|e|e.to_string())?;
                fence.finish()?;
                if status_word[0]==0 {
                    let mut event=compute::Event::empty();
                    // SAFETY: compiled row metadata and completed SSA values
                    // cover every output cell in the admitted natural-order trace.
                    unsafe { engine.pq.kernel_builder("device_witness_rows")
                        .arg(&self.metadata.buffer).arg(&wires.buffer).arg(&output.storage.buffer)
                        .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                        .global_work_size(plan.trace.rows()).build().map_err(|e|e.to_string())?
                        .cmd().enew(&mut event).enq().map_err(|e|e.to_string())?; }
                    session.session.record_event(engine, crate::proving::Stage::WitnessTrace, "device_witness_rows",&event)?;
                    fence.finish()?;
                }
                let upload=(public.len()+witness.len()) as u64*8;
                engine.stats.uploaded_bytes+=upload; engine.stats.downloaded_bytes+=8;
                let mut stats=session.session.stats.lock().unwrap();
                stats.uploaded_bytes+=upload; stats.downloaded_bytes+=8; stats.witness_status_bytes+=8;
                stats.witness_waves+=self.schedule.waves.len() as u64;
                if status_word[0]==0 { stats.witness_evaluations+=1; stats.witness_rows+=plan.trace.rows() as u64; }
                eprintln!("bounded_gpu_witness rows={} waves={} program_upload_bytes=0 input_upload_bytes={upload} status_readback_bytes=8 trace_upload_bytes=0 trace_readback_bytes=0 managed_peak_plan_bytes={} accepted={}",
                    plan.trace.rows(),self.schedule.waves.len(),plan.peak,status_word[0]==0);
                Ok((output,status_word[0]))
            })?;
            if status != 0 {
                return Err(WitnessError::Execution(ExecutionError::Unsatisfied));
            }
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests;
