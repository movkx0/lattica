//! Device-owned wallet witness/public-value arithmetic. The explicit readback
//! adapter exists for differential tests and the unchanged single-AIR prover;
//! this component does not claim that wallet proof generation is GPU-complete.
use super::*;
use crate::joinsplit_air as js;
use p3_field::PrimeField64;
#[cfg(feature = "gpu")]
mod batch;
mod htlc;
mod proof_storage;
pub(crate) use proof_storage::{WalletDevicePlan, WalletProofMinimum};

/// A batch generates one single-wallet frame at a time. Bound its auxiliary
/// storage with the actual single/batch planners, including empty batches.
#[cfg(feature = "gpu")]
fn witness_storage_extra(host_allowance: usize) -> Result<(usize, usize), String> {
    batch::admission_extra(host_allowance)
}

#[cfg(not(feature = "gpu"))]
fn witness_storage_extra(_host_allowance: usize) -> Result<(usize, usize), String> {
    Err("wallet phase admission requires the owned OpenCL implementation".into())
}
#[cfg(feature = "gpu")]
mod tree;

pub(crate) struct WalletTrace {
    trace: DeviceMatrix,
    public: DeviceMatrix,
}
impl WalletTrace {
    /// Move the trace into the PCS session; only the public statement crosses
    /// the host boundary. No private trace words are decoded or retained here.
    pub(crate) fn into_proving_parts(
        self,
        session: &DeviceSession,
        host_allowance: usize,
    ) -> Result<(DeviceMatrix, Vec<u64>), String> {
        session.check_owner(&self.trace)?;
        session.check_owner(&self.public)?;
        let public = session.read(&self.public, host_allowance)?;
        Ok((self.trace, public))
    }

    pub(crate) fn trace(&self) -> &DeviceMatrix {
        &self.trace
    }
    pub(crate) fn public(&self) -> &DeviceMatrix {
        &self.public
    }
    pub(crate) fn readback(
        &self,
        session: &DeviceSession,
        host_allowance: usize,
    ) -> Result<(Vec<u64>, Vec<u64>), String> {
        let bytes = self
            .trace
            .spec
            .bytes()
            .checked_add(self.public.spec.bytes())
            .ok_or("wallet readback overflow")?;
        if bytes > host_allowance {
            return Err("wallet readback exceeds aggregate host allowance".into());
        }
        session.check_owner(&self.trace)?;
        session.check_owner(&self.public)?;
        let trace = session.read(&self.trace, host_allowance - self.public.spec.bytes())?;
        let public = session.read(&self.public, host_allowance - self.trace.spec.bytes())?;
        Ok((trace, public))
    }
}

pub(super) use crate::gpu_wallet::{
    input_words, staging_words, InputWords, Plan, GEOMETRY_WORDS, INPUT_WORDS,
};

struct Scratch {
    matrices: [DeviceMatrix; 3],
    queue: compute::Queue,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for matrix in &self.matrices {
            if let Err(error) = matrix.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("wallet_scratch_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("wallet_scratch_scrub_drain", error);
        }
    }
}

impl DeviceSession {
    pub(crate) fn joinsplit_witness(
        &self,
        witness: &js::Witness,
        host_allowance: usize,
        run: &crate::proving::Run,
    ) -> Result<WalletTrace, String> {
        self.generate_wallet(
            Plan::new(host_allowance)?,
            &js::device_trace_geometry(),
            || input_words(witness),
            [
                "device_joinsplit_regions",
                "device_joinsplit_columns",
                "device_joinsplit_public",
            ],
            run,
        )
    }

    fn generate_wallet(
        &self,
        plan: Plan,
        geometry: &[u64],
        inputs: impl FnOnce() -> Result<InputWords, String>,
        kernels: [&'static str; 3],
        run: &crate::proving::Run,
    ) -> Result<WalletTrace, String> {
        for stage in [
            crate::proving::Stage::WitnessTrace,
            crate::proving::Stage::PublicValues,
        ] {
            run.check_device_stage(stage, crate::proving::Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        if geometry.len() != plan.geometry_words {
            return Err("wallet geometry length mismatch".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (plan, inputs, kernels);
            return Err("wallet witness arithmetic is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let specs = plan.specs()?;
            let _plan = Self::plan(engine, &specs)?;
            let trace = self.allocate(engine, plan.trace)?;
            let public = self.allocate(engine, plan.public)?;
            let scratch = Scratch {
                matrices: [
                    self.allocate(engine, specs[2])?,
                    self.allocate(engine, specs[3])?,
                    self.allocate(engine, specs[4])?,
                ],
                queue: engine.pq.queue().clone(),
            };
            let words = inputs()?;
            if words.0.len() != plan.input_words {
                return Err("wallet input length mismatch".into());
            }
            let [input, geometry_buffer, status] = &scratch.matrices;
            let fence = engine.fence();
            input
                .storage
                .buffer
                .write(&words.0)
                .enq()
                .map_err(|e| e.to_string())?;
            geometry_buffer
                .storage
                .buffer
                .write(&geometry[..])
                .enq()
                .map_err(|e| e.to_string())?;
            trace
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: the shared AIR geometry and complete peak plan bound each
            // disjoint region and every uploaded input. The fence drains all
            // commands before host staging or device scratch can be dropped.
            unsafe {
                engine
                    .pq
                    .kernel_builder(kernels[0])
                    .arg(&input.storage.buffer)
                    .arg(&geometry_buffer.storage.buffer)
                    .arg(&trace.storage.buffer)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(plan.regions)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self
                .session
                .record_event(
                    engine,
                    crate::proving::Stage::WitnessTrace,
                    "wallet_trace",
                    &event,
                )
                .map_err(|error| {
                    run.observation_failed();
                    error
                })?;
            run.observe_device(
                crate::proving::Stage::WitnessTrace,
                crate::proving::Backend::OpenCl,
                1,
                ns,
            )
            .map_err(|error| error.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: one work item owns the two global columns of a valid row.
            unsafe {
                engine
                    .pq
                    .kernel_builder(kernels[1])
                    .arg(&input.storage.buffer)
                    .arg(&geometry_buffer.storage.buffer)
                    .arg(&trace.storage.buffer)
                    .global_work_size(plan.trace.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self
                .session
                .record_event(
                    engine,
                    crate::proving::Stage::WitnessTrace,
                    "wallet_trace",
                    &event,
                )
                .map_err(|error| {
                    run.observation_failed();
                    error
                })?;
            run.observe_device(
                crate::proving::Stage::WitnessTrace,
                crate::proving::Backend::OpenCl,
                1,
                ns,
            )
            .map_err(|error| error.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: one work item consumes completed rows, validates the
            // witness and writes exactly N_PUBLIC words plus one status word.
            unsafe {
                engine
                    .pq
                    .kernel_builder(kernels[2])
                    .arg(&input.storage.buffer)
                    .arg(&geometry_buffer.storage.buffer)
                    .arg(&trace.storage.buffer)
                    .arg(&public.storage.buffer)
                    .arg(&status.storage.buffer)
                    .global_work_size(1)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = self
                .session
                .record_event(
                    engine,
                    crate::proving::Stage::PublicValues,
                    "wallet_public_values",
                    &event,
                )
                .map_err(|error| {
                    run.observation_failed();
                    error
                })?;
            run.observe_device(
                crate::proving::Stage::PublicValues,
                crate::proving::Backend::OpenCl,
                1,
                ns,
            )
            .map_err(|error| error.to_string())?;
            let mut invalid = [0u64; 1];
            status
                .storage
                .buffer
                .read(&mut invalid[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = ((plan.input_words + plan.geometry_words) * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += uploaded;
            stats.downloaded_bytes += 8;
            drop(stats);
            if invalid[0] != 0 {
                return Err("invalid wallet witness".into());
            }
            Ok(WalletTrace { trace, public })
        })
    }
}

#[cfg(test)]
mod tests;
