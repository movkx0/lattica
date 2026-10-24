//! Bounded arithmetic witness ownership; raw inputs and all scratch are retired
//! before the device trace enters the single-AIR prover.
use super::*;
use crate::block_v2::native_gpu::{arithmetic::ArithmeticSpec, GeneratedTrace};
use crate::proving::{Backend, Run, Stage};

struct Scratch {
    matrices: Vec<DeviceMatrix>,
    queue: compute::Queue,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for matrix in &self.matrices {
            if let Err(error) = matrix.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("research_arithmetic_scratch_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("research_arithmetic_scratch_scrub_drain", error);
        }
    }
}
fn words(n: usize) -> Result<MatrixSpec, String> {
    MatrixSpec::new(0, n, Extension::Base, RowOrder::Natural, 1)
}
impl DeviceSession {
    fn arithmetic_event(
        &self,
        engine: &mut Engine,
        run: &Run,
        stage: Stage,
        name: &'static str,
        event: &compute::Event,
    ) -> Result<(), String> {
        let ns = self
            .session
            .record_event(engine, stage, name, event)
            .map_err(|error| {
                run.observation_failed();
                error
            })?;
        run.observe_device(stage, Backend::OpenCl, 1, ns)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn research_arithmetic_trace(
        &self,
        spec: &ArithmeticSpec,
        input: &[u64],
        host_allowance: usize,
        run: &Run,
    ) -> Result<GeneratedTrace, String> {
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|error| error.to_string())?;
        }
        let host_words = input
            .len()
            .checked_add(spec.geometry.len())
            .and_then(|v| v.checked_add(spec.geometry[4] as usize))
            .ok_or("arithmetic staging overflow")?;
        if input.len() != spec.input_words
            || host_words
                .checked_mul(8)
                .is_none_or(|v| v > host_allowance || v > 64 << 20)
        {
            return Err("arithmetic raw input/metadata exceeds host admission".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (spec, input);
            Err("native arithmetic generators require OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let count = spec.geometry[4] as usize;
            let root_words = if spec.family() == 1 {
                count * 12
            } else {
                spec.public_words
            };
            let specs = [
                MatrixSpec::new(
                    spec.rows().ilog2(),
                    spec.width(),
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )?,
                words(spec.public_words)?,
                words(input.len())?,
                words(spec.geometry.len())?,
                words(root_words)?,
                words(count)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let trace = self.allocate(engine, specs[0])?;
            let public = self.allocate(engine, specs[1])?;
            let scratch = Scratch {
                matrices: specs[2..]
                    .iter()
                    .map(|&s| self.allocate(engine, s))
                    .collect::<Result<Vec<_>, _>>()?,
                queue: engine.pq.queue().clone(),
            };
            let raw = &scratch.matrices[0];
            let geometry = &scratch.matrices[1];
            let roots = &scratch.matrices[2];
            let status = &scratch.matrices[3];
            let fence = engine.fence();
            raw.storage
                .buffer
                .write(input)
                .enq()
                .map_err(|e| e.to_string())?;
            geometry
                .storage
                .buffer
                .write(spec.geometry.as_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            for matrix in [&trace, roots, status] {
                matrix
                    .storage
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let kernel = match spec.family() {
                1 => "pq_arithmetic_affine",
                2 => "pq_arithmetic_ntt",
                3 => "pq_arithmetic_mul",
                4 => "pq_arithmetic_permutation",
                5 => "pq_arithmetic_g_bound",
                6 => "pq_arithmetic_linear_map",
                _ => return Err("unknown arithmetic family".into()),
            };
            let mut event = compute::Event::empty();
            // SAFETY: immutable descriptor constructors validate every schedule
            // index and full output geometry. One work item owns each polynomial;
            // singleton families own the full admitted trace. Raw words are
            // validated on device before arithmetic or private-bank indexing.
            unsafe {
                engine
                    .pq
                    .kernel_builder(kernel)
                    .arg(&raw.storage.buffer)
                    .arg(&geometry.storage.buffer)
                    .arg(&trace.storage.buffer)
                    .arg(&roots.storage.buffer)
                    .arg(&status.storage.buffer)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(count)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.arithmetic_event(
                engine,
                run,
                Stage::WitnessTrace,
                "pq_arithmetic_trace",
                &event,
            )?;
            if spec.family() == 1 {
                let mut event = compute::Event::empty();
                // SAFETY: one work item folds count fixed-size root records into
                // the admitted trace's bundle columns and first four root words.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("pq_arithmetic_affine_bundle")
                        .arg(&geometry.storage.buffer)
                        .arg(&trace.storage.buffer)
                        .arg(&roots.storage.buffer)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(1)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                self.arithmetic_event(
                    engine,
                    run,
                    Stage::WitnessTrace,
                    "pq_arithmetic_bundle",
                    &event,
                )?;
            }
            if matches!(spec.family(), 2 | 3) {
                let mut event = compute::Event::empty();
                // SAFETY: disjoint row writers only fill admitted padding rows.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("pq_arithmetic_padding")
                        .arg(&geometry.storage.buffer)
                        .arg(&trace.storage.buffer)
                        .arg(&roots.storage.buffer)
                        .global_work_size(spec.rows())
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                self.arithmetic_event(
                    engine,
                    run,
                    Stage::WitnessTrace,
                    "pq_arithmetic_padding",
                    &event,
                )?;
            }
            let mut event = compute::Event::empty();
            // SAFETY: each row has exactly 94 Poseidon columns after pose_offset.
            unsafe {
                engine
                    .pq
                    .kernel_builder("pq_poseidon_trace_columns")
                    .arg(&trace.storage.buffer)
                    .arg(spec.width() as u32)
                    .arg(spec.geometry[3] as u32)
                    .arg(spec.rows() as u32)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(spec.rows())
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.arithmetic_event(
                engine,
                run,
                Stage::WitnessTrace,
                "pq_arithmetic_poseidon_columns",
                &event,
            )?;
            let mut event = compute::Event::empty();
            // SAFETY: roots contains at least public_words canonical field words.
            unsafe {
                engine
                    .pq
                    .kernel_builder("pq_arithmetic_public")
                    .arg(&roots.storage.buffer)
                    .arg(&public.storage.buffer)
                    .arg(spec.public_words as u32)
                    .global_work_size(spec.public_words)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.arithmetic_event(
                engine,
                run,
                Stage::PublicValues,
                "pq_arithmetic_public",
                &event,
            )?;
            let mut invalid = vec![0u64; count];
            status
                .storage
                .buffer
                .read(invalid.as_mut_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = ((input.len() + spec.geometry.len()) * 8) as u64;
            let downloaded = (count * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += downloaded;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += uploaded;
            stats.downloaded_bytes += downloaded;
            drop(stats);
            if let Some((index, code)) = invalid.iter().enumerate().find(|(_, v)| **v != 0) {
                return Err(format!(
                    "arithmetic family {} invalid witness at input {index}, status {code}",
                    spec.family()
                ));
            }
            drop(scratch);
            Ok(GeneratedTrace { trace, public })
        })
    }
}
