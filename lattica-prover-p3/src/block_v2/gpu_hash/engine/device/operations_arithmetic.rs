//! Raw coefficient egress for witness graph construction; no dense trace egress.
use super::random::SecretAllocation;
use super::*;
use crate::block_v2::native_gpu::operations_arithmetic::ArithmeticOperationSpec;
use crate::proving::{Backend, Run, Stage};

impl DeviceSession {
    pub(crate) fn research_arithmetic_output(
        &self,
        spec: &ArithmeticOperationSpec,
        input: &[u64],
        host_allowance: usize,
        run: &Run,
    ) -> Result<Vec<u64>, String> {
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|error| error.to_string())?;
        if input.len() != spec.input_words || spec.staging_bytes()? > host_allowance {
            return Err("raw arithmetic exceeds host admission".into());
        }
        self.with_engine(|engine| {
            let counts = [
                spec.input_words,
                spec.metadata.len(),
                spec.output_words,
                spec.work_items,
            ];
            let shapes = counts
                .map(|n| MatrixSpec::new(0, n, Extension::Base, RowOrder::Natural, 1))
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;
            let _plan = Self::plan(engine, &shapes)?;
            // Each allocation scrubs on drop, including partial-allocation or
            // kernel failure. The complete simultaneous geometry is admitted first.
            let raw = SecretAllocation::new(engine, counts[0])?;
            let metadata = SecretAllocation::new(engine, counts[1])?;
            let output = SecretAllocation::new(engine, counts[2])?;
            let status = SecretAllocation::new(engine, counts[3])?;
            let mut invalid = vec![0u64; spec.work_items];
            let fence = engine.fence();
            raw.buffer().write(input).enq().map_err(|e| e.to_string())?;
            metadata
                .buffer()
                .write(spec.metadata.as_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            status
                .buffer()
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: private descriptor fields can only be produced by bounded
            // constructors. Schedule indices and factors are admitted there;
            // raw value validity/overflow is checked by each disjoint GPU writer.
            unsafe {
                engine
                    .pq
                    .kernel_builder("pq_graph_arithmetic")
                    .arg(raw.buffer())
                    .arg(metadata.buffer())
                    .arg(output.buffer())
                    .arg(status.buffer())
                    .global_work_size(spec.work_items)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let elapsed = self
                .session
                .record_event(engine, Stage::WitnessTrace, "pq_graph_arithmetic", &event)
                .map_err(|error| {
                    run.observation_failed();
                    error
                })?;
            run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, elapsed)
                .map_err(|error| error.to_string())?;
            status
                .buffer()
                .read(invalid.as_mut_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = ((spec.input_words + spec.metadata.len()) * 8) as u64;
            let status_bytes = (spec.work_items * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += status_bytes;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += status_bytes;
            }
            if let Some((index, code)) = invalid.iter().enumerate().find(|(_, v)| **v != 0) {
                return Err(format!(
                    "raw arithmetic opcode {} invalid input at work item {index}, status {code}",
                    spec.metadata[0]
                ));
            }
            // Read only the small raw result after all status words are checked.
            // Buffer<u64> preserves i64 bit patterns; no field decoding occurs.
            let mut result = vec![0u64; spec.output_words];
            let fence = engine.fence();
            output
                .buffer()
                .read(result.as_mut_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let downloaded = (spec.output_words * 8) as u64;
            engine.stats.downloaded_bytes += downloaded;
            self.session.stats.lock().unwrap().downloaded_bytes += downloaded;
            Ok(result)
        })
    }
}
