//! Feature-only sampler probe; uses the exact production program and kernels.
use super::*;
use crate::block_v2::native_gpu::private_spend::oracle::{
    PrivateSamples, SamplerEvidence, SamplerKeyWords, SamplerLimits,
};

const KEY_BUFFER: usize = 0;
const SAMPLE_BUFFER: usize = 1;
const RNG_BUFFER: usize = 2;
const STATUS_BUFFER: usize = 3;
const PROBE_PHASE: u32 = 100;

impl DeviceSession {
    fn sampler_probe_event(
        &self,
        engine: &mut Engine,
        kernel: &ocl::Kernel,
        name: &'static str,
        run: &Run,
    ) -> Result<(), String> {
        let mut event = compute::Event::empty();
        // SAFETY: fixed one-job ABI over the admitted, disjoint buffers below;
        // this in-order queue also owns readbacks and both cleanup paths.
        unsafe {
            kernel
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = self
            .session
            .record_event(engine, Stage::WitnessTrace, name, &event)
            .map_err(|error| {
                run.observation_failed();
                error
            })?;
        run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns)
            .map_err(|e| e.to_string())
    }

    fn sampler_probe_status(
        &self,
        engine: &mut Engine,
        scratch: &Scratch,
        phase: u32,
    ) -> Result<(), String> {
        let mut status = SecretReadback(vec![0; STATUS_WORDS]);
        scratch.matrices[STATUS_BUFFER]
            .storage
            .buffer
            .read(status.0.as_mut_slice())
            .enq()
            .map_err(|e| e.to_string())?;
        self.native_spend_transfers(engine, 0, (STATUS_WORDS * 8) as u64)?;
        // Packed little endian: fatal/outcome are the first u64, followed by
        // phase/reserved. Preserve the exact all-zero/expected-phase contract.
        // Only fixed error categories may escape; never print status words,
        // RNG cursors, private counters, keys or coefficients.
        if status.0[1] >> 32 != 0 || status.0[2..].iter().any(|&word| word != 0) {
            return Err("sampler diagnostic device status failed: reserved words".into());
        }
        if status.0[1] as u32 != phase {
            return Err("sampler diagnostic device status failed: phase mismatch".into());
        }
        if status.0[0] >> 32 != 0 {
            return Err("sampler diagnostic device status failed: unexpected outcome".into());
        }
        let fatal = status.0[0] as u32;
        if fatal != 0 {
            // Exact public ABI codes from bundle.cl. Combined/unknown codes
            // remain rejected, and no numeric value is included in the error.
            let message = match fatal {
                1 => "sampler diagnostic device status failed: invalid input",
                16 => "sampler diagnostic device status failed: counter exhausted",
                // Both public exhaustion constants use this ABI bit.
                32 => "sampler diagnostic device status failed: budget or uniform exhaustion",
                128 => "sampler diagnostic device status failed: numerical contract",
                _ => "sampler diagnostic device status failed: unrecognized fatal code",
            };
            return Err(message.into());
        }
        Ok(())
    }

    fn sampler_probe_scrub(
        &self,
        engine: &mut Engine,
        program: &ocl::Program,
        scratch: &Scratch,
        counts: &[usize; 4],
        run: &Run,
    ) -> Result<(), String> {
        for (matrix, &count) in scratch.matrices.iter().zip(counts) {
            let kernel = ocl::Kernel::builder()
                .program(program)
                .queue(engine.pq.queue().clone())
                .name("pq_wipe_words")
                .global_work_size(count)
                .arg(&matrix.storage.buffer)
                .arg(count as u64)
                .build()
                .map_err(|e| e.to_string())?;
            self.sampler_probe_event(engine, &kernel, "pq_wipe_words", run)?;
        }
        // Read every admitted word after completed GPU wipe events. The
        // fallback Scratch Drop still wipes/drains on any error or unwind.
        for (matrix, &count) in scratch.matrices.iter().zip(counts) {
            let mut zero_check = SecretReadback(vec![0; count]);
            matrix
                .storage
                .buffer
                .read(zero_check.0.as_mut_slice())
                .enq()
                .map_err(|e| e.to_string())?;
            self.native_spend_transfers(engine, 0, (count * 8) as u64)?;
            if zero_check.0.iter().any(|&word| word != 0) {
                return Err("sampler diagnostic scrub verification failed".into());
            }
        }
        engine.pq.queue().finish().map_err(|e| e.to_string())
    }

    #[allow(deprecated)]
    pub(crate) fn probe_native_private_sampler(
        &self,
        packed: SamplerKeyWords,
        profile: u32,
        rows: usize,
        limits: SamplerLimits,
        run: &Run,
    ) -> Result<(PrivateSamples, SamplerEvidence), String> {
        limits.validate(rows)?;
        if packed.0.len() != 32 {
            return Err("sampler diagnostic key geometry is invalid".into());
        }
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        self.with_engine(|engine| {
            let program = program(engine)?;
            let counts = [32, rows * 256, RNG_WORDS, STATUS_WORDS];
            let specs = counts
                .iter()
                .map(|&words| MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1))
                .collect::<Result<Vec<_>, _>>()?;
            let plan = Self::plan(engine, &specs)?;
            let managed_bytes = counts.iter().sum::<usize>() * 8;
            let mut scratch = Scratch {
                matrices: Vec::with_capacity(specs.len()),
                queue: engine.pq.queue().clone(),
            };
            // Scrub ownership is installed before a private byte is uploaded.
            for spec in specs {
                scratch.matrices.push(self.allocate(engine, spec)?);
            }
            let fence = engine.fence();
            let result = (|| -> Result<PrivateSamples, String> {
                for matrix in &scratch.matrices {
                    matrix
                        .storage
                        .buffer
                        .cmd()
                        .fill(0u64, None)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                scratch.matrices[KEY_BUFFER]
                    .storage
                    .buffer
                    .write(packed.0.as_slice())
                    .enq()
                    .map_err(|e| e.to_string())?;
                engine.pq.queue().finish().map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, 32 * 8, 0)?;
                drop(packed);

                let init = ocl::Kernel::builder()
                    .program(&program)
                    .queue(engine.pq.queue().clone())
                    .name("pq_private_rng_init")
                    .global_work_size(1usize)
                    .arg(&scratch.matrices[KEY_BUFFER].storage.buffer)
                    .arg(32u64)
                    .arg(0u64)
                    .arg(0u64)
                    .arg(&scratch.matrices[RNG_BUFFER].storage.buffer)
                    .arg(limits.random_call_limit)
                    .arg(limits.proposal_limit)
                    .arg(1u32)
                    .arg_buf::<u32, _>(scratch.matrices[STATUS_BUFFER].storage.buffer.as_core())
                    .build()
                    .map_err(|e| e.to_string())?;
                self.sampler_probe_event(engine, &init, "pq_private_rng_init", run)?;
                self.sampler_probe_status(engine, &scratch, 0)?;

                let name = if profile == 5 {
                    "pq_sample_one"
                } else {
                    "pq_sample_gaussian"
                };
                let selector = if profile == 5 { rows as u32 } else { profile };
                let sample = ocl::Kernel::builder()
                    .program(&program)
                    .queue(engine.pq.queue().clone())
                    .name(name)
                    .global_work_size(1usize)
                    .arg(&scratch.matrices[RNG_BUFFER].storage.buffer)
                    .arg(&scratch.matrices[SAMPLE_BUFFER].storage.buffer)
                    .arg((rows * 256) as u64)
                    .arg(0u64)
                    .arg(0u64)
                    .arg(selector)
                    .arg(1u32)
                    .arg_buf::<u32, _>(scratch.matrices[STATUS_BUFFER].storage.buffer.as_core())
                    .arg(PROBE_PHASE)
                    .build()
                    .map_err(|e| e.to_string())?;
                self.sampler_probe_event(engine, &sample, name, run)?;
                self.sampler_probe_status(engine, &scratch, PROBE_PHASE)?;

                let mut output = PrivateSamples {
                    words: vec![0; rows * 256],
                    counters: [0; 3],
                };
                scratch.matrices[SAMPLE_BUFFER]
                    .storage
                    .buffer
                    .read(output.words.as_mut_slice())
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, 0, (rows * 256 * 8) as u64)?;
                // Read only the final six u64 fields; expanded AES keys never
                // return to host. The readback owner scrubs even failed checks.
                let mut state_tail = SecretReadback(vec![0; 6]);
                scratch.matrices[RNG_BUFFER]
                    .storage
                    .buffer
                    .read(state_tail.0.as_mut_slice())
                    .offset(30)
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, 0, 6 * 8)?;
                if state_tail.0[0] > 1u64 << 32
                    || state_tail.0[1] != 0
                    || state_tail.0[3] != limits.random_call_limit
                    || state_tail.0[5] != limits.proposal_limit
                    || state_tail.0[2] > limits.random_call_limit
                    || state_tail.0[4] > limits.proposal_limit
                {
                    return Err("sampler diagnostic RNG state failed".into());
                }
                output.counters[0] = state_tail.0[0];
                output.counters[1] = state_tail.0[2];
                output.counters[2] = state_tail.0[4];
                Ok(output)
            })();
            // Attempt verified scrub on both sampling success and failure.
            // A scrub error takes precedence; Drop performs final scrub/drain.
            self.sampler_probe_scrub(engine, &program, &scratch, &counts, run)?;
            fence.finish()?;
            drop(scratch);
            drop(plan);
            let output = result?;
            Ok((
                output,
                SamplerEvidence {
                    profile,
                    rows,
                    managed_bytes,
                    scrub_verified: true,
                    kernel_source_sha256: SOURCE_SHA256,
                },
            ))
        })
    }
}
