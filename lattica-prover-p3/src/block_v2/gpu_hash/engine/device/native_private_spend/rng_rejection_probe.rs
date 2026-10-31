//! Feature-only controller; production RNG and rejection arithmetic are reused.
use super::*;
use crate::block_v2::native_gpu::private_spend::rng_rejection_oracle::{
    PrivateRejection, PrivateRngCalls, ProbeEvidence, ProbeInput, ProbeLimits, ProbeOutput,
    ProbeWords, COUNTER_END,
};

const KEY: usize = 0;
const DATA: usize = 1;
const STATE: usize = 2;
const FLAGS: usize = 3;
const GEOMETRY: usize = 4;
const PROGRESS: usize = 5;
const PHASE: u32 = 101;
const DIAGNOSTIC_SOURCE_SHA256: &str = "176b1b03414456982518fbc2331f0b8204ebe6e369f84ffcdcb29f3246db3295";

impl DeviceSession {
    fn rng_rejection_probe_event(
        &self, engine: &mut Engine, kernel: &ocl::Kernel, name: &'static str, run: &Run,
    ) -> Result<(), String> {
        let mut event = compute::Event::empty();
        // SAFETY: one admitted job, disjoint buffers, same in-order queue for
        // uploads, dispatches, readbacks and both cleanup paths.
        unsafe { kernel.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?; }
        let ns = self.session.record_event(engine, Stage::WitnessTrace, name, &event)
            .map_err(|error| { run.observation_failed(); error })?;
        run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns)
            .map_err(|e| e.to_string())
    }

    fn rng_rejection_probe_status(
        &self, engine: &mut Engine, scratch: &Scratch, phase: u32, rejection: bool,
    ) -> Result<SecretReadback, String> {
        let mut status = SecretReadback(vec![0; STATUS_WORDS]);
        scratch.matrices[FLAGS].storage.buffer.read(status.0.as_mut_slice())
            .enq().map_err(|e| e.to_string())?;
        self.native_spend_transfers(engine, 0, (STATUS_WORDS * 8) as u64)?;
        // Fatal and normal rejection are distinct. No failed probe obtains a
        // success report or private output; every admitted buffer is scrubbed.
        match status.0[0] as u32 {
            0 => {},
            16 => return Err("RNG/rejection probe counter exhausted".into()),
            32 => return Err("RNG/rejection probe call budget exhausted".into()),
            _ => return Err("RNG/rejection probe device status failed".into()),
        }
        if (status.0[0] >> 32) > u64::from(rejection)
            || status.0[1] != u64::from(phase)
            || status.0[2..].iter().any(|&word| word != 0)
        {
            return Err("RNG/rejection probe phase or outcome failed".into());
        }
        Ok(status)
    }

    fn rng_rejection_probe_scrub(
        &self, engine: &mut Engine, program: &ocl::Program, scratch: &Scratch,
        counts: &[usize; 6], run: &Run,
    ) -> Result<(), String> {
        for (matrix, &count) in scratch.matrices.iter().zip(counts) {
            let kernel = ocl::Kernel::builder().program(program)
                .queue(engine.pq.queue().clone()).name("pq_wipe_words")
                .global_work_size(count).arg(&matrix.storage.buffer).arg(count as u64)
                .build().map_err(|e| e.to_string())?;
            self.rng_rejection_probe_event(engine, &kernel, "pq_wipe_words", run)?;
        }
        for (matrix, &count) in scratch.matrices.iter().zip(counts) {
            let mut check = SecretReadback(vec![0; count]);
            matrix.storage.buffer.read(check.0.as_mut_slice()).enq()
                .map_err(|e| e.to_string())?;
            self.native_spend_transfers(engine, 0, (count * 8) as u64)?;
            if check.0.iter().any(|&word| word != 0) {
                return Err("RNG/rejection probe scrub verification failed".into());
            }
        }
        engine.pq.queue().finish().map_err(|e| e.to_string())
    }

    #[allow(deprecated)]
    pub(crate) fn probe_native_rng_rejection(
        &self, key: ProbeWords, input: ProbeInput, limits: ProbeLimits, run: &Run,
    ) -> Result<(ProbeOutput, ProbeEvidence), String> {
        if key.0.len() != 32 { return Err("RNG/rejection probe key geometry failed".into()); }
        let (data_words, progress_words, geometry, kind, total, initial_counter) = match &input {
            ProbeInput::Rng { lengths, total, initial_counter } => (
                total.div_ceil(8).max(1), lengths.len() * 2, lengths.clone(), None,
                *total, *initial_counter,
            ),
            ProbeInput::Rejection { kind, words } => (
                words.0.len(), 1,
                [0u64, 18, 29, 40, 49, 59, 77, 88, 99, 108]
                    .into_iter().map(|row| row * 256).collect(),
                Some(*kind), 0, 0,
            ),
        };
        limits.validate(data_words * 8, progress_words)?;
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        self.with_engine(|engine| {
            let program = program(engine)?;
            let counts = [32, data_words, RNG_WORDS, STATUS_WORDS, geometry.len(), progress_words];
            let specs = counts.iter()
                .map(|&n| MatrixSpec::new(0, n, Extension::Base, RowOrder::Natural, 1))
                .collect::<Result<Vec<_>, _>>()?;
            let plan = Self::plan(engine, &specs)?;
            let managed_bytes = counts.iter().sum::<usize>() * 8;
            let mut scratch = Scratch {
                matrices: Vec::with_capacity(specs.len()), queue: engine.pq.queue().clone(),
            };
            // Install cleanup ownership before uploading any private material.
            for spec in specs { scratch.matrices.push(self.allocate(engine, spec)?); }
            let fence = engine.fence();
            let result = (|| -> Result<ProbeOutput, String> {
                for matrix in &scratch.matrices {
                    matrix.storage.buffer.cmd().fill(0u64, None).enq()
                        .map_err(|e| e.to_string())?;
                }
                scratch.matrices[KEY].storage.buffer.write(key.0.as_slice())
                    .enq().map_err(|e| e.to_string())?;
                scratch.matrices[GEOMETRY].storage.buffer.write(geometry.as_slice())
                    .enq().map_err(|e| e.to_string())?;
                let input_words = if let ProbeInput::Rejection { words, .. } = &input {
                    scratch.matrices[DATA].storage.buffer.write(words.0.as_slice())
                        .enq().map_err(|e| e.to_string())?;
                    words.0.len()
                } else { 0 };
                engine.pq.queue().finish().map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, ((32 + geometry.len() + input_words) * 8) as u64, 0)?;
                drop(key);
                drop(input);
                let init = ocl::Kernel::builder().program(&program)
                    .queue(engine.pq.queue().clone()).name("pq_private_rng_init")
                    .global_work_size(1usize)
                    .arg(&scratch.matrices[KEY].storage.buffer).arg(32u64).arg(0u64).arg(0u64)
                    .arg(&scratch.matrices[STATE].storage.buffer)
                    .arg(limits.random_call_limit).arg(1u64).arg(1u32)
                    .arg_buf::<u32, _>(scratch.matrices[FLAGS].storage.buffer.as_core())
                    .build().map_err(|e| e.to_string())?;
                self.rng_rejection_probe_event(engine, &init, "pq_private_rng_init", run)?;
                drop(self.rng_rejection_probe_status(engine, &scratch, 0, false)?);

                let mut builder = ocl::Kernel::builder();
                builder.program(&program).queue(engine.pq.queue().clone()).global_work_size(1usize);
                let name = match kind {
                    None => {
                        builder.name("pq_private_rng_calls_probe")
                            .arg(&scratch.matrices[STATE].storage.buffer)
                            .arg(&scratch.matrices[GEOMETRY].storage.buffer).arg(geometry.len() as u32)
                            .arg(&scratch.matrices[DATA].storage.buffer).arg(total as u64)
                            .arg(&scratch.matrices[PROGRESS].storage.buffer).arg(progress_words as u64)
                            .arg(initial_counter);
                        "pq_private_rng_calls_probe"
                    },
                    Some(0 | 1) => {
                        let rows = if kind == Some(0) { 11u64 } else { 8u64 };
                        let name = if kind == Some(0) { "pq_reject_f" } else { "pq_reject_z" };
                        builder.name(name).arg(&scratch.matrices[STATE].storage.buffer)
                            .arg(&scratch.matrices[DATA].storage.buffer).arg(data_words as u64)
                            .arg(0u64).arg(rows * 256).arg(0u64).arg(1u32);
                        name
                    },
                    Some(2) => {
                        builder.name("pq_reject_op").arg(&scratch.matrices[STATE].storage.buffer)
                            .arg(&scratch.matrices[DATA].storage.buffer).arg(data_words as u64)
                            .arg(&scratch.matrices[GEOMETRY].storage.buffer).arg(10u32)
                            .arg(0u64).arg(1u32);
                        "pq_reject_op"
                    },
                    _ => return Err("rejection probe input shape is invalid".into()),
                };
                builder.arg_buf::<u32, _>(scratch.matrices[FLAGS].storage.buffer.as_core()).arg(PHASE);
                let kernel = builder.build().map_err(|e| e.to_string())?;
                self.rng_rejection_probe_event(engine, &kernel, name, run)?;
                let status = self.rng_rejection_probe_status(engine, &scratch, PHASE, kind.is_some())?;
                // Expanded AES keys never return to host. Only the six final
                // state fields are read into an owned, wiped diagnostic buffer.
                let mut tail = SecretReadback(vec![0; 6]);
                scratch.matrices[STATE].storage.buffer.read(tail.0.as_mut_slice()).offset(30)
                    .enq().map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, 0, 6 * 8)?;
                if tail.0[0] > COUNTER_END || tail.0[1] != 0
                    || tail.0[2] > limits.random_call_limit || tail.0[3] != limits.random_call_limit
                    || tail.0[4] != 0 || tail.0[5] != 1
                { return Err("RNG/rejection probe private state failed".into()); }
                if kind.is_some() {
                    if tail.0[0] != tail.0[2] || tail.0[2] > 1 {
                        return Err("rejection probe RNG consumption is invalid".into());
                    }
                    return Ok(ProbeOutput::Rejection(PrivateRejection {
                        result: [status.0[0] >> 32, tail.0[0], tail.0[2]],
                    }));
                }
                let mut output = PrivateRngCalls { bytes: vec![0; total], progress: vec![0; progress_words] };
                let mut words = SecretReadback(vec![0; data_words]);
                scratch.matrices[DATA].storage.buffer.read(words.0.as_mut_slice())
                    .enq().map_err(|e| e.to_string())?;
                scratch.matrices[PROGRESS].storage.buffer.read(output.progress.as_mut_slice())
                    .enq().map_err(|e| e.to_string())?;
                self.native_spend_transfers(engine, 0, ((data_words + progress_words) * 8) as u64)?;
                for (i, byte) in output.bytes.iter_mut().enumerate() {
                    *byte = (words.0[i / 8] >> ((i % 8) * 8)) as u8;
                }
                let mut counter = initial_counter;
                for (i, &length) in geometry.iter().enumerate() {
                    counter = counter.checked_add(length.div_ceil(16))
                        .ok_or("RNG probe counter metadata overflow")?;
                    if output.progress[2 * i] != counter || output.progress[2 * i + 1] != (i + 1) as u64 {
                        return Err("RNG probe call boundary accounting failed".into());
                    }
                }
                if tail.0[0] != counter || tail.0[2] != geometry.len() as u64 {
                    return Err("RNG probe final accounting failed".into());
                }
                Ok(ProbeOutput::Rng(output))
            })();
            // Scrub errors override operation results. Scratch Drop performs
            // an additional synchronous wipe/drain on every path and unwind.
            self.rng_rejection_probe_scrub(engine, &program, &scratch, &counts, run)?;
            fence.finish()?;
            drop(scratch);
            drop(plan);
            let output = result?;
            Ok((output, ProbeEvidence {
                managed_bytes, scrub_verified: true, kernel_source_sha256: SOURCE_SHA256,
                diagnostic_source_sha256: DIAGNOSTIC_SOURCE_SHA256,
            }))
        })
    }
}
