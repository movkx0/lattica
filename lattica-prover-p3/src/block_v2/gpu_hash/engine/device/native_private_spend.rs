//! Resident native spend controller. No host proof arithmetic or CPU fallback.
//! Private storage is scrubbed and the queue drained on every exit, including
//! unwind. A failed cleanup invokes the engine's existing fatal cleanup policy.
use super::*;
use crate::block_v2::native_gpu::private_spend::{
    input_layout, status, PackedSpendInputs, PrivateOutputKeys, PrivateSpendOutput, SpendEvidence,
    SpendLimits, PROOF_BYTES, STATEMENT_BYTES, STATUS_U32_WORDS,
};
use crate::proving::{Backend, Run, Stage};
mod layout;

#[cfg(feature = "native-spend-oracle")]
mod sampler_probe;
#[cfg(feature = "native-spend-oracle")]
mod rng_rejection_probe;

#[cfg(feature = "native-spend-oracle")]
mod phase_probe;
use layout::*;
#[cfg(feature = "gpu")]
mod dispatch;

const INPUT: usize = 0;
const ARENA: usize = 1;
const OFFSETS: usize = 2;
const RNG: usize = 3;
const STATUS: usize = 4;
const REJECTION_OFFSETS_BUFFER: usize = 5;
const RNG_WORDS: usize = 288 / 8;
const STATUS_WORDS: usize = STATUS_U32_WORDS / 2;
const PRELUDE_MASK: u32 = (1 << 6) - 1;
const ACCEPTED_MASK: u32 = ((1 << 26) - 1) ^ PRELUDE_MASK;

struct Scratch {
    matrices: Vec<DeviceMatrix>,
    queue: compute::Queue,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for matrix in &self.matrices {
            if let Err(error) = matrix.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("native_private_spend_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("native_private_spend_scrub_drain", error);
        }
    }
}
struct SecretReadback(Vec<u64>);
impl Drop for SecretReadback {
    fn drop(&mut self) {
        for value in &mut self.0 {
            // SAFETY: initialized, exclusively owned live staging storage.
            unsafe { std::ptr::write_volatile(value, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "gpu")]
fn program(engine: &mut Engine) -> Result<ocl::Program, String> {
    use ocl::core::{DeviceInfo, DeviceInfoResult};
    if let Some(program) = &engine.native_private_spend_program {
        return Ok(program.clone());
    }
    if !cfg!(target_endian = "little") {
        return Err("native spend packed ABI requires a little-endian host".into());
    }
    let device = engine.pq.device();
    let extensions = match device
        .info(DeviceInfo::Extensions)
        .map_err(|e| e.to_string())?
    {
        DeviceInfoResult::Extensions(value) => value,
        _ => return Err("native spend cannot read OpenCL device extensions".into()),
    };
    if !extensions.split_whitespace().any(|v| v == "cl_khr_fp64") {
        return Err("native spend requires OpenCL cl_khr_fp64".into());
    }
    if !matches!(
        device.info(DeviceInfo::EndianLittle),
        Ok(DeviceInfoResult::EndianLittle(true))
    ) {
        return Err("native spend byte ABI requires a little-endian OpenCL device".into());
    }
    let required = ocl::flags::FP_DENORM
        | ocl::flags::FP_INF_NAN
        | ocl::flags::FP_ROUND_TO_NEAREST
        | ocl::flags::FP_FMA;
    match device
        .info(DeviceInfo::DoubleFpConfig)
        .map_err(|e| e.to_string())?
    {
        DeviceInfoResult::DoubleFpConfig(flags) if flags.contains(required) => {}
        _ => return Err("native spend requires FP64 denormals, nearest-even and FMA".into()),
    }
    // Separate from the integer STARK program: FP64 is required by the native
    // reference sampler, not by unrelated STARK users. Deliberately no fast
    // math, denorm flushing, native approximations or implicit contraction.
    engine.context_checkpoint("native private spend program admission")?;
    let mut builder = ocl::Program::builder();
    builder.devices(device)
        .src(include_str!("native_private_spend/bundle.cl"))
        .cmplr_opt("-cl-std=CL1.2");
    #[cfg(feature = "native-spend-oracle")]
    builder.src(include_str!("native_private_spend/rng_probe.cl"));
    #[cfg(feature = "native-spend-oracle")]
    builder.src(include_str!("native_private_spend/phase_probe.cl"));
    let compiled = builder.build(engine.pq.context()).map_err(|e| e.to_string())?;
    engine.context_checkpoint("native private spend program compiled")?;
    engine.native_private_spend_program = Some(compiled.clone());
    Ok(compiled)
}

#[cfg(feature = "gpu")]
fn read_public(arena: &DeviceMatrix, offset: usize, bytes: usize) -> Result<Vec<u8>, String> {
    if bytes % 8 != 0
        || offset
            .checked_add(bytes / 8)
            .is_none_or(|end| end > ARENA_WORDS)
    {
        return Err("native spend public readback geometry is invalid".into());
    }
    let mut words = vec![0u64; bytes / 8];
    arena
        .storage
        .buffer
        .read(words.as_mut_slice())
        .offset(offset)
        .enq()
        .map_err(|e| e.to_string())?;
    let mut output = Vec::with_capacity(bytes);
    for word in words {
        output.extend_from_slice(&word.to_le_bytes());
    }
    Ok(output)
}

#[cfg(feature = "gpu")]
impl DeviceSession {
    fn native_spend_transfers(
        &self,
        engine: &mut Engine,
        uploaded: u64,
        downloaded: u64,
    ) -> Result<(), String> {
        let mut stats = self
            .session
            .stats
            .lock()
            .map_err(|_| "native spend session statistics poisoned")?;
        let eu = engine
            .stats
            .uploaded_bytes
            .checked_add(uploaded)
            .ok_or("native spend upload counter overflow")?;
        let ed = engine
            .stats
            .downloaded_bytes
            .checked_add(downloaded)
            .ok_or("native spend download counter overflow")?;
        let su = stats
            .uploaded_bytes
            .checked_add(uploaded)
            .ok_or("native spend session upload counter overflow")?;
        let sd = stats
            .downloaded_bytes
            .checked_add(downloaded)
            .ok_or("native spend session download counter overflow")?;
        engine.stats.uploaded_bytes = eu;
        engine.stats.downloaded_bytes = ed;
        stats.uploaded_bytes = su;
        stats.downloaded_bytes = sd;
        Ok(())
    }

    fn native_spend_step(
        &self,
        engine: &mut Engine,
        program: &ocl::Program,
        scratch: &Scratch,
        step: usize,
        limits: SpendLimits,
        run: &Run,
    ) -> Result<u32, String> {
        let descriptor = STEPS
            .get(step)
            .ok_or("native spend invalid schedule index")?;
        let mut dispatches = dispatch::preparations(engine, program, scratch, step)?;
        dispatches.push((
            descriptor.name,
            dispatch::build_step(engine, program, scratch, step, limits)?,
        ));
        for (name, kernel) in dispatches {
            let mut event = compute::Event::empty();
            // SAFETY: preparation first admits the original arena and bounds;
            // each parallel lane owns disjoint whole output polynomials. The
            // same in-order queue separates preparations, suffix and scrub.
            // A logical step receipt is issued only after all real events and
            // the original single64-byte status read below have succeeded.
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
                .map_err(|e| e.to_string())?;
        }
        let mut raw = [0u64; STATUS_WORDS];
        scratch.matrices[STATUS]
            .storage
            .buffer
            .read(&mut raw[..])
            .enq()
            .map_err(|e| e.to_string())?;
        self.native_spend_transfers(engine, 0, (STATUS_WORDS * 8) as u64)?;
        let mut words = [0u32; STATUS_U32_WORDS];
        for (i, value) in raw.into_iter().enumerate() {
            words[2 * i] = value as u32;
            words[2 * i + 1] = (value >> 32) as u32;
        }
        if words[status::ERROR] != 0 {
            return Err(format!(
                "native spend device reported fatal status bits {}",
                words[status::ERROR]
            ));
        }
        if words[3..].iter().any(|&v| v != 0) || words[status::PHASE] != descriptor.phase {
            return Err("native spend device status violates phase/reserved-word ABI".into());
        }
        match words[status::OUTCOME] {
            status::PENDING if step != 25 => Ok(status::PENDING),
            status::REJECTED if descriptor.may_reject => Ok(status::REJECTED),
            status::ACCEPTED if step == 25 => Ok(status::ACCEPTED),
            _ => Err("native spend device outcome violates the fixed dispatch schedule".into()),
        }
    }
}

impl DeviceSession {
    pub(crate) fn create_native_private_spend(
        &self,
        packed: PackedSpendInputs,
        limits: SpendLimits,
        run: &Run,
    ) -> Result<(PrivateSpendOutput, SpendEvidence), String> {
        #[cfg(feature = "native-spend-oracle")]
        {
            self.create_native_private_spend_inner(packed, limits, run, None)
        }
        #[cfg(not(feature = "native-spend-oracle"))]
        {
            self.create_native_private_spend_inner(packed, limits, run)
        }
    }

    #[cfg(feature = "native-spend-oracle")]
    pub(crate) fn create_native_private_spend_with_phases(
        &self,
        packed: PackedSpendInputs,
        limits: SpendLimits,
        run: &Run,
    ) -> Result<
        (
            PrivateSpendOutput,
            SpendEvidence,
            crate::block_v2::native_gpu::private_spend::phase_oracle::PrivatePhaseRecords,
        ),
        String,
    > {
        let mut capture = phase_probe::Capture::new(limits)?;
        let (output, evidence) =
            self.create_native_private_spend_inner(packed, limits, run, Some(&mut capture))?;
        Ok((output, evidence, capture.into_records()?))
    }

    fn create_native_private_spend_inner(
        &self,
        packed: PackedSpendInputs,
        limits: SpendLimits,
        run: &Run,
        #[cfg(feature = "native-spend-oracle")] mut capture: Option<&mut phase_probe::Capture>,
    ) -> Result<(PrivateSpendOutput, SpendEvidence), String> {
        limits.validate()?;
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        // Include simultaneous public word/byte readback and secret word/poly
        // staging. Input ownership/packing is separately admitted before entry.
        let host_peak = input_layout::BYTES
            .checked_add(2 * (STATEMENT_BYTES + PROOF_BYTES))
            .and_then(|n| n.checked_add(2 * 18 * 256 * 8))
            .and_then(|n| n.checked_add(64 * 1024))
            .ok_or("native spend host staging overflow")?;
        #[cfg(feature = "native-spend-oracle")]
        let host_peak = match capture.as_deref() {
            Some(capture) => host_peak
                .checked_add(capture.host_peak_bytes())
                .ok_or("phase diagnostic total host staging overflow")?,
            None => host_peak,
        };
        if host_peak > limits.host_bytes || packed.words().len() != input_layout::WORDS {
            return Err("native spend transfer staging exceeds host admission".into());
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (packed, limits, run);
            Err("native private spend requires OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let program = program(engine)?;
            let counts = [
                input_layout::WORDS,
                ARENA_WORDS,
                SLOT_OFFSETS.len(),
                RNG_WORDS,
                STATUS_WORDS,
                REJECTION_OFFSETS.len(),
            ];
            #[cfg(feature = "native-spend-oracle")]
            let counts = match capture.as_deref() {
                Some(capture) => capture.extend_counts(&counts)?,
                None => counts.to_vec(),
            };
            let specs = counts
                .iter()
                .map(|&words| MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1))
                .collect::<Result<Vec<_>, _>>()?;
            let plan = Self::plan(engine, &specs)?;
            let managed_bytes = counts
                .iter()
                .try_fold(0usize, |sum, &n| {
                    n.checked_mul(8).and_then(|bytes| sum.checked_add(bytes))
                })
                .ok_or("native spend device admission overflow")?;
            let mut scratch = Scratch {
                matrices: Vec::with_capacity(specs.len()),
                queue: engine.pq.queue().clone(),
            };
            // Install scrub ownership before uploading anything private.
            for spec in specs {
                scratch.matrices.push(self.allocate(engine, spec)?);
            }
            let fence = engine.fence();
            for matrix in &scratch.matrices {
                matrix
                    .storage
                    .buffer
                    .cmd()
                    .fill(0u64, None)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            scratch.matrices[INPUT]
                .storage
                .buffer
                .write(packed.words())
                .enq()
                .map_err(|e| e.to_string())?;
            scratch.matrices[OFFSETS]
                .storage
                .buffer
                .write(&SLOT_OFFSETS[..])
                .enq()
                .map_err(|e| e.to_string())?;
            scratch.matrices[REJECTION_OFFSETS_BUFFER]
                .storage
                .buffer
                .write(&REJECTION_OFFSETS[..])
                .enq()
                .map_err(|e| e.to_string())?;
            // Explicit completion before private host staging is destroyed.
            engine.pq.queue().finish().map_err(|e| e.to_string())?;
            self.native_spend_transfers(
                engine,
                ((input_layout::WORDS + SLOT_OFFSETS.len() + REJECTION_OFFSETS.len()) * 8) as u64,
                0,
            )?;
            drop(packed);
            let mut prelude = 0u32;
            for step in 0..6 {
                self.native_spend_step(engine, &program, &scratch, step, limits, run)?;
                #[cfg(feature = "native-spend-oracle")]
                if let Some(capture) = capture.as_deref_mut() {
                    capture.after_step(self, engine, &program, &scratch, step, run)?;
                }
                prelude |= 1 << step;
                if step == 2 {
                    // Import and RNG initialization consumed the packed witness.
                    scratch.matrices[INPUT]
                        .storage
                        .buffer
                        .cmd()
                        .fill(0u64, None)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
            }
            if prelude != PRELUDE_MASK {
                return Err("native spend prelude receipts incomplete".into());
            }
            let accepted = 'attempt: loop {
                let mut observed = 0u32;
                for step in 6..26 {
                    let outcome =
                        self.native_spend_step(engine, &program, &scratch, step, limits, run)?;
                    #[cfg(feature = "native-spend-oracle")]
                    if let Some(capture) = capture.as_deref_mut() {
                        capture.after_step(self, engine, &program, &scratch, step, run)?;
                    }
                    observed |= 1 << step;
                    if outcome == status::REJECTED {
                        continue 'attempt;
                    }
                    if outcome == status::ACCEPTED {
                        if observed != ACCEPTED_MASK {
                            return Err(
                                "native spend accepted without complete phase receipts".into()
                            );
                        }
                        break 'attempt observed;
                    }
                }
                return Err("native spend schedule ended without an acceptance decision".into());
            };
            let arena = &scratch.matrices[ARENA];
            let statement = read_public(arena, STATEMENT_BYTES_OFFSET, STATEMENT_BYTES)?;
            self.native_spend_transfers(engine, 0, STATEMENT_BYTES as u64)?;
            let proof = read_public(arena, PROOF_BYTES_OFFSET, PROOF_BYTES)?;
            self.native_spend_transfers(engine, 0, PROOF_BYTES as u64)?;
            let mut key_words = SecretReadback(vec![0; 18 * 256]);
            arena
                .storage
                .buffer
                .read(key_words.0.as_mut_slice())
                .offset(CK_OUT)
                .enq()
                .map_err(|e| e.to_string())?;
            self.native_spend_transfers(engine, 0, (18 * 256 * 8) as u64)?;
            let mut polys = vec![[0i64; 256]; 18];
            for (dst, src) in polys.iter_mut().flatten().zip(&key_words.0) {
                *dst = *src as i64;
            }
            let output_keys = PrivateOutputKeys::new(polys)?;
            drop(key_words);
            #[cfg(feature = "native-spend-oracle")]
            if let Some(capture) = capture.as_deref_mut() {
                capture.read_and_scrub(self, engine, &program, &scratch, run)?;
            }
            fence.finish()?;
            drop(scratch); // synchronously scrub before returning ownership
            drop(plan);
            Ok((
                PrivateSpendOutput {
                    statement,
                    proof,
                    output_keys,
                },
                SpendEvidence {
                    prelude_steps: prelude,
                    accepted_attempt_steps: accepted,
                    managed_bytes,
                    kernel_source_sha256: SOURCE_SHA256,
                },
            ))
        })
    }
}
