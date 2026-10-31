//! The protocol's domain-separated public hash, distinct from its transcript.
//! State and bounded input scratch stay on device across all message chunks.
use super::*;
use crate::block_v2::{commitment, machine::programs};

#[cfg(feature = "gpu")]
pub(crate) mod nvidia;
pub(crate) mod report;
mod selection;
#[cfg(feature = "gpu-tuning")]
pub(crate) mod batched;
pub(crate) use selection::Selection as PublicHashSelection;

pub(crate) const BATCH_WORDS: usize = 4096;
pub(crate) const WORKSPACE_BYTES: u64 = (BATCH_WORDS as u64 + 4) * 8;
pub(crate) const MAX_ALLOCATION_BYTES: u64 = BATCH_WORDS as u64 * 8;
pub(crate) const HOST_BYTES: u64 = 1 << 16;
// Static workgroup SRAM, separate from the unchanged global-buffer allowance.
// One workgroup owns one sequential sponge, with one state word per lane.
const HASH_LANES: usize = 8;
const COOPERATIVE_MIN_WORDS: usize = 64;

// Keep the default program byte-for-byte unchanged. The experimental entry
// point is compiled only by a build which explicitly enables gpu-tuning.
macro_rules! public_hash_source {
    ($extra:expr) => {
        concat!(r#"
__kernel void device_public_hash(__global ulong *state, __global const ulong *input,
    const ulong domain, const ulong length, const uint first, const uint count,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    ulong s[8];
    for (uint i = 0; i < 4; ++i) s[i] = first ? 0UL : state[i];
    if (first) { s[0] = domain; s[1] = length; }
    for (uint offset = 0; offset < count; offset += 4) {
        for (uint i = 0; i < 4; ++i)
            s[4 + i] = offset + i < count ? input[offset + i] : 0UL;
        perm8(s, rci, rcp, rcf, diag);
    }
    for (uint i = 0; i < 4; ++i) state[i] = gl_canon(s[i]);
}

#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
// One eight-item workgroup occupies lanes 0..7 of one NVIDIA warp. All lanes
// execute each exchange with the same active mask and source indices in 0..8.
// Volatile prevents eliminating or hoisting an exchange based only on this
// lane's inputs: its result also depends on the other participating lanes.
inline ulong public_hash_exchange(ulong value, uint source) {
    uint low, high;
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, 255;" : "=r"(low) : "r"((uint)value), "r"(source));
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, 255;" : "=r"(high) : "r"((uint)(value>>32)), "r"(source));
    return ((ulong)high<<32)|(ulong)low;
}
inline ulong public_hash_external(ulong value, uint lane, __local ulong *words) {
    ulong sum=gl_add(value, public_hash_exchange(value, lane^1u));
    sum=gl_add(sum, public_hash_exchange(sum, lane^2u));
    ulong next=public_hash_exchange(value, (lane&4u)|((lane+1u)&3u));
    ulong own=gl_add(sum, gl_add(value, gl_add(next,next)));
    ulong partner=public_hash_exchange(own, lane^4u);
    return gl_add(gl_add(own,own),partner);
}
inline ulong public_hash_internal(ulong value, uint lane, ulong diagonal,
                                 __local ulong *words) {
    ulong sum=gl_add(value, public_hash_exchange(value,lane^1u));
    sum=gl_add(sum, public_hash_exchange(sum,lane^2u));
    sum=gl_add(sum, public_hash_exchange(sum,lane^4u));
    return gl_add(gl_mul(value,diagonal),sum);
}
#else
inline ulong public_hash_external(ulong value, uint lane, __local ulong *words) {
    words[lane] = value;
    barrier(CLK_LOCAL_MEM_FENCE);
    const uint base = lane & 4u, other = lane ^ 4u;
    const uint next = base | ((lane + 1u) & 3u);
    ulong own_sum = gl_add(gl_add(words[base], words[base + 1u]),
                           gl_add(words[base + 2u], words[base + 3u]));
    const uint opposite = base ^ 4u;
    ulong other_sum = gl_add(gl_add(words[opposite], words[opposite + 1u]),
                             gl_add(words[opposite + 2u], words[opposite + 3u]));
    // The existing M4 row i is sum(x) + x[i] + 2*x[(i+1) mod 4].
    ulong own = gl_add(own_sum, gl_add(value, gl_add(words[next], words[next])));
    ulong partner = gl_add(other_sum,
        gl_add(words[other], gl_add(words[next ^ 4u], words[next ^ 4u])));
    ulong result = gl_add(gl_add(own, own), partner);
    // Every lane must finish reading before the next layer writes the scratch.
    barrier(CLK_LOCAL_MEM_FENCE);
    return result;
}

inline ulong public_hash_internal(ulong value, uint lane, ulong diagonal,
                                 __local ulong *words) {
    words[lane] = value;
    barrier(CLK_LOCAL_MEM_FENCE);
    ulong low = gl_add(gl_add(words[0], words[1]), gl_add(words[2], words[3]));
    ulong high = gl_add(gl_add(words[4], words[5]), gl_add(words[6], words[7]));
    ulong result = gl_add(gl_mul(value, diagonal), gl_add(low, high));
    barrier(CLK_LOCAL_MEM_FENCE);
    return result;
}

#endif

__attribute__((reqd_work_group_size(8, 1, 1)))
__kernel void device_public_hash_cooperative(__global ulong *state,
    __global const ulong *input, const ulong domain, const ulong length,
    const uint first, const uint count, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf,
    __global const ulong *diag) {
    const uint lane = get_local_id(0);
    __local ulong words[8];
    ulong value = lane < 4u && !first ? state[lane] : 0UL;
    if (first && lane < 2u) value = lane == 0u ? domain : length;
    const ulong diagonal = diag[lane];
    for (uint offset = 0; offset < count; offset += 4u) {
        if (lane >= 4u) {
            uint index = offset + lane - 4u;
            value = index < count ? input[index] : 0UL;
        }
        value = public_hash_external(value, lane, words);
        #if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
for (uint round = 0; round < 4u; ++round) {
            value = gl_pow7(gl_add(value, rci[round * 8u + lane]));
            value = public_hash_external(value, lane, words);
        }
        #if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
for (uint round = 0; round < 22u; ++round) {
            if (lane == 0u) value = gl_pow7(gl_add(value, rcp[round]));
            value = public_hash_internal(value, lane, diagonal, words);
        }
        #if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
for (uint round = 0; round < 4u; ++round) {
            value = gl_pow7(gl_add(value, rcf[round * 8u + lane]));
            value = public_hash_external(value, lane, words);
        }
    }
    if (lane < 4u) state[lane] = gl_canon(value);
}

__kernel void device_validate_summary(__global const ulong *words, __global ulong *status,
    const ulong modes, const uint mode_index, const uint level_index,
    const uint count_index, const uint root_index, const uint max_level) {
    for (uint i = 0; i < 16; ++i) {
        if (words[i] > 0xffffffffUL) { status[0] = 1; return; }
    }
    const ulong mode = words[mode_index], level = words[level_index], count = words[count_index];
    if (mode == 0 || mode > modes || level > max_level) { status[0] = 2; return; }
    if (count > (1UL << level)) { status[0] = 2; return; }
    for (uint i = 0; i < 4; ++i) {
        if (words[root_index + i] >= 0xffffffff00000001UL) { status[0] = 3; return; }
    }
    status[0] = 0;
}
"#, $extra)
    };
}

#[cfg(not(feature = "gpu-tuning"))]
pub(crate) const KERNEL_SRC: &str = public_hash_source!("");
#[cfg(feature = "gpu-tuning")]
pub(crate) const KERNEL_SRC: &str = public_hash_source!(concat!(
    include_str!("public_hash/sbox_pair.cl"), include_str!("public_hash/batched.cl")
));

#[cfg(test)]
fn validate(domain: u64, fields: &[u64]) -> Result<u64, String> {
    let length = u64::try_from(fields.len()).map_err(|_| "GPU public hash length overflow")?;
    if domain >= GOLDILOCKS_MODULUS
        || length >= GOLDILOCKS_MODULUS
        || fields.iter().any(|&value| value >= GOLDILOCKS_MODULUS)
    {
        return Err("GPU public hash requires canonical fields, domain and length".into());
    }
    Ok(length)
}

type FieldSink<'a> = dyn FnMut(u64) -> Result<(), String> + 'a;

// Producers are replayed: validate every field and count before allocating a
// device buffer, then check the replay as it enters fixed-size upload scratch.
fn stream_length(
    domain: u64,
    produce: &mut impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
) -> Result<usize, String> {
    if domain >= GOLDILOCKS_MODULUS {
        return Err("GPU public hash requires a canonical domain".into());
    }
    let mut length = 0usize;
    let mut failed = false;
    produce(&mut |field| {
        let next = length.checked_add(1);
        if failed
            || field >= GOLDILOCKS_MODULUS
            || next.is_none_or(|n| n as u128 >= GOLDILOCKS_MODULUS as u128)
        {
            failed = true;
            return Err("GPU public hash requires canonical fields and length".into());
        }
        length = next.unwrap();
        Ok(())
    })?;
    if failed {
        return Err("GPU public hash rejected stream".into());
    }
    Ok(length)
}

fn batches(
    expected: usize,
    produce: &mut impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
    mut consume: impl FnMut(&[u64], bool) -> Result<(), String>,
) -> Result<(), String> {
    let mut scratch = [0u64; BATCH_WORDS];
    let mut received = 0usize;
    let mut used = 0usize;
    let mut first = true;
    let mut failed = false;
    produce(&mut |field| {
        if failed || received == expected || field >= GOLDILOCKS_MODULUS {
            failed = true;
            return Err("GPU public hash stream length or field changed".into());
        }
        scratch[used] = field;
        used += 1;
        received += 1;
        if used == BATCH_WORDS {
            // Latch failures even if a producer mistakenly ignores the error.
            failed = true;
            consume(&scratch, first)?;
            failed = false;
            first = false;
            used = 0;
        }
        Ok(())
    })?;
    if failed || received != expected {
        return Err("GPU public hash stream length or field changed".into());
    }
    if used != 0 || first {
        consume(&scratch[..used], first)?;
    }
    Ok(())
}

impl DeviceSession {
    /// Validate the fixed public statement on device, including the nonempty
    /// case which requires no hashing. Only a bounded status word is returned.
    pub(crate) fn validate_public_summary_reported(
        &self,
        words: &[u64; programs::PUBLIC_VALUES],
        modes: u64,
        run: &crate::proving::Run,
        stage: crate::proving::Stage,
    ) -> Result<(), String> {
        use crate::proving::Backend;
        run.check_device_stage(stage, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (words, modes);
            return Err("GPU public summary validation is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let specs = [
                MatrixSpec::new(
                    0,
                    programs::PUBLIC_VALUES,
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )?,
                MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let input = self.allocate(engine, specs[0])?;
            let status = self.allocate(engine, specs[1])?;
            let mut result = [u64::MAX];
            let fence = engine.fence();
            input
                .storage
                .buffer
                .write(&words[..])
                .enq()
                .map_err(|e| e.to_string())?;
            let mut event = compute::Event::empty();
            // SAFETY: one work item reads the fixed public layout and writes
            // one status word. Level is checked before the capacity shift.
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_validate_summary")
                    .arg(&input.storage.buffer)
                    .arg(&status.storage.buffer)
                    .arg(modes)
                    .arg(programs::MODE as u32)
                    .arg(programs::LEVEL as u32)
                    .arg(programs::COUNT as u32)
                    .arg(programs::ROOT as u32)
                    .arg(u32::from(commitment::DEPTH))
                    .global_work_size(1usize)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            let ns = engine.timeline.record("device_validate_summary", &event)?;
            status
                .storage
                .buffer
                .read(&mut result[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = std::mem::size_of_val(words) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 8;
            }
            // A validation rejection still represents completed device work.
            run.observe_device(stage, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())?;
            match result[0] {
                0 => Ok(()),
                1 => Err("noncanonical context limb".into()),
                2 => Err("node metadata range".into()),
                3 => Err(commitment::CommitmentError::NonCanonicalField.to_string()),
                _ => Err("GPU public summary validation returned an invalid status".into()),
            }
        })
    }

    pub(crate) fn hash_public_fields(
        &self,
        domain: u64,
        fields: &[u64],
    ) -> Result<[u64; 4], String> {
        self.hash_public_fields_inner(domain, fields, |_| Ok(()))
    }

    pub(crate) fn hash_public_fields_reported(
        &self,
        domain: u64,
        fields: &[u64],
        run: &crate::proving::Run,
        stage: crate::proving::Stage,
    ) -> Result<[u64; 4], String> {
        use crate::proving::Backend;
        run.check_device_stage(stage, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        self.hash_public_fields_inner(domain, fields, |ns| {
            run.observe_device(stage, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())
        })
    }

    fn hash_public_fields_inner(
        &self,
        domain: u64,
        fields: &[u64],
        after_batch: impl FnMut(u128) -> Result<(), String>,
    ) -> Result<[u64; 4], String> {
        self.hash_public_stream_inner(
            domain,
            |emit| {
                for &field in fields {
                    emit(field)?;
                }
                Ok(())
            },
            after_batch,
        )
    }

    pub(crate) fn hash_public_stream_reported(
        &self,
        domain: u64,
        produce: impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
        run: &crate::proving::Run,
        stage: crate::proving::Stage,
    ) -> Result<[u64; 4], String> {
        use crate::proving::Backend;
        run.check_device_stage(stage, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        self.hash_public_stream_inner(domain, produce, |ns| {
            run.observe_device(stage, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())
        })
    }

    fn hash_public_stream_inner(
        &self,
        domain: u64,
        produce: impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
        after_batch: impl FnMut(u128) -> Result<(), String>,
    ) -> Result<[u64; 4], String> {
        // Capture once, before reading the stream; a selector change cannot
        // change implementations halfway through a sequential sponge.
        let selected = PublicHashSelection::from_env()?;
        let result =
            self.hash_public_stream_selected(domain, produce, after_batch, true, selected)?;
        #[cfg(test)]
        if let Some(execution) = crate::block_v2::gpu_hash::engine::public_hash_execution()? {
            println!(
                "PUBLIC_HASH_EXECUTION {}",
                serde_json::to_string(&execution).map_err(|e| e.to_string())?
            );
        }
        Ok(result)
    }

    #[cfg(test)]
    fn hash_public_stream_kernel(
        &self,
        domain: u64,
        produce: impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
        after_batch: impl FnMut(u128) -> Result<(), String>,
        cooperative: bool,
    ) -> Result<[u64; 4], String> {
        self.hash_public_stream_selected(
            domain,
            produce,
            after_batch,
            cooperative,
            selection::Selection::Baseline,
        )
    }

    fn hash_public_stream_selected(
        &self,
        domain: u64,
        mut produce: impl FnMut(&mut FieldSink<'_>) -> Result<(), String>,
        mut after_batch: impl FnMut(u128) -> Result<(), String>,
        cooperative: bool,
        selected: selection::Selection,
    ) -> Result<[u64; 4], String> {
        let length = stream_length(domain, &mut produce)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (length, after_batch, cooperative, selected);
            return Err("GPU public hashing is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            selected.require_device(engine.pq.device())?;
            // Inspect the physical kernel before allocating output or upload
            // scratch. Null arguments are replaced only after admission; this
            // kernel is built once and reused for every batch, including tails.
            let paired = if selected == selection::Selection::SboxPairV1 {
                let kernel = engine
                    .pq
                    .kernel_builder("device_public_hash_sbox_pair")
                    .arg(None::<&ocl::Buffer<u64>>)
                    .arg(None::<&ocl::Buffer<u64>>)
                    .arg(domain)
                    .arg(length as u64)
                    .arg(0u32)
                    .arg(0u32)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(selection::PAIR_LANES)
                    .local_work_size(selection::PAIR_LANES)
                    .build()
                    .map_err(|e| e.to_string())?;
                let (local, private) = selection::inspect_kernel(&kernel, engine.pq.device())?;
                eprintln!("bounded_gpu_public_hash selection=sbox-pair-v1 gpu_tuning={} physical_lanes={} global_workspace_bytes={WORKSPACE_BYTES} max_allocation_bytes={MAX_ALLOCATION_BYTES} driver_local_bytes={local} driver_private_bytes_per_lane={private}",
                    cfg!(feature = "gpu-tuning"), selection::PAIR_LANES);
                Some(kernel)
            } else {
                None
            };
            let specs = [
                MatrixSpec::new(0, 4, Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, BATCH_WORDS, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let state = self.allocate(engine, specs[0])?;
            let input = self.allocate(engine, specs[1])?;
            // Kernels retain their arguments. Drop this owner before the
            // tracked buffers and their memory reservations are released.
            let paired = paired;
            if let Some(kernel) = &paired {
                kernel.set_arg(0, &state.storage.buffer).map_err(|e| e.to_string())?;
                kernel.set_arg(1, &input.storage.buffer).map_err(|e| e.to_string())?;
            }
            // Handles retain their buffer arguments and must drop before the
            // accounted buffers on success, refusal and callback failure.
            let mut baseline: Option<(&str, ocl::Kernel)> = None;
            let mut result = [0u64; 4];
            let fence = engine.fence();
            batches(length, &mut produce, |words, first| {
                if !words.is_empty() {
                    input
                        .storage
                        .buffer
                        .write(words)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let mut event = compute::Event::empty();
                let (kernel, lanes) = if paired.is_some() {
                    ("device_public_hash_sbox_pair", selection::PAIR_LANES)
                } else if cooperative && words.len() >= COOPERATIVE_MIN_WORDS {
                    ("device_public_hash_cooperative", HASH_LANES)
                } else {
                    ("device_public_hash", 1)
                };
                let execution = report::PublicHashExecution::validated_kernel(kernel, engine.nvidia_shuffle)?;
                // SAFETY: one workgroup owns the four capacity words. The
                // baseline cooperative kernel requires eight uniformly active
                // lanes. The opt-in pair kernel requires sixteen and executes
                // every exchange uniformly, including partial rounds; only
                // even lanes write the four state words. Its physical local
                // and private storage was checked before allocation. Every
                // full chunk is a multiple of the four-word rate; only the
                // final chunk is zero padded.
                unsafe {
                    if let Some(candidate) = &paired {
                        candidate.set_arg(4, u32::from(first)).map_err(|e| e.to_string())?;
                        candidate.set_arg(5, words.len() as u32).map_err(|e| e.to_string())?;
                        candidate.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    } else {
                        // Full chunks share one kernel. Only the final short
                        // tail can switch to scalar, so each is built once.
                        if baseline.as_ref().is_none_or(|(name, _)| *name != kernel) {
                        baseline = Some((kernel, engine
                        .pq
                        .kernel_builder(kernel)
                        .arg(&state.storage.buffer)
                        .arg(&input.storage.buffer)
                        .arg(domain)
                        .arg(length as u64)
                        .arg(u32::from(first))
                        .arg(words.len() as u32)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(lanes)
                        .local_work_size(lanes)
                        .build()
                        .map_err(|e| e.to_string())?));
                        }
                        let candidate = &baseline.as_ref().expect("selected baseline kernel").1;
                        candidate.set_arg(4, u32::from(first)).map_err(|e| e.to_string())?;
                        candidate.set_arg(5, words.len() as u32).map_err(|e| e.to_string())?;
                        candidate.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?;
                    }
                }
                let ns = engine.timeline.record(kernel, &event)?;
                engine.public_hash_execution.record(execution);
                engine.stats.uploaded_bytes += words.len() as u64 * 8;
                {
                    let mut stats = self.session.stats.lock().unwrap();
                    stats.uploaded_bytes += words.len() as u64 * 8;
                    stats.public_hash_batches += 1;
                    stats.public_hash_fields += words.len() as u64;
                    stats.public_hash_permutations += words.len().div_ceil(4) as u64;
                    stats.public_hash_device_ns += ns;
                }
                after_batch(ns)
            })?;
            state
                .storage
                .buffer
                .read(&mut result[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += 32;
            self.session.stats.lock().unwrap().downloaded_bytes += 32;
            if result.iter().any(|&value| value >= GOLDILOCKS_MODULUS) {
                return Err("GPU public hash result is not canonical".into());
            }
            self.session.stats.lock().unwrap().public_hash_calls += 1;
            Ok(result)
        })
    }
}

#[cfg(all(test, feature = "gpu"))]
mod cooperative_tests;
#[cfg(all(test, feature = "gpu", feature = "gpu-tuning"))]
mod sbox_pair_tests;
#[cfg(all(test, feature = "gpu", feature = "gpu-tuning"))]
mod fused_partial_probe;
#[cfg(all(test, feature = "gpu", feature = "gpu-tuning"))]
mod redux_sum_probe;
#[cfg(all(test, feature = "gpu", feature = "gpu-tuning"))]
mod serial_lane_probe;
#[cfg(all(test, feature = "gpu"))]
mod shuffle_tests;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "gpu"))]
mod unroll_tests;
