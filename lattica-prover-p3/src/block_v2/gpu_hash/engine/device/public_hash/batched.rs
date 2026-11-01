//! Bounded parallelism across independent public sponges, never within a stream.
use super::*;
use crate::proving::{Backend, Run, Stage};

pub(crate) const MAX_STREAMS: usize = crate::block_v2::machine::backend::identity_batch::MAX_IDENTITY_STREAMS;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct Footprint {
    pub host_bytes: u64,
    pub device_bytes: u64,
    pub max_allocation_bytes: u64,
}

impl Footprint {
    pub(crate) fn for_streams<I>(streams: usize) -> Result<Self, String> {
        if !(1..=MAX_STREAMS).contains(&streams) { return Err("public hash batch stream bound".into()); }
        let input = streams as u64 * BATCH_WORDS as u64 * 8;
        let device_bytes = input + streams as u64 * 64;
        let host_bytes = device_bytes + HOST_BYTES + 2 * std::mem::size_of::<I>() as u64
            + (streams * (std::mem::size_of::<Input<I>>() + std::mem::size_of::<Job<I>>()
                + 2 * std::mem::size_of::<Prefix>())) as u64;
        Ok(Self { host_bytes, device_bytes, max_allocation_bytes: input })
    }
}

pub(crate) struct Input<I> {
    pub domain: u64,
    pub total_fields: usize,
    pub prefix_fields: usize,
    pub fields: I,
}

/// Completed GPU capacity words. Only backend-owned tokens may cross epochs;
/// this primitive grants no program/phase authority and has no serialization.
pub(crate) struct Prefix {
    domain: u64,
    total_fields: usize,
    absorbed: usize,
    state: [u64; 4],
    selection: PublicHashSelection,
    origin: std::sync::Weak<JobLease>,
}

impl Prefix {
    pub(crate) fn origin_retired(&self) -> bool { self.origin.upgrade().is_none() }
}

struct Job<I> {
    domain: u64,
    total_fields: usize,
    count: usize,
    fields: I,
    state: Option<[u64; 4]>,
}

fn validate<I: Iterator<Item = Result<u64, String>> + Clone>(jobs: &[Job<I>]) -> Result<(), String> {
    if !(1..=MAX_STREAMS).contains(&jobs.len()) { return Err("public hash batch stream bound".into()); }
    for job in jobs {
        if job.domain >= GOLDILOCKS_MODULUS || job.total_fields as u128 >= GOLDILOCKS_MODULUS as u128
            || job.count > job.total_fields || job.state.is_some_and(|s| s.iter().any(|&v| v >= GOLDILOCKS_MODULUS))
        { return Err("public hash batch geometry or field".into()); }
        let mut fields = job.fields.clone();
        for _ in 0..job.count {
            if fields.next().ok_or("public hash batch short stream")?? >= GOLDILOCKS_MODULUS {
                return Err("public hash batch noncanonical field".into());
            }
        }
        if fields.next().is_some() { return Err("public hash batch long stream".into()); }
    }
    Ok(())
}

fn words(length: usize) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    out.try_reserve_exact(length).map_err(|_| "public hash batch host allocation")?;
    if out.capacity() != length { return Err("public hash batch host capacity".into()); }
    out.resize(length, 0);
    Ok(out)
}

impl DeviceSession {
    pub(crate) fn hash_public_prefix_batch<I>(
        &self, inputs: Vec<Input<I>>, run: &Run, host_allowance: u64,
    ) -> Result<Vec<Prefix>, String>
    where I: Iterator<Item = Result<u64, String>> + Clone {
        let selected = PublicHashSelection::from_env()?;
        if Footprint::for_streams::<I>(inputs.len())?.host_bytes > host_allowance {
            return Err("public hash batch host allowance".into());
        }
        // All structural and canonical checks precede any GPU work.
        if inputs.iter().any(|i| i.prefix_fields % 4 != 0) {
            return Err("public hash prefix is not rate aligned".into());
        }
        let mut jobs: Vec<_> = inputs.into_iter().map(|i| Job {
            domain: i.domain, total_fields: i.total_fields, count: i.prefix_fields, fields: i.fields, state: None,
        }).collect();
        let states = self.hash_public_batch(&mut jobs, selected, run, host_allowance)?;
        Ok(jobs.into_iter().zip(states).map(|(job, state)| Prefix {
            domain: job.domain, total_fields: job.total_fields, absorbed: job.count, state, selection: selected,
            origin: Arc::downgrade(&self.session.context),
        }).collect())
    }

    pub(crate) fn finish_public_prefix(
        &self, prefix: Prefix, suffix: &[u64], run: &Run, host_allowance: u64,
    ) -> Result<[u64; 4], String> {
        if prefix.total_fields.checked_sub(prefix.absorbed) != Some(suffix.len()) {
            return Err("public hash prefix suffix length changed".into());
        }
        if PublicHashSelection::from_env()? != prefix.selection {
            return Err("public hash prefix implementation changed".into());
        }
        let mut jobs = [Job { domain: prefix.domain, total_fields: prefix.total_fields,
            count: suffix.len(), fields: suffix.iter().copied().map(Ok), state: Some(prefix.state) }];
        let result = self.hash_public_batch(&mut jobs, prefix.selection, run, host_allowance)?;
        self.session.stats.lock().unwrap().public_hash_calls += 1;
        Ok(result[0])
    }

    fn hash_public_batch<I>(
        &self, jobs: &mut [Job<I>], selected: PublicHashSelection, run: &Run, host_allowance: u64,
    ) -> Result<Vec<[u64; 4]>, String>
    where I: Iterator<Item = Result<u64, String>> + Clone {
        run.check_device_stage(Stage::Preprocessing, Backend::OpenCl).map_err(|e| e.to_string())?;
        let footprint = Footprint::for_streams::<I>(jobs.len())?;
        if footprint.host_bytes > host_allowance { return Err("public hash batch host allowance".into()); }
        validate(jobs)?;
        self.with_engine(|engine| {
            selected.require_device(engine.pq.device())?;
            let n = jobs.len();
            let specs = [
                MatrixSpec::new(0, n * 4, Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, n * BATCH_WORDS, Extension::Base, RowOrder::Natural, 1)?,
                MatrixSpec::new(0, n * 4, Extension::Base, RowOrder::Natural, 1)?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let mut input = words(n * BATCH_WORDS)?;
            let mut state = words(n * 4)?;
            let mut meta = words(n * 4)?;
            for (i, job) in jobs.iter().enumerate() {
                state[4 * i..4 * i + 4].copy_from_slice(&job.state.unwrap_or([0; 4]));
            }
            let (name, lanes) = if selected == PublicHashSelection::SboxPairV1 {
                ("device_public_hash_batch_pair", 16)
            } else { ("device_public_hash_batch", 8) };
            // Driver resources are checked before allocating buffers or dispatch.
            let kernel = engine.pq.kernel_builder(name)
                .arg(None::<&ocl::Buffer<u64>>).arg(None::<&ocl::Buffer<u64>>).arg(None::<&ocl::Buffer<u64>>)
                .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                .global_work_size(n * lanes).local_work_size(lanes).build().map_err(|e| e.to_string())?;
            // Pair inspection also asserts its required 16-lane geometry.
            if lanes == 16 { selection::inspect_kernel(&kernel, engine.pq.device())?; }
            let execution = report::PublicHashExecution::validated_kernel(name, engine.nvidia_shuffle)?;
            let states = self.allocate(engine, specs[0])?;
            let inputs = self.allocate(engine, specs[1])?;
            let metadata = self.allocate(engine, specs[2])?;
            // Drop the kernel's argument references before the tracked owners.
            let kernel = kernel;
            kernel.set_arg(0, &states.storage.buffer).map_err(|e| e.to_string())?;
            kernel.set_arg(1, &inputs.storage.buffer).map_err(|e| e.to_string())?;
            kernel.set_arg(2, &metadata.storage.buffer).map_err(|e| e.to_string())?;
            let fence = engine.fence();
            states.storage.buffer.write(&state).enq().map_err(|e| e.to_string())?;
            let mut offset = 0usize;
            loop {
                let mut total = 0usize;
                let mut permutations = 0usize;
                for (i, job) in jobs.iter_mut().enumerate() {
                    let count = job.count.saturating_sub(offset).min(BATCH_WORDS);
                    meta[4 * i..4 * i + 4].copy_from_slice(&[
                        job.domain, job.total_fields as u64, u64::from(offset == 0 && job.state.is_none()), count as u64,
                    ]);
                    for slot in &mut input[i * BATCH_WORDS..i * BATCH_WORDS + count] {
                        *slot = job.fields.next().ok_or("public hash batch replay short")??;
                        if *slot >= GOLDILOCKS_MODULUS { return Err("public hash batch replay field".into()); }
                    }
                    total += count;
                    permutations += count.div_ceil(4);
                }
                if total == 0 && offset != 0 { break; }
                inputs.storage.buffer.write(&input).enq().map_err(|e| e.to_string())?;
                metadata.storage.buffer.write(&meta).enq().map_err(|e| e.to_string())?;
                let mut event = compute::Event::empty();
                // SAFETY: one fixed-size workgroup per admitted stream; buffers
                // have disjoint offsets, canonical metadata and initialized input.
                unsafe { kernel.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?; }
                let ns = engine.timeline.record(name, &event)?;
                engine.public_hash_execution.record(execution);
                run.observe_device(Stage::Preprocessing, Backend::OpenCl, 1, ns).map_err(|e| e.to_string())?;
                let uploaded = (input.len() + meta.len()) as u64 * 8;
                engine.stats.uploaded_bytes += uploaded;
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.public_hash_batches += 1;
                stats.public_hash_fields += total as u64;
                stats.public_hash_permutations += permutations as u64;
                stats.public_hash_device_ns += ns;
                drop(stats);
                offset = offset.checked_add(BATCH_WORDS).ok_or("public hash batch offset overflow")?;
            }
            for job in jobs.iter_mut() {
                if job.fields.next().is_some() { return Err("public hash batch replay long".into()); }
            }
            states.storage.buffer.read(&mut state).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += state.len() as u64 * 8;
            engine.stats.downloaded_bytes += state.len() as u64 * 8;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += state.len() as u64 * 8;
            stats.downloaded_bytes += state.len() as u64 * 8;
            if state.iter().any(|&v| v >= GOLDILOCKS_MODULUS) { return Err("public hash batch noncanonical output".into()); }
            Ok(state.chunks_exact(4).map(|s| s.try_into().unwrap()).collect())
        })
    }
}

#[cfg(test)]
mod tests;
