use super::*;
use crate::block_v2::native_gpu::operations_batch::{FieldStream, PackedWords, COMMITMENT_BATCH_WORDS};

impl DeviceSession {
    pub(crate) fn prepared_field_streams(&self, workspace: &RefCell<Option<Workspace>>,
        streams: &[FieldStream<'_>], run: &Run) -> Option<Result<Vec<[u64; 4]>, String>> {
        let count = streams.len();
        if !(1..=64).contains(&count) { return Some(Err("invalid tiled field stream count".into())); }
        // Every intermediate tile ends at an absorption boundary. Length order
        // is private packing order; the caller still receives original indices.
        let tile = (4096.min(COMMITMENT_BATCH_WORDS / count) / 4) * 4;
        let packed_words = tile * count;
        self.with_prepared(workspace, [packed_words, 6 * count, 4 * count, count], profile::FIELDS, run, |use_, engine| {
            let mut order: [usize; 64] = core::array::from_fn(|i| i);
            order[..count].sort_unstable_by_key(|&i| (core::cmp::Reverse(streams[i].words()), i));
            let maximum = streams[order[0]].words();
            let mut packed = PackedWords(vec![0; packed_words]);
            let mut descriptors = PackedWords(vec![0; 6 * count]);
            for stream in streams { profile::field_stream(stream.words()); }
            profile::batch_hashes(count);
            let lanes = use_.workspace.field_lanes;
            let name = tiled_field_kernel_name(lanes, use_.workspace.fused_fields);
            let kernel = use_.kernel(5);
            let fence = engine.fence();
            for begin in (0..maximum.max(1)).step_by(tile) {
                // Fixed-length backing is scrubbed on every exit, including
                // the unused tail of a shorter final tile.
                let mut packed_length = 0;
                for (slot, &index) in order[..count].iter().enumerate() {
                    let stream = streams[index];
                    let length = stream.words().saturating_sub(begin).min(tile);
                    let offset = packed_length;
                    packed_length += length;
                    descriptors.0[6 * slot..6 * slot + 2].copy_from_slice(&[offset as u64, length as u64]);
                    descriptors.0[6 * slot + 2..6 * slot + 6].copy_from_slice(&stream.initial);
                    for word in 0..length { packed.0[offset + word] = stream.word(begin + word); }
                }
                let upload = profile::metric(profile::UPLOAD);
                if packed_length != 0 { use_.buffer(0).write(&packed.0[..packed_length]).enq().map_err(|e| e.to_string())?; }
                use_.buffer(1).write(&descriptors.0).enq().map_err(|e| e.to_string())?;
                drop(upload);
                let setup = profile::metric(profile::KERNEL);
                kernel.set_arg(2, count as u32).map_err(|e| e.to_string())?;
                kernel.set_arg(3, u32::from(begin == 0)).map_err(|e| e.to_string())?;
                drop(setup);
                let mut event = compute::Event::empty();
                // SAFETY: fixed, admitted tile/descriptor/state prefixes and
                // disjoint per-stream roots; the queue orders all carry states.
                unsafe { kernel.cmd().global_work_size(count * lanes).enew(&mut event).enq().map_err(|e| e.to_string())?; }
                profile::field_kernel(lanes);
                self.prepared_event(engine, run, name, &event)?;
                self.prepared_transfer(engine, ((packed_length + descriptors.0.len()) * 8) as u64, 0);
            }
            let roots = self.batch_roots(use_, engine, count)?;
            fence.finish()?;
            let mut ordered = vec![[0; 4]; count];
            for (slot, &index) in order[..count].iter().enumerate() { ordered[index] = roots[slot]; }
            Ok(ordered)
        })
    }
}
