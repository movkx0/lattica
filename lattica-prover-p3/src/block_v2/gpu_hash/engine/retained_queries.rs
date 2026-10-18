//! Bounded Merkle path batches. Result order, including duplicates, is stable.
use super::*;

pub(super) const KERNEL_SRC: &str = r#"
__kernel void retained_merkle_paths(__global const ulong *tree,
    __global const ulong *indices, __global ulong *output,
    uint height, uint path_len, uint count) {
    size_t i=get_global_id(0);
    if(i >= (size_t)path_len*count) return;
    uint query=i/path_len, level=i%path_len;
    ulong rows=((ulong)height)>>level;
    ulong sibling=(indices[query]>>level)^1UL;
    ulong offset=(2UL*(ulong)height-2UL*rows+sibling)*4UL;
    for(uint limb=0;limb<4;++limb)output[i*4+limb]=tree[offset+limb];
}
"#;

impl RetainedTree {
    pub(in crate::block_v2::gpu_hash) fn open_many(
        &self,
        indices: &[usize],
        cap_height: usize,
    ) -> Result<Vec<Vec<[Val; 4]>>, String> {
        if indices.is_empty()
            || indices.len() > 256
            || indices.iter().any(|&i| i >= self.height)
            || retained_layout(self.height, cap_height, usize::MAX)? != self.layout
        {
            return Err("retained-tree query batch geometry mismatch".into());
        }
        #[cfg(feature = "gpu")]
        {
            let mut slot = ENGINE
                .get()
                .ok_or("GPU hashing was not initialized")?
                .lock()
                .map_err(|_| "GPU engine poisoned")?;
            let engine = slot.as_mut().ok_or("GPU hashing was shut down")?;
            if !Arc::ptr_eq(&engine._job_lease, &self._job_lease) {
                return Err("retained query batch belongs to another GPU context".into());
            }
            if engine.tuning.paths {
                return engine.open_retained_many(self, indices);
            }
        }
        indices.iter().map(|&i| self.open(i, cap_height)).collect()
    }
}

#[cfg(feature = "gpu")]
impl Engine {
    pub(super) fn open_retained_many(
        &mut self,
        tree: &RetainedTree,
        indices: &[usize],
    ) -> Result<Vec<Vec<[Val; 4]>>, String> {
        if indices.is_empty()
            || indices.len() > 256
            || indices.iter().any(|&i| i >= tree.height)
            || tree.layout.path_len > 32
            || !Arc::ptr_eq(&self._job_lease, &tree._job_lease)
        {
            return Err("retained query batch context or bounds mismatch".into());
        }
        if tree.layout.path_len == 0 {
            return Ok(indices.iter().map(|_| Vec::new()).collect());
        }
        let started = Instant::now();
        let count = indices.len() * tree.layout.path_len;
        let bytes = (indices.len() + count * 4) * 8;
        if bytes > 1 << 20 {
            return Err("retained query batch workspace allowance".into());
        }
        let live = self.accounting.lock().unwrap().live;
        if live
            .checked_add(bytes)
            .is_none_or(|n| n > self.limits.managed_bytes)
            || count * 32 > self.max_alloc
        {
            return indices
                .iter()
                .map(|&i| self.open_retained(tree, i))
                .collect();
        }
        let input = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            indices.len(),
            compute::flags::MEM_READ_ONLY,
        )?;
        let output = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            count * 4,
            compute::flags::MEM_READ_WRITE,
        )?;
        let mut words = [0u64; 256];
        for (dst, &index) in words.iter_mut().zip(indices) {
            *dst = index as u64;
        }
        let fence = self.fence();
        input
            .buffer
            .write(&words[..indices.len()])
            .enq()
            .map_err(|e| e.to_string())?;
        self.stats.uploaded_bytes += (indices.len() * 8) as u64;
        let mut event = Event::empty();
        // SAFETY: all indices and context owners were checked before enqueue;
        // each item writes one distinct four-word path node. The fence drains
        // before any borrowed host scratch or device allocation is released.
        unsafe {
            self.pq
                .kernel_builder("retained_merkle_paths")
                .arg(&tree.storage.buffer)
                .arg(&input.buffer)
                .arg(&output.buffer)
                .arg(tree.height as u32)
                .arg(tree.layout.path_len as u32)
                .arg(indices.len() as u32)
                .global_work_size(count)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_retained_query_after_enqueue) {
            self.injected_event = Some(event.clone());
            return Err("injected retained query batch failure".into());
        }
        self.timeline
            .launch("retained_merkle_paths", count, None, count * 32);
        self.retained_query_device_ns += self.timeline.record("path_gather_batch", &event)?;
        let flat = self.download_buffer(&output.buffer, 0, count)?;
        fence.finish()?;
        self.retained_query_count += indices.len() as u64;
        self.retained_query_wall_ns += started.elapsed().as_nanos();
        Ok(flat
            .chunks_exact(tree.layout.path_len)
            .map(|path| path.to_vec())
            .collect())
    }
}
