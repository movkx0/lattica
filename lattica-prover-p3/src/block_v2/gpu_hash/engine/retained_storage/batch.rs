//! Bounded GPU gathering for all authentication paths of one retained tree.
use super::*;

pub(crate) const MAX_QUERIES: usize = 256;
pub(crate) const DEVICE_BYTES: usize = (MAX_QUERIES + MAX_QUERIES * QUERY_ELEMENTS) * 8;

impl Engine {
    /// Marshal contiguous child pairs through the existing pinned staging slot.
    /// The GPU still selects each sibling and assembles the authentication path.
    /// Scratch and transfers scale with query count/depth, not the retained tree.
    pub(super) fn upload_host_query_pairs(
        &mut self,
        tree: &RetainedTree,
        host: &HostBacking,
        indices: &[usize],
    ) -> Result<Allocation, String> {
        if host.words.len() != tree.layout.elements || self.staging[0].map.len() < 8 {
            return Err("host query pair storage geometry".into());
        }
        let pairs = indices.len() * tree.layout.path_len;
        let output = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            pairs * 8,
            compute::flags::MEM_READ_ONLY,
        )?;
        let fence = self.fence();
        let started = Instant::now();
        let chunk_pairs = self.staging[0].map.len() / 8;
        for first in (0..pairs).step_by(chunk_pairs) {
            let count = chunk_pairs.min(pairs - first);
            for (pair, target) in self.staging[0].map[..count * 8]
                .chunks_exact_mut(8)
                .enumerate()
            {
                let item = first + pair;
                let level = item % tree.layout.path_len;
                let index = indices[item / tree.layout.path_len];
                let rows = tree.height >> level;
                let parent_first = (index >> level) & !1;
                let offset = (2 * tree.height - 2 * rows + parent_first) * 4;
                target.copy_from_slice(
                    host.words
                        .get(offset..offset + 8)
                        .ok_or("host query pair outside retained tree")?,
                );
            }
            let mut event = Event::empty();
            let transfer = Instant::now();
            output
                .buffer
                .write(&self.staging[0].map[..count * 8])
                .offset(first * 8)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
            self.stats.upload_device_ns += self.timeline.record("tree_reload", &event)?;
            self.stats.uploaded_bytes += (count * 64) as u64;
        }
        fence.finish()?;
        self.stats.upload_and_marshal_ns += started.elapsed().as_nanos();
        Ok(output)
    }

    pub(super) fn open_retained_batch_buffer(
        &mut self,
        tree: &RetainedTree,
        source: &Buffer<u64>,
        indices: &[usize],
        sparse_pairs: bool,
    ) -> Result<Vec<Vec<[Val; 4]>>, String> {
        if indices.is_empty()
            || indices.len() > MAX_QUERIES
            || indices.iter().any(|&index| index >= tree.height)
            || tree.layout.path_len == 0
            || tree.layout.path_len * 4 > QUERY_ELEMENTS
            || source.len()
                != if sparse_pairs {
                    indices.len() * tree.layout.path_len * 8
                } else {
                    tree.layout.elements
                }
            || !Arc::ptr_eq(&tree._job_lease, &self._job_lease)
        {
            return Err("batched retained query geometry or epoch mismatch".into());
        }
        let started = Instant::now();
        let paths = indices
            .len()
            .checked_mul(tree.layout.path_len)
            .ok_or("batched query size overflow")?;
        let input_words: Vec<u64> = indices.iter().map(|&i| i as u64).collect();
        let input = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            input_words.len(),
            compute::flags::MEM_READ_ONLY,
        )?;
        let output = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            paths * 4,
            compute::flags::MEM_READ_WRITE,
        )?;
        let mut flat = vec![0u64; paths * 4];
        // Created after every GPU/host source owner: error paths drain before
        // either allocation or the asynchronous input backing can be dropped.
        let fence = self.fence();
        let mut upload = Event::empty();
        input
            .buffer
            .write(&input_words)
            .enew(&mut upload)
            .enq()
            .map_err(|e| e.to_string())?;
        self.stats.uploaded_bytes += (input_words.len() * 8) as u64;
        self.stats.upload_device_ns += self.timeline.record("upload", &upload)?;
        let mut event = Event::empty();
        // SAFETY: both dimensions and all indices were checked above; one work
        // item writes exactly one four-word node in the query-major output.
        unsafe {
            self.pq
                .kernel_builder(if sparse_pairs {
                    "retained_merkle_paths_pairs"
                } else {
                    "retained_merkle_paths"
                })
                .arg(source)
                .arg(&input.buffer)
                .arg(&output.buffer)
                .arg(tree.height as u32)
                .arg(tree.layout.path_len as u32)
                .arg(indices.len() as u32)
                .global_work_size(paths)
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
            if let Some(notify) = self.retained_query_submitted.take() {
                notify.send(()).unwrap();
            }
            return Err("injected retained-tree query failure".into());
        }
        self.retained_query_device_ns += self.timeline.record("path_gather", &event)?;
        let transfer = Instant::now();
        let mut read = Event::empty();
        // The default blocking read also keeps this host owner alive until completion.
        output
            .buffer
            .read(&mut flat[..])
            .enew(&mut read)
            .enq()
            .map_err(|e| e.to_string())?;
        self.stats.download_wall_ns += transfer.elapsed().as_nanos();
        self.stats.download_device_ns += self.timeline.record("download", &read)?;
        self.stats.downloaded_bytes += (flat.len() * 8) as u64;
        fence.finish()?;
        let decode = Instant::now();
        let mut result = Vec::new();
        result
            .try_reserve_exact(indices.len())
            .map_err(|_| "batched query outer allocation")?;
        for path in flat.chunks_exact(tree.layout.path_len * 4) {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(tree.layout.path_len)
                .map_err(|_| "batched query path allocation")?;
            owned.extend(
                path.chunks_exact(4)
                    .map(|node| core::array::from_fn(|i| Val::new(node[i]))),
            );
            result.push(owned);
        }
        self.stats.decode_ns += decode.elapsed().as_nanos();
        self.stats.download_and_decode_ns += transfer.elapsed().as_nanos();
        self.retained_query_count += indices.len() as u64;
        self.retained_query_wall_ns += started.elapsed().as_nanos();
        eprintln!("bounded_retained_query_batch queries={} path_len={} kernels=1 readbacks=1 fences=1 index_bytes={} output_bytes={}",
            indices.len(), tree.layout.path_len, input_words.len() * 8, paths * 32);
        Ok(result)
    }
}
