//! Owned commitments can construct disjoint digest layers inside their final
//! tree. The opt-in host storage path avoids duplicate leaf/parent workspaces;
//! the default device storage path retains its existing allocation schedule.
use super::*;

pub(super) struct OwnedHashPlan {
    pub workspace: Option<Plan>,
    pub bytes: usize,
    pub largest_allocation: usize,
}

impl OwnedHashPlan {
    pub(super) fn new(
        height: usize,
        width: usize,
        limits: Limits,
        max_alloc: usize,
        slots: usize,
        mode: RetainedTreeStorageMode,
    ) -> Result<Self, String> {
        if mode == RetainedTreeStorageMode::Device {
            let plan = plan_slots(height, width, limits, max_alloc, slots)?;
            let bytes = plan
                .bytes
                .checked_sub(CONSTANT_BYTES + limits.staging_bytes + transport_bytes(limits))
                .ok_or("owned hash workspace accounting underflow")?;
            return Ok(Self {
                workspace: Some(plan),
                bytes,
                largest_allocation: plan.input.max(plan.leaves).max(plan.parents) * 8,
            });
        }
        limits.validate()?;
        if !matches!(slots, 1 | 2)
            || limits.staging_bytes % (slots * 8) != 0
            || limits.staging_bytes / slots < 32
            || limits.staging_bytes / slots > max_alloc
            || !height.is_power_of_two()
            || height > u32::MAX as usize
            || width == 0
            || width > u32::MAX as usize
        {
            return Err("direct retained hash geometry exceeds indexing or staging limits".into());
        }
        // Every later tree index is bounded by this before any hash dispatch.
        let layout = retained_layout(height, 0, max_alloc)?;
        DirectLayers::new(height, layout)?;
        Ok(Self {
            workspace: None,
            bytes: 0,
            largest_allocation: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectLayer {
    src_offset_words: u32,
    dst_offset_words: u32,
    n_out: u32,
}

struct DirectLayers {
    rows: usize,
    source: usize,
    destination: usize,
}

impl DirectLayers {
    fn new(height: usize, layout: RetainedLayout) -> Result<Self, String> {
        if !layout.cap_rows.is_power_of_two()
            || layout != retained_layout(height, layout.cap_rows.ilog2() as usize, usize::MAX)?
            || layout.elements > u32::MAX as usize
        {
            return Err("direct retained layer geometry mismatch or offset overflow".into());
        }
        Ok(Self {
            rows: height,
            source: 0,
            destination: height * 4,
        })
    }
}

#[cfg(all(test, feature = "gpu"))]
mod kernel_tests;

impl Iterator for DirectLayers {
    type Item = DirectLayer;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rows == 1 {
            return None;
        }
        self.rows /= 2;
        let layer = DirectLayer {
            src_offset_words: self.source as u32,
            dst_offset_words: self.destination as u32,
            n_out: self.rows as u32,
        };
        self.source = self.destination;
        self.destination += self.rows * 4;
        Some(layer)
    }
}

impl Engine {
    /// Leaves already occupy tree[0..4*height]. Caller holds a queue fence
    /// declared after the storage owner through all hash and download work.
    pub(super) fn finish_direct_retained_layers(
        &mut self,
        storage: &Allocation,
        height: usize,
        layout: RetainedLayout,
    ) -> Result<Vec<[Val; 4]>, String> {
        if storage.buffer.len() != layout.elements {
            return Err("direct retained tree allocation differs from its layout".into());
        }
        for layer in DirectLayers::new(height, layout)? {
            let mut event = Event::empty();
            // SAFETY: DirectLayers admits all offsets before dispatch. Source
            // and destination are disjoint layers in the same allocation;
            // the in-order queue completes each producer before its consumer.
            unsafe {
                self.pq
                    .kernel_builder("compress_retained_layer")
                    .global_work_size(layer.n_out as usize)
                    .arg(&storage.buffer)
                    .arg(layer.src_offset_words)
                    .arg(layer.dst_offset_words)
                    .arg(layer.n_out)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.stats.compress_kernel_ns += self.timeline.record("compress", &event)?;
        }
        let cap = self.download_buffer(&storage.buffer, layout.cap_offset, layout.cap_rows)?;
        if cap.capacity() != layout.cap_rows {
            return Err("retained tree cap capacity exceeds its reservation".into());
        }
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_layers_cover_exact_disjoint_regions_for_every_cap() {
        for log_height in 0..=20 {
            let height = 1 << log_height;
            for cap in 0..=log_height + 1 {
                let layout = retained_layout(height, cap, usize::MAX).unwrap();
                let mut end = height * 4;
                let mut source = 0;
                let mut n = height;
                for layer in DirectLayers::new(height, layout).unwrap() {
                    n /= 2;
                    assert_eq!(layer.n_out as usize, n);
                    assert_eq!(layer.src_offset_words as usize, source);
                    assert_eq!(layer.dst_offset_words as usize, end);
                    assert_eq!(source + n * 8, end);
                    source = end;
                    end += n * 4;
                }
                assert_eq!(n, 1);
                assert_eq!(end, layout.elements);
            }
        }
    }

    #[test]
    fn direct_layers_reject_mismatched_layout_before_dispatch() {
        let mut layout = retained_layout(16, 2, usize::MAX).unwrap();
        layout.cap_offset += 4;
        assert!(DirectLayers::new(16, layout).is_err());
        let huge = retained_layout(1 << 30, 0, usize::MAX).unwrap();
        assert!(DirectLayers::new(1 << 30, huge).is_err());
    }
}
