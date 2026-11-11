//! Mixed-height MMCS layers use the existing full-tree allocation and fence.
use super::*;

impl Engine {
    pub(super) fn advance_mixed_lde_layers(
        &mut self,
        tree: &Allocation,
        rows: &mut usize,
        offset: &mut usize,
        target: usize,
    ) -> Result<(), String> {
        if !target.is_power_of_two() || target > *rows {
            return Err("mixed tree target height".into());
        }
        while *rows > target {
            let next = offset
                .checked_add(rows.checked_mul(4).ok_or("mixed tree offset")?)
                .ok_or("mixed tree offset")?;
            let count = *rows / 2;
            if next
                .checked_add(count * 4)
                .is_none_or(|end| end > tree.buffer.len())
                || next > u32::MAX as usize
                || *offset > u32::MAX as usize
            {
                return Err("mixed tree layer exceeds admitted allocation".into());
            }
            let mut event = Event::empty();
            // The caller's fence retains tree. Layers are disjoint; the
            // in-order queue completes each producer before its consumer.
            unsafe {
                self.pq
                    .kernel_builder("compress_retained_layer")
                    .arg(&tree.buffer)
                    .arg(*offset as u32)
                    .arg(next as u32)
                    .arg(count as u32)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .global_work_size(count)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.stats.compress_kernel_ns += self.timeline.record("mixed_compress", &event)?;
            *rows = count;
            *offset = next;
        }
        Ok(())
    }
    pub(super) fn finalize_mixed_lde_height(
        &mut self,
        sponge: &Allocation,
        tree: &Allocation,
        height: usize,
        offset: usize,
        rate: usize,
        inject: bool,
    ) -> Result<(), String> {
        if height
            .checked_mul(8)
            .is_none_or(|end| end > sponge.buffer.len())
            || offset
                .checked_add(height * 4)
                .is_none_or(|end| end > tree.buffer.len())
            || offset > u32::MAX as usize
            || height > u32::MAX as usize
            || rate >= 4
        {
            return Err("mixed tree leaf geometry".into());
        }
        let mut event = Event::empty();
        // Each work item modifies a distinct node after its compression.
        unsafe {
            self.pq
                .kernel_builder("lde_leaf_finalize_at")
                .arg(&sponge.buffer)
                .arg(&tree.buffer)
                .arg(offset as u32)
                .arg(height as u32)
                .arg(rate as u32)
                .arg(u32::from(inject))
                .arg(&self.constants[0].buffer)
                .arg(&self.constants[1].buffer)
                .arg(&self.constants[2].buffer)
                .arg(&self.constants[3].buffer)
                .global_work_size(height)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = self.timeline.record("mixed_leaf_injection", &event)?;
        self.stats.lde_sponge_ns += ns;
        self.stats.leaf_kernel_ns += ns;
        Ok(())
    }
}
