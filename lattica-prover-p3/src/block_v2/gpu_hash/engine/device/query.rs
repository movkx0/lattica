//! Reconstruct committed query rows from immutable device degree prefixes.
//! Two reusable transform buffers bound the working set independently of the
//! matrix width. Only root constants, indices and final query rows cross PCIe.
use super::*;

pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_query_prefix(__global const ulong *input,
    __global ulong *output, uint input_width, uint first, uint width,
    uint rows, uint log_rows) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * width) return;
    uint row = (uint)(i / width);
    output[i] = input[(size_t)(log_rows ? brev(row, log_rows) : 0) * input_width + first + i % width];
}
"#;

use crate::gpu_matrix::query::geometry;
pub(super) use crate::gpu_matrix::query::{QueryPlan, PREFERRED_SCRATCH};

impl DeviceSession {
    /// Interpolate a degree prefix on its coset and gather bit-reversed rows
    /// from the larger committed domain on that same coset. Query order and
    /// duplicates are preserved. The input is immutable and never downloaded.
    pub(crate) fn query_rows(
        &self,
        prefix: &DeviceMatrix,
        log_rows: u32,
        indices: &[usize],
        host_allowance: usize,
    ) -> Result<Vec<u64>, String> {
        self.check_owner(prefix)?;
        geometry(prefix.spec, log_rows, indices)?;
        #[cfg(not(feature = "gpu"))]
        {
            let _ = host_allowance;
            Err("owned query reconstruction is not implemented on Metal".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            self.observe_engine(engine, |engine| {
                let started = std::time::Instant::now();
                engine.fence().finish()?;
                engine.workspace = None;
                engine.lde_workspace = None;
                let live = engine.accounting.lock().unwrap().live;
                let plan = QueryPlan::new(
                    prefix.spec,
                    log_rows,
                    indices.len(),
                    engine
                        .limits
                        .managed_bytes
                        .checked_sub(live)
                        .ok_or("owned query exceeds managed budget")?,
                    engine.max_alloc,
                    host_allowance,
                )?;
                let alloc = |words| {
                    allocation(
                        &engine.pq,
                        &engine.accounting,
                        engine.limits,
                        engine.max_alloc,
                        words,
                        compute::flags::MEM_READ_WRITE,
                    )
                };
                let a = alloc(plan.height * plan.columns)?;
                let b = alloc(plan.height * plan.columns)?;
                let inverse = alloc(plan.inverse_words)?;
                let forward = alloc(plan.forward_words)?;
                let parameters = alloc(2)?;
                let queries = alloc(indices.len())?;
                let gathered = alloc(indices.len() * plan.columns)?;
                let inverse_roots: Vec<_> = (1..=plan.inverse_words)
                    .map(|log| super::super::fri_fold::inverse_root(log as u32))
                    .collect();
                let forward_roots: Vec<_> = (1..=plan.forward_words)
                    .map(|log| super::super::fri_fold::root(log as u32))
                    .collect();
                let query_indices: Vec<_> = indices.iter().map(|i| *i as u64).collect();
                let mut result = vec![0u64; indices.len() * prefix.spec.columns];
                let mut words = vec![0u64; indices.len() * plan.columns];
                let fence = engine.fence();
                inverse
                    .buffer
                    .write(&inverse_roots)
                    .enq()
                    .map_err(|e| e.to_string())?;
                forward
                    .buffer
                    .write(&forward_roots)
                    .enq()
                    .map_err(|e| e.to_string())?;
                queries
                    .buffer
                    .write(&query_indices)
                    .enq()
                    .map_err(|e| e.to_string())?;
                let uploaded =
                    ((plan.inverse_words + plan.forward_words + indices.len()) * 8) as u64;
                engine.stats.uploaded_bytes += uploaded;
                self.session.stats.lock().unwrap().uploaded_bytes += uploaded;
                let mut event = compute::Event::empty();
                // SAFETY: two parameter words and one work item. Normalization is
                // computed on GPU, using the same nonzero input/output coset.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transform_parameters")
                        .arg(&parameters.buffer)
                        .arg(prefix.spec.rows() as u32)
                        .arg(prefix.spec.shift)
                        .arg(prefix.spec.shift)
                        .global_work_size(1)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let mut ns = self.session.record_event(
                    engine,
                    crate::proving::Stage::FriQuery,
                    "device_query_parameters",
                    &event,
                )?;
                let before_ntt = engine.stats.lde_transform_ns;
                let mut tiles = 0;
                for first in (0..prefix.spec.columns).step_by(plan.columns) {
                    let width = plan.columns.min(prefix.spec.columns - first);
                    let natural = if prefix.spec.rows() == 1 {
                        &b.buffer
                    } else {
                        &a.buffer
                    };
                    let mut event = compute::Event::empty();
                    // SAFETY: the checked column interval stays inside the prefix;
                    // the row permutation is bijective and both workspaces cover it.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_query_prefix")
                            .arg(&prefix.storage.buffer)
                            .arg(natural)
                            .arg(prefix.spec.columns as u32)
                            .arg(first as u32)
                            .arg(width as u32)
                            .arg(prefix.spec.rows() as u32)
                            .arg(prefix.spec.log_rows)
                            .global_work_size(prefix.spec.rows() * width)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    ns += self.session.record_event(
                        engine,
                        crate::proving::Stage::FriQuery,
                        "device_query_prefix",
                        &event,
                    )?;
                    if prefix.spec.rows() > 1 {
                        engine.lde_ntt(
                            &a.buffer,
                            &b.buffer,
                            &inverse.buffer,
                            true,
                            prefix.spec.rows(),
                            width,
                            1,
                            1,
                            false,
                            false,
                            false,
                            None,
                        )?;
                    }
                    let mut event = compute::Event::empty();
                    // SAFETY: separate buffers; all coefficient and zero-pad lanes
                    // are covered by the planned full-domain allocations.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_transform_scale")
                            .arg(&b.buffer)
                            .arg(&a.buffer)
                            .arg(&parameters.buffer)
                            .arg(width as u32)
                            .arg(prefix.spec.rows() as u32)
                            .arg(plan.height as u32)
                            .global_work_size(plan.height * width)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    ns += self.session.record_event(
                        engine,
                        crate::proving::Stage::FriQuery,
                        "device_query_scale",
                        &event,
                    )?;
                    let in_b = if plan.height > 1 {
                        engine.lde_ntt(
                            &a.buffer,
                            &b.buffer,
                            &forward.buffer,
                            false,
                            plan.height,
                            width,
                            1,
                            1,
                            true,
                            true,
                            false,
                            None,
                        )?
                    } else {
                        false
                    };
                    let output = if in_b { &b.buffer } else { &a.buffer };
                    let mut event = compute::Event::empty();
                    // SAFETY: every index is in the expanded domain. The query
                    // buffer fits every lane; the fence drains before any release.
                    unsafe {
                        engine
                            .pq
                            .kernel_builder("device_gather_rows")
                            .arg(output)
                            .arg(&queries.buffer)
                            .arg(&gathered.buffer)
                            .arg(width as u32)
                            .arg(indices.len() as u32)
                            .global_work_size(indices.len() * width)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    let gather_ns = self.session.record_event(
                        engine,
                        crate::proving::Stage::FriQuery,
                        "device_query_gather",
                        &event,
                    )?;
                    ns += gather_ns;
                    engine.stats.query_gather_device_ns += gather_ns;
                    let tile = &mut words[..indices.len() * width];
                    gathered
                        .buffer
                        .read(&mut *tile)
                        .enq()
                        .map_err(|e| e.to_string())?;
                    let downloaded = (tile.len() * 8) as u64;
                    engine.stats.downloaded_bytes += downloaded;
                    engine.stats.query_downloaded_bytes += downloaded;
                    engine.stats.query_readbacks += 1;
                    {
                        let mut stats = self.session.stats.lock().unwrap();
                        stats.downloaded_bytes += downloaded;
                        stats.query_value_bytes += downloaded;
                    }
                    if tile.iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                        return Err("owned query returned a noncanonical value".into());
                    }
                    for (query, row) in tile.chunks_exact(width).enumerate() {
                        let start = query * prefix.spec.columns + first;
                        result[start..start + width].copy_from_slice(row);
                    }
                    tiles += 1;
                }
                fence.finish()?;
                ns += engine.stats.lde_transform_ns - before_ntt;
                engine.stats.query_reconstruction_calls += 1;
                engine.stats.query_reconstruction_tiles += tiles;
                engine.stats.query_reconstruction_wall_ns += started.elapsed().as_nanos();
                let mut stats = self.session.stats.lock().unwrap();
                stats.query_reconstructions += 1;
                stats.query_reconstruction_tiles += tiles;
                stats.query_device_ns += ns;
                tracing::debug!(
                    workspace_bytes = plan.workspace_bytes,
                    host_peak_bytes = plan.host_peak_bytes,
                    tiles,
                    "owned query reconstruction"
                );
                Ok(result)
            })
        })
    }
}

#[cfg(test)]
mod tests;
