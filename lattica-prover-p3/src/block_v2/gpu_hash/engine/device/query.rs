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

// Prefer <=64 MiB of scratch. A domain too tall for one column may use
// exactly one column's larger working set, still bounded by log_rows <=25.
const PREFERRED_SCRATCH: usize = 64 << 20;
const HOST_METADATA: usize = 8 << 10;

#[derive(Debug)]
struct QueryPlan {
    height: usize,
    columns: usize,
    inverse_words: usize,
    forward_words: usize,
    workspace_bytes: usize,
    host_peak_bytes: usize,
}

fn geometry(input: MatrixSpec, log_rows: u32, indices: &[usize]) -> Result<(), String> {
    if input.extension != Extension::Base
        || input.order != RowOrder::BitReversed
        || input.columns > 4096
        || log_rows < input.log_rows
        || log_rows > 25
        || indices.is_empty()
        || indices.len() > 256
        || indices.iter().any(|i| *i >= 1usize << log_rows)
    {
        return Err(
            "owned query requires a bounded bit-reversed base-field prefix and query indices"
                .into(),
        );
    }
    Ok(())
}

impl QueryPlan {
    fn new(
        input: MatrixSpec,
        log_rows: u32,
        queries: usize,
        remaining: usize,
        max_allocation: usize,
        host_allowance: usize,
    ) -> Result<Self, String> {
        // These checks also make all arithmetic below fit usize on supported
        // 64-bit hosts, even when the caller supplies overflowing allowances.
        geometry(input, log_rows, &[0])?;
        if queries == 0 || queries > 256 {
            return Err("owned query count exceeds its bound".into());
        }
        let height = 1usize << log_rows;
        let inverse_words = input.log_rows.max(1) as usize;
        let forward_words = log_rows.max(1) as usize;
        let fixed = (inverse_words + forward_words + 2 + queries) * 8;
        if [inverse_words, forward_words, 2, queries]
            .into_iter()
            .any(|words| words * 8 > max_allocation)
        {
            return Err("owned query constants/indices exceed allocation limit".into());
        }
        let per_column = (2 * height + queries) * 8;
        let scratch_limit = PREFERRED_SCRATCH.max(fixed + per_column);
        let available = remaining
            .min(scratch_limit)
            .checked_sub(fixed)
            .ok_or("owned query has no scratch allowance")?;
        let columns = input
            .columns
            .min(available / per_column)
            .min(max_allocation / (height * 8))
            .min(max_allocation / (queries * 8))
            .min(u32::MAX as usize / height);
        if columns == 0 {
            return Err("no owned query transform column fits GPU allowance".into());
        }
        let host_peak_bytes = queries * (input.columns + columns) * 8 + HOST_METADATA;
        if host_peak_bytes > host_allowance {
            return Err("owned query result and staging exceed host allowance".into());
        }
        Ok(Self {
            height,
            columns,
            inverse_words,
            forward_words,
            workspace_bytes: fixed + columns * per_column,
            host_peak_bytes,
        })
    }
}

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
                            prefix.spec.rows(),
                            width,
                            1,
                            1,
                            false,
                            false,
                            false,
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
                            plan.height,
                            width,
                            1,
                            1,
                            true,
                            true,
                            false,
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
