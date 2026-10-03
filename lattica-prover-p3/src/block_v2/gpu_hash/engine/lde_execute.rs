//! Experimental, synchronous coset-LDE -> resident commitment execution.
//! This is a research seam, not a PCS replacement. Inputs and explicit salts
//! belong to one proof attempt. Returned matrices are physical bit-reversed LDEs.
//! Every device allocation uses the existing engine's accounting and lease.
use super::{
    allocation,
    lde_plan::{InputShape, LdeCommitPlan},
    lde_readback::HostReadback,
    plan_slots, retained_layout, Allocation, Engine, RetainedTree, ENGINE,
};
use crate::block_v2::compute;
use crate::config::Val;
use compute::{Buffer, Event};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::*;
use std::time::Instant;

pub(super) const KERNEL_SRC: &str = r#"
// Absorb an uninterrupted column stream. A tile or matrix boundary is NOT a
// sponge boundary; only every fourth word permutes. The final partial block is
// permuted once by lde_leaf_finalize, preserving the padding-free CPU sponge.
__kernel void lde_absorb(__global const ulong *input, __global ulong *states,
    uint row0, uint rows, uint width, uint rate_offset,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong s[8];
    size_t state_base = ((size_t)row0 + row) * 8;
    for (uint k = 0; k < 8; ++k) s[k] = states[state_base + k];
    uint at = rate_offset;
    for (uint col = 0; col < width; ++col) {
        s[at++] = input[row * (size_t)width + col];
        if (at == 4) { perm8(s, rci, rcp, rcf, diag); at = 0; }
    }
    for (uint k = 0; k < 8; ++k) states[state_base + k] = s[k];
}
__kernel void lde_leaf_finalize(__global const ulong *states, __global ulong *leaves,
    uint height, uint rate_offset, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0);
    if (row >= height) return;
    ulong s[8];
    for (uint k = 0; k < 8; ++k) s[k] = states[row * 8 + k];
    if (rate_offset != 0) perm8(s, rci, rcp, rcf, diag);
    for (uint k = 0; k < 4; ++k) leaves[row * 4 + k] = gl_canon(s[k]);
}
// IDFT already multiplied coefficient i by (generator / domain_shift)^i.
// This applies the same balanced hiding polynomial as CPU fused_ldes.
__kernel void quotient_mask(__global ulong *coefficients, __global const ulong *masks,
    uint height, uint width, ulong generator, ulong ratio_h) {
    size_t index = get_global_id(0);
    size_t elements = (size_t)height * width;
    if (index >= elements) return;
    ulong masked = gl_mul(masks[index], gl_pow(generator, (ulong)(index / width)));
    coefficients[index] = gl_sub(coefficients[index], masked);
    coefficients[elements + index] = gl_mul(ratio_h, masked);
}
"#;

/// Natural-order evaluations and per-output-row salts. The caller must supply
/// fresh proof-attempt randomness; this API neither generates nor caches it.
#[derive(Clone, Copy)]
pub struct LdeInput<'a> {
    pub evaluations: &'a RowMajorMatrix<Val>,
    pub salts: &'a RowMajorMatrix<Val>,
    pub added_bits: usize,
    pub shift: Val,
}

/// Host readback remains explicit until quotient/opening consumers move to the
/// device. Neither the allocation plan nor this output measures whole-job RSS.
pub struct LdeCommitOutput {
    pub matrices: Vec<RowMajorMatrix<Val>>,
    pub plan: LdeCommitPlan,
    pub(crate) tree: RetainedTree,
    cap_height: usize,
}
impl LdeCommitOutput {
    pub fn cap(&self) -> &[[Val; 4]] {
        self.tree.cap()
    }
    pub fn open(&self, index: usize) -> Result<Vec<[Val; 4]>, String> {
        self.tree.open(index, self.cap_height)
    }
}

fn validate_inputs(inputs: &[LdeInput<'_>]) -> Result<Vec<InputShape>, String> {
    inputs
        .iter()
        .map(|input| {
            let matrix = input.evaluations;
            if matrix.width == 0 || matrix.values.len() % matrix.width != 0 {
                return Err("LDE input matrix storage is not rectangular".into());
            }
            let height = matrix.values.len() / matrix.width;
            if height < 2
                || !height.is_power_of_two()
                || input.added_bits >= 32
                || input.shift == Val::ZERO
            {
                return Err("LDE input transform domain is invalid".into());
            }
            let output_height = height
                .checked_mul(
                    1usize
                        .checked_shl(input.added_bits as u32)
                        .ok_or("LDE output overflow")?,
                )
                .ok_or("LDE output overflow")?;
            if input.salts.width != 4
                || output_height.checked_mul(4) != Some(input.salts.values.len())
            {
                return Err("LDE salts must be exactly four words per output row".into());
            }
            Ok(InputShape {
                height,
                width: matrix.width,
                added_bits: input.added_bits,
            })
        })
        .collect()
}

/// Holds the engine mutex from fresh planning through reservations, kernels and
/// drain. Existing retained trees stay live and count against the same budget.
pub fn coset_lde_commit(
    inputs: &[LdeInput<'_>],
    cap_height: usize,
    host_output_budget_bytes: usize,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    slot.as_mut()
        .ok_or("GPU hashing shut down")?
        .coset_lde_commit(inputs, cap_height, host_output_budget_bytes)
}

/// Commit quotient chunks after CPU generation of the balanced hiding masks.
/// Inputs and masks belong to this attempt; the device never draws randomness.
pub fn quotient_lde_commit(
    inputs: &[LdeInput<'_>],
    masks: &[RowMajorMatrix<Val>],
    cap_height: usize,
    host_output_budget_bytes: usize,
) -> Result<LdeCommitOutput, String> {
    let mut slot = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    slot.as_mut()
        .ok_or("GPU hashing shut down")?
        .coset_lde_commit_with_masks(inputs, Some(masks), cap_height, host_output_budget_bytes)
}

/// Kernel scheduling shared with the existing tiled-NTT arithmetic, without
/// borrowing that module's separate context or allocator.
fn ntt_groups(height: usize, width: usize) -> Result<Vec<(usize, usize, usize)>, String> {
    if height < 2
        || !height.is_power_of_two()
        || height > u32::MAX as usize
        || width == 0
        || width > u32::MAX as usize
    {
        return Err("unsupported resident NTT geometry".into());
    }
    let log_h = height.trailing_zeros() as usize;
    let log_c = width
        .checked_next_power_of_two()
        .ok_or("NTT column overflow")?
        .trailing_zeros()
        .min(4) as usize;
    let cap = (12 - log_c).min(log_h);
    let groups = log_h.div_ceil(cap);
    let (base, extra) = (log_h / groups, log_h % groups);
    let mut stage = 0;
    Ok((0..groups)
        .map(|group| {
            let count = base + usize::from(group < extra);
            let item = (stage, count, log_c);
            stage += count;
            item
        })
        .collect())
}

struct TransformBuffers {
    a: Allocation,
    b: Allocation,
    sponge: Allocation,
    forward: Allocation,
    inverse: Allocation,
}

impl Engine {
    fn lde_upload_rows(
        &mut self,
        buffer: &Buffer<u64>,
        rows: usize,
        width: usize,
        fill: impl Fn(usize, &mut [u64]) + Sync,
    ) -> Result<(), String> {
        let started = Instant::now();
        let chunk_rows = self.staging[0].map.len() / width;
        if chunk_rows == 0 || rows.checked_mul(width).is_none_or(|n| n > buffer.len()) {
            return Err("resident LDE upload bounds".into());
        }
        for row0 in (0..rows).step_by(chunk_rows) {
            let count = chunk_rows.min(rows - row0);
            let marshal = Instant::now();
            self.staging[0].map[..count * width]
                .par_chunks_mut(width)
                .enumerate()
                .for_each(|(i, dst)| fill(row0 + i, dst));
            self.stats.marshal_ns += marshal.elapsed().as_nanos();
            let transfer = Instant::now();
            let mut event = Event::empty();
            buffer
                .write(&self.staging[0].map[..count * width])
                .offset(row0 * width)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
            self.stats.upload_device_ns += self.timeline.record("lde_upload", &event)?;
            self.stats.uploaded_bytes += (count * width * 8) as u64;
        }
        self.stats.upload_and_marshal_ns += started.elapsed().as_nanos();
        Ok(())
    }

    fn lde_read_columns(
        &mut self,
        buffer: &Buffer<u64>,
        output: &mut HostReadback,
        first: usize,
        columns: usize,
    ) -> Result<(), String> {
        let started = Instant::now();
        let height = output.height();
        if columns == 0 {
            return Err("resident LDE readback columns must be nonzero".into());
        }
        let chunk_rows = self.staging[0].map.len() / columns;
        if chunk_rows == 0 || height.checked_mul(columns).is_none_or(|n| n > buffer.len()) {
            return Err("resident LDE readback bounds".into());
        }
        for row0 in (0..height).step_by(chunk_rows) {
            let count = chunk_rows.min(height - row0);
            let transfer = Instant::now();
            let mut event = Event::empty();
            buffer
                .read(&mut self.staging[0].map[..count * columns])
                .offset(row0 * columns)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.download_wall_ns += transfer.elapsed().as_nanos();
            self.stats.download_device_ns += self.timeline.record("lde_download", &event)?;
            let decode = Instant::now();
            output.append_rows(
                first,
                columns,
                row0,
                &self.staging[0].map[..count * columns],
            )?;
            self.stats.decode_ns += decode.elapsed().as_nanos();
            if output.uses_parallel_decode(count * columns) {
                self.stats.lde_parallel_decode_bytes += (count * columns * 8) as u64;
                self.stats.lde_parallel_decode_chunks += 1;
            }
            self.stats.downloaded_bytes += (count * columns * 8) as u64;
        }
        self.stats.download_and_decode_ns += started.elapsed().as_nanos();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn lde_ntt(
        &mut self,
        src: &Buffer<u64>,
        dst: &Buffer<u64>,
        roots: &Buffer<u64>,
        height: usize,
        width: usize,
        post_c: u64,
        post_b: u64,
        canonical: bool,
        bit_reversed: bool,
    ) -> Result<bool, String> {
        let groups = ntt_groups(height, width)?;
        let log_h = height.trailing_zeros() as usize;
        if height
            .checked_mul(width)
            .is_none_or(|n| n > src.len() || n > dst.len())
            || roots.len() < log_h
        {
            return Err("resident NTT buffer bounds".into());
        }
        let mut in_dst = true;
        for (group, &(stage, count, log_c)) in groups.iter().enumerate() {
            let last = group + 1 == groups.len();
            let (input, output) = match (group == 0, last && bit_reversed) {
                (true, _) => (src, dst),
                (false, true) => (dst, src),
                (false, false) => (dst, dst),
            };
            if last {
                in_dst = std::ptr::eq(output, dst);
            }
            let local_elements = 1usize << (count + log_c);
            let workgroup = (local_elements / 2).clamp(32, 256);
            let workgroups = (height >> count) * width.div_ceil(1 << log_c);
            let mut event = Event::empty();
            // SAFETY: whole independent columns, bounded u32 row/column indexing,
            // 32 KiB local tile, and distinct buffers at permutation boundaries.
            unsafe {
                let kernel = self
                    .pq
                    .kernel_builder("ntt_tile")
                    .arg(input)
                    .arg(output)
                    .arg(width as u32)
                    .arg(height as u32)
                    .arg(stage as u32)
                    .arg(count as u32)
                    .arg(log_c as u32)
                    .arg(u32::from(group == 0))
                    .arg(log_h as u32)
                    .arg(u32::from(last && canonical))
                    .arg(u32::from(last && bit_reversed))
                    .arg(if last { post_c } else { 1 })
                    .arg(if last { post_b } else { 1 })
                    .arg(roots)
                    .arg_local::<u64>(local_elements)
                    .global_work_size(workgroups * workgroup)
                    .local_work_size(workgroup)
                    .build()
                    .map_err(|e| e.to_string())?;
                let command = kernel.cmd().enew(&mut event);
                #[cfg(test)]
                let command = if let Some(gate) = self.lde_gate.as_ref() {
                    command.ewait(gate)
                } else {
                    command
                };
                command.enq().map_err(|e| e.to_string())?;
            }
            #[cfg(test)]
            if let Some(unwind) = self.fail_lde_after_enqueue.take() {
                self.injected_event = Some(event.clone());
                if let Some(notify) = self.lde_submitted.take() {
                    use compute::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
                    assert!(!matches!(
                        event.info(EventInfo::CommandExecutionStatus).unwrap(),
                        EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
                    ));
                    notify.send(()).unwrap();
                }
                if unwind {
                    panic!("injected unwind after resident NTT enqueue");
                }
                return Err("injected error after resident NTT enqueue".into());
            }
            self.stats.lde_transform_ns += self.timeline.record("lde_ntt", &event)?;
        }
        Ok(in_dst)
    }

    fn lde_absorb(
        &mut self,
        input: &Buffer<u64>,
        sponge: &Buffer<u64>,
        row0: usize,
        rows: usize,
        columns: usize,
        rate_offset: usize,
    ) -> Result<(), String> {
        if rate_offset >= 4
            || columns == 0
            || rows.checked_mul(columns).is_none_or(|n| n > input.len())
            || row0
                .checked_add(rows)
                .and_then(|n| n.checked_mul(8))
                .is_none_or(|n| n > sponge.len())
        {
            return Err("resident sponge bounds".into());
        }
        let mut event = Event::empty();
        // SAFETY: each work item owns one bounded eight-word row state.
        unsafe {
            self.pq
                .kernel_builder("lde_absorb")
                .arg(input)
                .arg(sponge)
                .arg(row0 as u32)
                .arg(rows as u32)
                .arg(columns as u32)
                .arg(rate_offset as u32)
                .arg(&self.constants[0].buffer)
                .arg(&self.constants[1].buffer)
                .arg(&self.constants[2].buffer)
                .arg(&self.constants[3].buffer)
                .global_work_size(rows)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        let ns = self.timeline.record("lde_absorb", &event)?;
        self.stats.lde_sponge_ns += ns;
        self.stats.leaf_kernel_ns += ns;
        Ok(())
    }

    pub(super) fn coset_lde_commit(
        &mut self,
        inputs: &[LdeInput<'_>],
        cap_height: usize,
        host_budget: usize,
    ) -> Result<LdeCommitOutput, String> {
        self.coset_lde_commit_with_masks(inputs, None, cap_height, host_budget)
    }

    fn coset_lde_commit_with_masks(
        &mut self,
        inputs: &[LdeInput<'_>],
        masks: Option<&[RowMajorMatrix<Val>]>,
        cap_height: usize,
        host_budget: usize,
    ) -> Result<LdeCommitOutput, String> {
        let parallel_readback = super::switch("LATTICA_V2_GPU_PARALLEL_READBACK")?;
        let started = Instant::now();
        if !self.retain_trees {
            return Err("resident LDE requires retained commitments".into());
        }
        let shapes = validate_inputs(inputs)?;
        if let Some(masks) = masks {
            if masks.len() != inputs.len()
                || masks.iter().zip(inputs).any(|(mask, input)| {
                    mask.width != input.evaluations.width
                        || mask.values.len() != input.evaluations.values.len()
                        || input.added_bits != crate::block_v2::profile::LOG_BLOWUP + 1
                })
            {
                return Err("quotient mask dimensions or hiding blowup mismatch".into());
            }
        }
        let live = self
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live;
        let old_workspace = self.workspace.as_ref().map_or(0, super::Workspace::bytes);
        let plan = LdeCommitPlan::new(
            &shapes,
            cap_height,
            self.limits,
            self.max_alloc,
            self.mode.slots(),
            live,
            old_workspace,
            host_budget,
        )?;
        let height = plan.output_height();
        let width = shapes
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.width)?.checked_add(4))
            .ok_or("resident LDE row width overflow")?;
        let hash_plan = plan_slots(
            height,
            width,
            self.limits,
            self.max_alloc,
            self.mode.slots(),
        )?;
        let layout = retained_layout(height, cap_height, self.max_alloc)?;
        self.fence().finish()?;
        // The planner subtracts only this replaceable workspace. Force exact
        // replacement even if a larger old workspace would otherwise fit.
        self.workspace = None;
        self.workspace(hash_plan)?;
        let alloc = |bytes| {
            allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                bytes / 8,
                compute::flags::MEM_READ_WRITE,
            )
        };
        let buffers = TransformBuffers {
            a: alloc(plan.transform_buffer_bytes)?,
            b: alloc(plan.transform_buffer_bytes)?,
            sponge: alloc(plan.sponge_state_bytes)?,
            forward: alloc(plan.twiddle_bytes / 2)?,
            inverse: alloc(plan.twiddle_bytes / 2)?,
        };
        let mut storage = alloc(plan.retained_tree_bytes)?;
        storage._lease.mark_retained()?;
        // Must outlive all pending operations and drop BEFORE any owned buffer
        // above, on normal return, device error, or unwind.
        let fence = self.fence();
        let mut matrices = Vec::with_capacity(shapes.len());
        buffers
            .sponge
            .buffer
            .cmd()
            .fill(0u64, None)
            .enq()
            .map_err(|e| e.to_string())?;
        let log_height = height.trailing_zeros() as usize;
        self.lde_upload_rows(&buffers.forward.buffer, log_height, 1, |row, dst| {
            dst[0] = Val::two_adic_generator(row + 1).as_canonical_u64();
        })?;
        self.lde_upload_rows(&buffers.inverse.buffer, log_height, 1, |row, dst| {
            dst[0] = Val::two_adic_generator(row + 1)
                .inverse()
                .as_canonical_u64();
        })?;
        for (matrix_index, input) in inputs.iter().enumerate() {
            let shape = shapes[matrix_index];
            let mut readback = HostReadback::new(height, shape.width, plan.columns_per_tile())?
                .with_parallel_decode(parallel_readback);
            for tile in plan.tiles().filter(|t| t.matrix == matrix_index) {
                buffers
                    .b
                    .buffer
                    .cmd()
                    .fill(0u64, Some(tile.output_elements))
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.lde_upload_rows(&buffers.a.buffer, shape.height, tile.columns, |row, dst| {
                    for (dst, value) in dst
                        .iter_mut()
                        .zip(&input.evaluations.values[row * shape.width + tile.first_column..])
                    {
                        *dst = value.as_canonical_u64();
                    }
                })?;
                self.lde_ntt(
                    &buffers.a.buffer,
                    &buffers.b.buffer,
                    &buffers.inverse.buffer,
                    shape.height,
                    tile.columns,
                    Val::from_usize(shape.height).inverse().as_canonical_u64(),
                    input.shift.as_canonical_u64(),
                    false,
                    false,
                )?;
                if let Some(masks) = masks {
                    let mask = &masks[matrix_index];
                    self.lde_upload_rows(
                        &buffers.a.buffer,
                        shape.height,
                        tile.columns,
                        |row, dst| {
                            for (out, value) in dst
                                .iter_mut()
                                .zip(&mask.values[row * shape.width + tile.first_column..])
                            {
                                *out = value.as_canonical_u64();
                            }
                        },
                    )?;
                    let mut event = Event::empty();
                    // SAFETY: Admission covers the doubled polynomial. The mask
                    // and coefficients use the same full-height column tile.
                    unsafe {
                        self.pq
                            .kernel_builder("quotient_mask")
                            .arg(&buffers.b.buffer)
                            .arg(&buffers.a.buffer)
                            .arg(shape.height as u32)
                            .arg(tile.columns as u32)
                            .arg(Val::GENERATOR.as_canonical_u64())
                            .arg(input.shift.exp_u64(shape.height as u64).as_canonical_u64())
                            .global_work_size(shape.height * tile.columns)
                            .build()
                            .map_err(|e| e.to_string())?
                            .cmd()
                            .enew(&mut event)
                            .enq()
                            .map_err(|e| e.to_string())?;
                    }
                    self.stats.quotient_mask_ns += self.timeline.record("quotient_mask", &event)?;
                }
                let in_a = self.lde_ntt(
                    &buffers.b.buffer,
                    &buffers.a.buffer,
                    &buffers.forward.buffer,
                    height,
                    tile.columns,
                    1,
                    1,
                    true,
                    true,
                )?;
                let transformed = if in_a {
                    &buffers.a.buffer
                } else {
                    &buffers.b.buffer
                };
                self.lde_absorb(
                    transformed,
                    &buffers.sponge.buffer,
                    0,
                    height,
                    tile.columns,
                    tile.sponge_rate_offset,
                )?;
                self.lde_read_columns(transformed, &mut readback, tile.first_column, tile.columns)?;
                self.stats.lde_column_tiles += 1;
            }
            let (matrix, reorder) = readback.finish()?;
            // Keep the existing host-materialization counters inclusive of the
            // new layout pass; the reorder counter is a nonadditive subset.
            self.stats.decode_ns += reorder.elapsed_ns;
            self.stats.download_and_decode_ns += reorder.elapsed_ns;
            self.stats.lde_host_reorder_ns += reorder.elapsed_ns;
            self.stats.lde_host_reordered_bytes += reorder.bytes as u64;
            self.stats.lde_host_workspace_peak_bytes = self
                .stats
                .lde_host_workspace_peak_bytes
                .max(reorder.workspace_bytes);
            matrices.push(matrix);
            // Reuse a transform buffer for bounded salt bands only AFTER its
            // transformed columns have been hashed and read back.
            let salt_columns = plan.columns_per_tile().min(4);
            for first_salt in (0..4).step_by(salt_columns) {
                let columns = salt_columns.min(4 - first_salt);
                let band_rows =
                    (buffers.a.buffer.len() / columns).min(self.staging[0].map.len() / columns);
                for row0 in (0..height).step_by(band_rows) {
                    let rows = band_rows.min(height - row0);
                    self.lde_upload_rows(&buffers.a.buffer, rows, columns, |row, dst| {
                        for (dst, value) in dst
                            .iter_mut()
                            .zip(&input.salts.values[(row0 + row) * 4 + first_salt..])
                        {
                            *dst = value.as_canonical_u64();
                        }
                    })?;
                    self.lde_absorb(
                        &buffers.a.buffer,
                        &buffers.sponge.buffer,
                        row0,
                        rows,
                        columns,
                        (plan.salt_rate_offset(matrix_index).unwrap() + first_salt) % 4,
                    )?;
                }
            }
        }
        let final_offset = plan.salt_rate_offset(inputs.len() - 1).unwrap();
        let mut event = Event::empty();
        // SAFETY: full-height states and leaf workspace were jointly admitted.
        unsafe {
            self.pq
                .kernel_builder("lde_leaf_finalize")
                .arg(&buffers.sponge.buffer)
                .arg(&self.workspace.as_ref().unwrap().a.buffer)
                .arg(height as u32)
                .arg(final_offset as u32)
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
        let ns = self.timeline.record("lde_leaf_finalize", &event)?;
        self.stats.lde_sponge_ns += ns;
        self.stats.leaf_kernel_ns += ns;
        let cap = self.finish_retained_layers(&storage, height, layout)?;
        fence.finish()?;
        self.stats.commits += 1;
        self.stats.lde_commits += 1;
        if masks.is_some() {
            self.stats.quotient_lde_commits += 1;
        }
        self.stats.lde_wall_ns += started.elapsed().as_nanos();
        Ok(LdeCommitOutput {
            matrices,
            plan,
            cap_height,
            tree: RetainedTree {
                storage,
                height,
                layout,
                cap,
                _job_lease: self._job_lease.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    fn matrix(height: usize, width: usize, salt: u64) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(
            (0..height * width)
                .map(|i| {
                    Val::new(match i % 5 {
                        0 => 0,
                        1 => 1,
                        2 => 0xffff_ffff_0000_0000,
                        3 => u64::MAX,
                        _ => (i as u64)
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .wrapping_add(salt),
                    })
                })
                .collect(),
            width,
        )
    }

    #[test]
    fn input_validation_rejects_storage_domain_and_salt_mismatches() {
        let evals = matrix(8, 3, 1);
        let salts = matrix(32, 4, 2);
        let input = LdeInput {
            evaluations: &evals,
            salts: &salts,
            added_bits: 2,
            shift: Val::GENERATOR,
        };
        assert_eq!(
            validate_inputs(&[input]).unwrap(),
            vec![InputShape {
                height: 8,
                width: 3,
                added_bits: 2
            }]
        );
        assert!(validate_inputs(&[LdeInput {
            shift: Val::ZERO,
            ..input
        }])
        .is_err());
        assert!(validate_inputs(&[LdeInput {
            added_bits: usize::MAX,
            ..input
        }])
        .is_err());
        let bad_salts = matrix(32, 3, 2);
        assert!(validate_inputs(&[LdeInput {
            salts: &bad_salts,
            ..input
        }])
        .is_err());
        let short_salts = matrix(16, 4, 2);
        assert!(validate_inputs(&[LdeInput {
            salts: &short_salts,
            ..input
        }])
        .is_err());
        let mut nonrectangular = matrix(1, 7, 1);
        nonrectangular.width = 3;
        let mut zero_width = matrix(1, 1, 1);
        zero_width.width = 0;
        for malformed in [nonrectangular, zero_width, matrix(3, 3, 1), matrix(1, 3, 1)] {
            assert!(validate_inputs(&[LdeInput {
                evaluations: &malformed,
                ..input
            }])
            .is_err());
        }
    }

    #[test]
    fn ntt_schedule_covers_every_stage_with_bounded_local_storage() {
        for log_h in 1..32 {
            for width in [1usize, 2, 3, 4, 7, 16, 35, 98, 204, 1024] {
                let groups = ntt_groups(1usize << log_h, width).unwrap();
                let mut stage = 0;
                for (start, count, log_c) in groups {
                    assert_eq!(start, stage);
                    assert!(count > 0 && (1usize << (count + log_c)) * 8 <= 32 * 1024);
                    stage += count;
                }
                assert_eq!(stage, log_h);
            }
        }
        for (height, width) in [(0, 1), (1, 1), (3, 1), (8, 0), (8, usize::MAX)] {
            assert!(ntt_groups(height, width).is_err());
        }
    }

    fn check_cpu_reference(inputs: &[LdeInput<'_>], cap_height: usize) -> LdeCommitOutput {
        use crate::config::{Dft, MyCompress, MyHash};
        use p3_dft::TwoAdicSubgroupDft;
        use p3_goldilocks::default_goldilocks_poseidon2_8;
        use p3_matrix::{bitrev::BitReversibleMatrix, Matrix};
        use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
        let before = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot();
        let output = coset_lde_commit(inputs, cap_height, 32 * 1024 * 1024).unwrap();
        let after = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot();
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            (output.plan.projected_input_upload_bytes
                + output.plan.projected_salt_upload_bytes
                + output.plan.twiddle_bytes) as u64
        );
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            (output.plan.projected_host_readback_bytes + output.cap().len() * 4 * 8) as u64
        );
        let expected: Vec<_> = inputs
            .iter()
            .map(|input| {
                Dft::default()
                    .coset_lde_batch(input.evaluations.clone(), input.added_bits, input.shift)
                    .bit_reverse_rows()
                    .to_row_major_matrix()
            })
            .collect();
        for (actual, expected) in output.matrices.iter().zip(&expected) {
            assert_eq!(actual.values, expected.values);
            assert_eq!(actual.width, expected.width);
        }
        let permutation = default_goldilocks_poseidon2_8();
        let hash = MyHash::new(permutation.clone());
        let compress = MyCompress::new(permutation);
        let height = output.plan.output_height();
        let mut layers: Vec<Vec<[Val; 4]>> = vec![(0..height)
            .map(|row| {
                hash.hash_iter(expected.iter().zip(inputs).flat_map(|(matrix, input)| {
                    matrix.values[row * matrix.width..(row + 1) * matrix.width]
                        .iter()
                        .chain(&input.salts.values[row * 4..row * 4 + 4])
                        .copied()
                }))
            })
            .collect()];
        while layers.last().unwrap().len() > 1 {
            layers.push(
                layers
                    .last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| compress.compress([pair[0], pair[1]]))
                    .collect(),
            );
        }
        let path_len = height.ilog2() as usize - cap_height.min(height.ilog2() as usize);
        assert_eq!(output.cap(), layers[path_len]);
        for index in [0, height / 2, height - 1] {
            let expected_path: Vec<_> = layers[..path_len]
                .iter()
                .enumerate()
                .map(|(level, values)| values[(index >> level) ^ 1])
                .collect();
            assert_eq!(output.open(index).unwrap(), expected_path);
        }
        assert!(output.open(height).is_err());
        assert!(
            super::super::shutdown().is_err(),
            "live tree must retain context lease"
        );
        output
    }

    #[test]
    #[ignore = "requires OpenCL GPU, LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_resident_lde_columns_caps_and_paths_match_cpu() {
        let _shutdown = super::super::TestShutdownGuard;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 512 * 1024,
                tile_bytes: 8 * 1024,
                staging_bytes: 4 * 1024,
            },
            super::super::TransferMode::Serial,
        )
        .unwrap();
        for (height, added, widths) in [
            (2usize, 0usize, vec![1]),
            (8, 1, vec![3]),
            (8, 2, vec![4, 5]),
            (128, 3, vec![35, 7]),
            (64, 4, vec![17, 6, 1]),
        ] {
            // Different input heights are valid when their LDE heights agree.
            let evaluations: Vec<_> = widths
                .iter()
                .enumerate()
                .map(|(i, &w)| {
                    matrix(
                        if i > 0 && height >= 4 {
                            height / 2
                        } else {
                            height
                        },
                        w,
                        i as u64 + 5,
                    )
                })
                .collect();
            let salts: Vec<_> = widths
                .iter()
                .enumerate()
                .map(|(i, _)| matrix(height << added, 4, i as u64 + 11))
                .collect();
            let inputs: Vec<_> = evaluations
                .iter()
                .zip(&salts)
                .enumerate()
                .map(|(i, (evaluations, salts))| LdeInput {
                    evaluations,
                    salts,
                    added_bits: added + usize::from(i > 0 && height >= 4),
                    shift: Val::GENERATOR,
                })
                .collect();
            let output = check_cpu_reference(&inputs, 2);
            if widths[0] == 35 {
                assert!(output.plan.columns_per_tile() < 35);
            }
            drop(output);
        }
        let stats = super::super::report("resident LDE equivalence").unwrap();
        assert_eq!(stats.lde_commits, 5);
        assert!(stats.lde_transform_ns > 0 && stats.lde_sponge_ns > 0);
        assert!(stats.managed_peak_bytes <= 512 * 1024);
        assert!(stats.lde_host_reordered_bytes > 0);
        assert!(stats.lde_host_workspace_peak_bytes > 0);
        assert!(stats.lde_host_reorder_ns > 0);
        // Reordering is a subset of decode, not an extra additive stage.
        assert!(stats.decode_ns >= stats.lde_host_reorder_ns);
        assert!(stats.download_and_decode_ns >= stats.decode_ns);
    }

    #[test]
    #[ignore = "requires OpenCL GPU, LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_resident_lde_multigroup_ntt_and_unequal_input_heights_match_cpu() {
        let _shutdown = super::super::TestShutdownGuard;
        #[cfg(feature = "gpu")]
        let mode = super::super::TransferMode::Overlap;
        #[cfg(feature = "gpu-metal")]
        let mode = super::super::TransferMode::Serial;
        super::super::initialize_mode(
            super::super::Limits {
                managed_bytes: 32 * 1024 * 1024,
                tile_bytes: 64 * 1024,
                staging_bytes: 32 * 1024,
            },
            mode,
        )
        .unwrap();
        let a = matrix(8192, 3, 17);
        let b = matrix(2048, 5, 19);
        let sa = matrix(32768, 4, 23);
        let sb = matrix(32768, 4, 29);
        let inputs = [
            LdeInput {
                evaluations: &a,
                salts: &sa,
                added_bits: 2,
                shift: Val::GENERATOR,
            },
            LdeInput {
                evaluations: &b,
                salts: &sb,
                added_bits: 4,
                shift: Val::GENERATOR.inverse(),
            },
        ];
        assert!(ntt_groups(8192, 3).unwrap().len() > 1);
        assert!(ntt_groups(32768, 3).unwrap().len() > 1);
        let output = check_cpu_reference(&inputs, 6);
        let before = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot();
        assert!(coset_lde_commit(&inputs, 6, 8).is_err());
        let after = ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot();
        assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
        assert_eq!(after.allocations, before.allocations);
        // Admission failure must not corrupt a previously retained tree.
        assert!(output.open(32767).is_ok());
        drop(output);
    }
}
