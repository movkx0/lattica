//! Reconstruct each tile once for a batch of queries; download only those rows.
//! Salt and Merkle path data are retained by the caller. No randomness is used.
use super::*;
use crate::config::Val;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

pub(super) const KERNEL_SRC: &str = r#"
__kernel void query_gather(
    __global const ulong *input, __global const ulong *indices,
    __global ulong *output, uint width, uint query_count
) {
    size_t item = get_global_id(0);
    if (item >= (size_t)width * query_count) return;
    size_t query = item / width;
    output[item] = input[(size_t)indices[query] * width + item % width];
}
"#;

fn tile_columns(
    height: usize,
    max_width: usize,
    remaining: usize,
    max_alloc: usize,
    queries: usize,
    gather: bool,
) -> Result<usize, String> {
    let matrix_column = height.checked_mul(8).ok_or("query column size overflow")?;
    let query_column = queries.checked_mul(8).ok_or("query index size overflow")?;
    if matrix_column == 0 || max_width == 0 || queries == 0 || queries > 256 {
        return Err("query tile dimensions".into());
    }
    let fixed = if gather { query_column } else { 0 };
    if fixed > max_alloc {
        return Err("query index buffer exceeds device allocation limit".into());
    }
    let per_column = matrix_column
        .checked_mul(2)
        .and_then(|n| n.checked_add(if gather { query_column } else { 0 }))
        .ok_or("query workspace size overflow")?;
    let available = remaining
        .checked_sub(fixed)
        .ok_or("query index allowance")?;
    let mut columns = max_width
        .min(available / per_column)
        .min(max_alloc / matrix_column)
        .min(u32::MAX as usize / height);
    if gather {
        columns = columns
            .min(max_alloc / query_column)
            .min(u32::MAX as usize / queries);
    }
    if columns == 0 {
        return Err("no query transform column fits device budget".into());
    }
    Ok(columns)
}

pub(crate) fn reconstruct(
    prefixes: &[super::super::prefix_storage::PrefixMatrix],
    height: usize,
    indices: &[usize],
) -> Result<Vec<Vec<Vec<Val>>>, String> {
    if prefixes.is_empty()
        || indices.len() > 256
        || indices.iter().any(|i| *i >= height)
        || !height.is_power_of_two()
        || height > (1 << 25)
    {
        return Err("query reconstruction dimensions".into());
    }
    let low = height >> crate::block_v2::profile::LOG_BLOWUP;
    if low == 0 || prefixes.iter().any(|p| p.width == 0 || p.height() < low) {
        return Err("query reconstruction missing degree prefix".into());
    }
    let mut guard = ENGINE
        .get()
        .ok_or("GPU not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = guard.as_mut().ok_or("GPU shut down")?;
    engine.fence().finish()?;
    engine.workspace = None;
    if indices.is_empty() {
        return Ok(Vec::new());
    }
    let started = Instant::now();
    let gather = engine.query_gather;
    let live = engine
        .accounting
        .lock()
        .map_err(|_| "GPU accounting poisoned")?
        .live;
    let roots = height.trailing_zeros() as usize;
    #[cfg(feature = "gpu-metal")]
    let backend_reserve = engine.pq.ntt_cache_reserve(&[low, height])?;
    #[cfg(not(feature = "gpu-metal"))]
    let backend_reserve = 0;
    let remaining = engine
        .limits
        .managed_bytes
        .checked_sub(live + 2 * roots * 8)
        .and_then(|bytes| bytes.checked_sub(backend_reserve))
        .ok_or("query workspace allowance")?;
    let max_width = prefixes.iter().map(|p| p.width).max().unwrap();
    let columns = tile_columns(
        height,
        max_width,
        remaining,
        engine.max_alloc,
        indices.len(),
        gather,
    )?;
    let alloc = |n| {
        allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            n,
            compute::flags::MEM_READ_WRITE,
        )
    };
    let a = alloc(height * columns)?;
    let b = alloc(height * columns)?;
    let forward = alloc(roots)?;
    let inverse = alloc(roots)?;
    let query_indices = if gather {
        Some(alloc(indices.len())?)
    } else {
        None
    };
    let query_output = if gather {
        Some(alloc(indices.len() * columns)?)
    } else {
        None
    };
    let mut result: Vec<Vec<Vec<Val>>> = indices
        .iter()
        .map(|_| prefixes.iter().map(|p| vec![Val::ZERO; p.width]).collect())
        .collect();
    let fence = engine.fence();
    if let Some(storage) = &query_indices {
        let words: Vec<u64> = indices.iter().map(|&index| index as u64).collect();
        storage
            .buffer
            .write(&words)
            .enq()
            .map_err(|e| e.to_string())?;
        engine.stats.uploaded_bytes += (words.len() * 8) as u64;
    }
    engine.lde_upload_rows(&forward.buffer, roots, 1, |row, dst| {
        dst[0] = Val::two_adic_generator(row + 1).as_canonical_u64();
    })?;
    engine.lde_upload_rows(&inverse.buffer, roots, 1, |row, dst| {
        dst[0] = Val::two_adic_generator(row + 1)
            .inverse()
            .as_canonical_u64();
    })?;
    for (m, prefix) in prefixes.iter().enumerate() {
        for first in (0..prefix.width).step_by(columns) {
            let width = columns.min(prefix.width - first);
            b.buffer
                .cmd()
                .fill(0u64, Some(height * width))
                .enq()
                .map_err(|e| e.to_string())?;
            let target = if low == 1 { &b.buffer } else { &a.buffer };
            engine.lde_upload_rows(target, low, width, |row, dst| {
                let row = if low == 1 {
                    0
                } else {
                    row.reverse_bits() >> (usize::BITS - low.trailing_zeros())
                };
                for (out, value) in dst
                    .iter_mut()
                    .zip(&prefix.values[row * prefix.width + first..])
                {
                    *out = value.as_canonical_u64();
                }
            })?;
            if low > 1 {
                engine.lde_ntt(
                    &a.buffer,
                    &b.buffer,
                    &inverse.buffer,
                    true,
                    low,
                    width,
                    Val::from_usize(low).inverse().as_canonical_u64(),
                    1,
                    false,
                    false,
                    false,
                    None,
                )?;
            }
            let in_a = engine.lde_ntt(
                &b.buffer,
                &a.buffer,
                &forward.buffer,
                false,
                height,
                width,
                1,
                1,
                true,
                true,
                false,
                None,
            )?;
            let output = if in_a { &a.buffer } else { &b.buffer };
            if let (Some(query_indices), Some(query_output)) = (&query_indices, &query_output) {
                let mut event = Event::empty();
                // SAFETY: indices were checked against height; tile_columns
                // bounds both buffers and the 32-bit dispatch range. QueueFence
                // drains submitted work before any accounted buffer is dropped.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("query_gather")
                        .arg(output)
                        .arg(&query_indices.buffer)
                        .arg(&query_output.buffer)
                        .arg(width as u32)
                        .arg(indices.len() as u32)
                        .global_work_size(width * indices.len())
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                engine.stats.query_gather_device_ns +=
                    engine.timeline.record("query_gather", &event)?;
                let mut words = vec![0u64; width * indices.len()];
                query_output
                    .buffer
                    .read(&mut words)
                    .enq()
                    .map_err(|e| e.to_string())?;
                engine.stats.query_readbacks += 1;
                for (q, row) in words.chunks_exact(width).enumerate() {
                    for (out, word) in result[q][m][first..first + width].iter_mut().zip(row) {
                        *out = Val::from_u64(*word);
                    }
                }
            } else {
                let mut words = vec![0u64; width];
                for (q, &index) in indices.iter().enumerate() {
                    output
                        .read(&mut words)
                        .offset(index * width)
                        .enq()
                        .map_err(|e| e.to_string())?;
                    engine.stats.query_readbacks += 1;
                    for (out, word) in result[q][m][first..first + width].iter_mut().zip(&words) {
                        *out = Val::from_u64(*word);
                    }
                }
            }
            let downloaded = (indices.len() * width * 8) as u64;
            engine.stats.downloaded_bytes += downloaded;
            engine.stats.query_downloaded_bytes += downloaded;
            engine.stats.query_reconstruction_tiles += 1;
        }
    }
    fence.finish()?;
    engine.stats.query_reconstruction_calls += 1;
    engine.stats.query_reconstruction_wall_ns += started.elapsed().as_nanos();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::tile_columns;

    #[test]
    fn gather_reserves_both_transform_buffers_indices_and_output() {
        for height in [16usize, 64, 4096, 1 << 23] {
            for queries in [1usize, 17, 256] {
                for max_alloc in [4096usize, 1 << 20, 1 << 30] {
                    for remaining in [1usize << 16, 1 << 24, 7usize << 30] {
                        if let Ok(columns) =
                            tile_columns(height, 200, remaining, max_alloc, queries, true)
                        {
                            assert!(
                                2 * height * columns * 8 + queries * (columns + 1) * 8 <= remaining
                            );
                            assert!(height * columns * 8 <= max_alloc);
                            assert!(queries * columns * 8 <= max_alloc);
                            assert!(queries * 8 <= max_alloc);
                            assert!(height * columns <= u32::MAX as usize);
                            assert!(queries * columns <= u32::MAX as usize);
                        }
                    }
                }
            }
        }
        let bytes = 2 * 64 * 3 * 8;
        assert_eq!(tile_columns(64, 3, bytes, bytes, 17, false).unwrap(), 3);
        assert_eq!(tile_columns(64, 3, bytes, bytes, 17, true).unwrap(), 2);
    }

    #[test]
    fn query_tile_rejects_unaffordable_and_overflowing_allocations() {
        assert!(tile_columns(16, 1, 256, 256, 1, true).is_err());
        assert!(tile_columns(16, 1, 4096, 128, 256, true).is_err());
        assert!(tile_columns(16, 1, 4096, 4096, 0, true).is_err());
        assert!(tile_columns(usize::MAX, 1, usize::MAX, usize::MAX, 1, true).is_err());
    }
}
