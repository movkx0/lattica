//! Reconstruct each tile once for a batch of queries; download only those rows.
//! Salt and Merkle path data are retained by the caller. No randomness is used.
use super::*;
use crate::config::Val;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};

pub(crate) fn reconstruct(
    prefixes: &[RowMajorMatrix<Val>],
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
    let live = engine
        .accounting
        .lock()
        .map_err(|_| "GPU accounting poisoned")?
        .live;
    let roots = height.trailing_zeros() as usize;
    let remaining = engine
        .limits
        .managed_bytes
        .checked_sub(live + 2 * roots * 8)
        .ok_or("query workspace allowance")?;
    let max_width = prefixes.iter().map(|p| p.width).max().unwrap();
    let columns = max_width
        .min(remaining / 2 / height / 8)
        .min(engine.max_alloc / height / 8)
        .min(u32::MAX as usize / height);
    if columns == 0 {
        return Err("no query transform column fits device budget".into());
    }
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
    let mut result: Vec<Vec<Vec<Val>>> = indices
        .iter()
        .map(|_| prefixes.iter().map(|p| vec![Val::ZERO; p.width]).collect())
        .collect();
    let fence = engine.fence();
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
                    low,
                    width,
                    Val::from_usize(low).inverse().as_canonical_u64(),
                    1,
                    false,
                    false,
                    false,
                )?;
            }
            let in_a = engine.lde_ntt(
                &b.buffer,
                &a.buffer,
                &forward.buffer,
                height,
                width,
                1,
                1,
                true,
                true,
                false,
            )?;
            let output = if in_a { &a.buffer } else { &b.buffer };
            let mut words = vec![0u64; width];
            for (q, &index) in indices.iter().enumerate() {
                output
                    .read(&mut words)
                    .offset(index * width)
                    .enq()
                    .map_err(|e| e.to_string())?;
                for (out, word) in result[q][m][first..first + width].iter_mut().zip(&words) {
                    *out = Val::from_u64(*word);
                }
                engine.stats.downloaded_bytes += (width * 8) as u64;
            }
        }
    }
    fence.finish()?;
    Ok(result)
}
