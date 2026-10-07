//! Opt-in Goldilocks cubic arity-two FRI folding. Fiat-Shamir sampling stays
//! with the caller; only the already-sampled algebraic fold runs on device.
use super::*;
use crate::block_v2::profile::Challenge;
use p3_field::{BasedVectorSpace, Field, PrimeField64, TwoAdicField};

const TILE_ROWS: usize = 8192;
pub(super) const KERNEL_SRC: &str = r#"
__kernel void fri_fold_two(__global const ulong *input, __global ulong *output,
    uint rows, uint row_start, uint log_rows, ulong g_inv,
    ulong beta0, ulong beta1, ulong beta2) {
    uint r = (uint)get_global_id(0);
    if (r >= rows) return;
    uint index = row_start + r, reversed = 0;
    for (uint i = 0; i < log_rows; ++i) { reversed = (reversed << 1) | (index & 1); index >>= 1; }
    ulong inverse = gl_pow(g_inv, (ulong)reversed);
    ulong beta[3] = { beta0, beta1, beta2 }, delta[3], product[3];
    for (uint i = 0; i < 3; ++i) delta[i] = gl_sub(input[6 * (size_t)r + i], input[6 * (size_t)r + 3 + i]);
    opening_cubic_mul(delta, beta, product);
    for (uint i = 0; i < 3; ++i) {
        ulong sum = gl_add(input[6 * (size_t)r + i], input[6 * (size_t)r + 3 + i]);
        output[3 * (size_t)r + i] = gl_canon(gl_mul(gl_add(sum, gl_mul(product[i], inverse)), 9223372034707292161UL));
    }
}
"#;

/// None means the explicitly selected backend remains the CPU reference.
pub(crate) fn fold(
    beta: Challenge,
    values: &[Challenge],
) -> Result<Option<Vec<Challenge>>, String> {
    let Some(engine) = ENGINE.get() else {
        return Ok(None);
    };
    let mut guard = engine.lock().map_err(|_| "GPU engine poisoned")?;
    let engine = guard.as_mut().ok_or("GPU engine shut down")?;
    if !engine.fri_fold {
        return Ok(None);
    }
    if values.len() < 2 || !values.len().is_power_of_two() || values.len() > 1 << 25 {
        return Err("GPU FRI folding dimensions".into());
    }
    engine.fence().finish()?;
    // The LDE scratch cache is replaceable. Reclaim it before a different phase.
    engine.lde_workspace = None;
    let count = values.len() / 2;
    let tile = count.min(TILE_ROWS);
    let input = allocation(
        &engine.pq,
        &engine.accounting,
        engine.limits,
        engine.max_alloc,
        tile * 6,
        compute::flags::MEM_READ_WRITE,
    )?;
    let output = allocation(
        &engine.pq,
        &engine.accounting,
        engine.limits,
        engine.max_alloc,
        tile * 3,
        compute::flags::MEM_READ_WRITE,
    )?;
    let fence = engine.fence();
    let log_rows = count.ilog2();
    let inverse = Val::two_adic_generator(log_rows as usize + 1)
        .inverse()
        .as_canonical_u64();
    let b: &[Val] = beta.as_basis_coefficients_slice();
    let mut upload = vec![0u64; tile * 6];
    let mut download = vec![0u64; tile * 3];
    let mut result = Vec::with_capacity(count);
    let started = Instant::now();
    let mut device_ns = 0u128;
    for first in (0..count).step_by(tile) {
        let rows = (count - first).min(tile);
        for (dst, value) in upload
            .chunks_exact_mut(3)
            .zip(&values[first * 2..(first + rows) * 2])
        {
            let coefficients: &[Val] = value.as_basis_coefficients_slice();
            for (word, coefficient) in dst.iter_mut().zip(coefficients) {
                *word = coefficient.as_canonical_u64();
            }
        }
        input
            .buffer
            .write(&upload[..rows * 6])
            .enq()
            .map_err(|e| e.to_string())?;
        let mut event = Event::empty();
        // SAFETY: all buffers are tile-sized, rows is bounded by the tile and
        // the global row index/domain fit u32. The fence drains before reuse.
        unsafe {
            engine
                .pq
                .kernel_builder("fri_fold_two")
                .arg(&input.buffer)
                .arg(&output.buffer)
                .arg(rows as u32)
                .arg(first as u32)
                .arg(log_rows)
                .arg(inverse)
                .arg(b[0].as_canonical_u64())
                .arg(b[1].as_canonical_u64())
                .arg(b[2].as_canonical_u64())
                .global_work_size(rows)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        device_ns += engine.timeline.record("fri_fold_two", &event)?;
        output
            .buffer
            .read(&mut download[..rows * 3])
            .enq()
            .map_err(|e| e.to_string())?;
        fence.finish()?;
        result.extend(download[..rows * 3].chunks_exact(3).map(|row| {
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(row[0]),
                Val::from_u64(row[1]),
                Val::from_u64(row[2]),
            ])
            .unwrap()
        }));
    }
    eprintln!("bounded_gpu_fri_fold rows={count} workspace_bytes={} uploaded_bytes={} downloaded_bytes={} device_ns={device_ns} wall_ns={}",
              tile * 9 * 8, values.len() * 24, count * 24, started.elapsed().as_nanos());
    Ok(Some(result))
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    use p3_matrix::dense::RowMajorMatrixView;
    #[test]
    #[ignore = "requires OpenCL GPU; run serially in a bounded service"]
    fn gpu_fri_fold_matches_cpu_on_domains_challenges_and_tile_boundaries() {
        let _shutdown = TestShutdownGuard;
        initialize_mode(
            Limits {
                managed_bytes: 4 << 20,
                tile_bytes: 64 << 10,
                staging_bytes: 4096,
            },
            TransferMode::Serial,
        )
        .unwrap();
        ENGINE
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .fri_fold = true;
        let cpu = TwoAdicFriFolding::<(), ()>(std::marker::PhantomData);
        for log in [0, 1, 4, 13, 14] {
            let rows = 1 << log;
            let values: Vec<_> = (0..rows * 2)
                .map(|i| {
                    Challenge::from_basis_coefficients_fn(|j| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xffff_ffff_0000_0000)
                                .wrapping_add(j as u64),
                        )
                    })
                })
                .collect();
            for beta in [
                Challenge::ZERO,
                Challenge::ONE,
                Challenge::from_basis_coefficients_fn(|i| Val::from_u64(17 + i as u64)),
            ] {
                let expected =
                    <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Val, Challenge>>::fold_matrix(
                        &cpu,
                        beta,
                        1,
                        RowMajorMatrixView::new(&values, 2),
                    );
                assert_eq!(fold(beta, &values).unwrap().unwrap(), expected);
            }
        }
        assert!(fold(Challenge::ONE, &[]).is_err());
        assert!(fold(Challenge::ONE, &[Challenge::ONE; 3]).is_err());
    }
}
