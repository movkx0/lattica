//! Public deterministic kernel data; allocations share the live engine ledger.
use super::super::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};

pub(super) const SOURCE: &str = r#"
__kernel void aggregation_fill(__global ulong *out, ulong count) {
    ulong i=get_global_id(0); if(i<count) out[i]=(i*0x9e3779b97f4a7c15UL)^17UL;
}
__kernel void aggregation_compare(__global const ulong *a, __global const ulong *b,
    __global uint *bad, ulong count) {
    ulong i=get_global_id(0); if(i<count && gl_canon(a[i])!=gl_canon(b[i])) atomic_or(bad,1u);
}
__kernel void aggregation_square_probe(__global const ulong *a, __global ulong *b, ulong count) {
    ulong i=get_global_id(0); if(i<count) b[i]=gl_canon(gl_square(a[i]));
}
"#;

struct Buffers {
    values: Vec<Allocation>,
    queue: compute::Queue,
}
impl Drop for Buffers {
    fn drop(&mut self) {
        if let Err(error) = self.queue.finish() {
            fatal_cleanup("kernel_screen_drain", error);
        }
    }
}
fn buffers(engine: &Engine, words: &[usize]) -> Result<Buffers, String> {
    let mut owned = Buffers {
        values: Vec::new(),
        queue: engine.pq.queue().clone(),
    };
    for &words in words {
        let value = allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            words,
            compute::flags::MEM_READ_WRITE,
        )?;
        owned.values.push(value);
    }
    Ok(owned)
}
fn fill(engine: &Engine, buffer: &Buffer<u64>) -> Result<(), String> {
    unsafe {
        engine
            .pq
            .kernel_builder("aggregation_fill")
            .arg(buffer)
            .arg(buffer.len() as u64)
            .global_work_size(buffer.len())
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enq()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn compare(
    engine: &Engine,
    a: &Buffer<u64>,
    b: &Buffer<u64>,
    flag: &Buffer<u64>,
) -> Result<(), String> {
    flag.cmd()
        .fill(0u64, None)
        .enq()
        .map_err(|e| e.to_string())?;
    unsafe {
        engine
            .pq
            .kernel_builder("aggregation_compare")
            .arg(a)
            .arg(b)
            .arg(flag)
            .arg(a.len() as u64)
            .global_work_size(a.len())
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enq()
            .map_err(|e| e.to_string())?;
    }
    let mut bad = [0u64];
    flag.read(&mut bad[..]).enq().map_err(|e| e.to_string())?;
    if bad[0] != 0 {
        return Err("kernel screen differs from reference transform".into());
    }
    Ok(())
}

pub fn run(seconds: u64) -> Result<serde_json::Value, String> {
    let start = std::time::Instant::now();
    let mut slot = ENGINE
        .get()
        .ok_or("kernel screen requires a live GPU session")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = slot
        .as_mut()
        .ok_or("kernel screen requires initialized engine")?;
    let selected = engine.tuning;
    let outcome = (|| {
        let mut rows = Vec::new();
        for (height, width) in [
            (1usize << 22, 3usize),
            (1 << 23, 8),
            (1 << 24, 1),
            (1 << 24, 8),
            (1 << 24, 16),
        ] {
            if start.elapsed().as_secs() >= seconds {
                return Err("kernel screen deadline".into());
            }
            let words = height.checked_mul(width).ok_or("kernel screen overflow")?;
            let owned = buffers(engine, &[words, words, words, 24, 1])?;
            let [src, dst, reference, roots, flag] = &owned.values[..] else {
                unreachable!()
            };
            let values: Vec<_> = (1..=24)
                .map(|log| crate::config::Val::two_adic_generator(log).as_canonical_u64())
                .collect();
            roots
                .buffer
                .write(&values)
                .enq()
                .map_err(|e| e.to_string())?;
            fill(engine, &src.buffer)?;
            engine.tuning.ntt_schedule = super::Ntt::Baseline;
            let in_dst = engine.lde_ntt(
                &src.buffer,
                &dst.buffer,
                &roots.buffer,
                false,
                height,
                width,
                1,
                1,
                true,
                false,
                false,
                None,
            )?;
            let answer = if in_dst { &dst.buffer } else { &src.buffer };
            answer
                .cmd()
                .copy(&reference.buffer, None, None)
                .enq()
                .map_err(|e| e.to_string())?;
            engine.tuning = selected;
            for repetition in 0..4 {
                if start.elapsed().as_secs() >= seconds {
                    return Err("kernel screen deadline".into());
                }
                fill(engine, &src.buffer)?;
                engine.pq.queue().finish().map_err(|e| e.to_string())?;
                let before = engine.stats.lde_transform_ns;
                let begun = std::time::Instant::now();
                let in_dst = engine.lde_ntt(
                    &src.buffer,
                    &dst.buffer,
                    &roots.buffer,
                    false,
                    height,
                    width,
                    1,
                    1,
                    true,
                    false,
                    false,
                    None,
                )?;
                engine.pq.queue().finish().map_err(|e| e.to_string())?;
                let elapsed = begun.elapsed().as_secs_f64();
                compare(
                    engine,
                    if in_dst { &dst.buffer } else { &src.buffer },
                    &reference.buffer,
                    &flag.buffer,
                )?;
                rows.push(serde_json::json!({"kind":"ntt","rows":height,"columns":width,"repetition":repetition,
                    "seconds":elapsed,"device_ns":engine.stats.lde_transform_ns-before,"reference_equal":true}));
            }
        }
        // The same commitment geometry across processes isolates Poseidon variants.
        let height = 1usize << 20;
        let owned = buffers(engine, &[height * 16, height * 4])?;
        fill(engine, &owned.values[0].buffer)?;
        for repetition in 0..4 {
            if start.elapsed().as_secs() >= seconds {
                return Err("kernel screen deadline".into());
            }
            let mut builder = engine.pq.kernel_builder("leaf_hash");
            builder
                .arg(&owned.values[0].buffer)
                .arg(&owned.values[1].buffer)
                .arg(0u32)
                .arg(height as u32)
                .arg(16u32);
            for constant in &engine.constants {
                builder.arg(&constant.buffer);
            }
            let kernel = builder
                .global_work_size(height)
                .build()
                .map_err(|e| e.to_string())?;
            let mut event = Event::empty();
            let begun = std::time::Instant::now();
            unsafe {
                kernel
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            event.wait_for().map_err(|e| e.to_string())?;
            let ns = engine.timeline.record("kernel screen poseidon", &event)?;
            rows.push(serde_json::json!({"kind":"poseidon","rows":height,"columns":16,"repetition":repetition,
                "seconds":begun.elapsed().as_secs_f64(),"device_ns":ns,
                "private_memory":format!("{:?}",kernel.wg_info(engine.pq.device(),ocl::core::KernelWorkGroupInfo::PrivateMemSize).map_err(|e|e.to_string())?)}));
        }
        Ok(
            serde_json::json!({"scope":"deterministic-kernel-screen","proofs_generated":0,"samples":rows,
            "transform_reference_equal":true,"independent_correctness_required":true}),
        )
    })();
    engine.tuning = selected;
    engine.pq.queue().finish().map_err(|e| e.to_string())?;
    outcome
}
