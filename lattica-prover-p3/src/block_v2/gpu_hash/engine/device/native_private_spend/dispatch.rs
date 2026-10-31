//! Generated fixed kernel ABI bindings; see source-manifest.json.
use super::*;
// Status is 64 bytes in an accounted u64 allocation. Bind its retained core
// memory explicitly as u32 to match the OpenCL ABI even on drivers exposing
// argument metadata. Alignment8 satisfies uint; type checks stay enabled.
#[allow(deprecated)]
pub(super) fn build_step(
    engine: &Engine,
    program: &ocl::Program,
    buffers: &Scratch,
    step: usize,
    limits: SpendLimits,
) -> Result<ocl::Kernel, String> {
    let matrices = &buffers.matrices;
    let mut b = ocl::Kernel::builder();
    b.program(program)
        .queue(engine.pq.queue().clone())
        .name(
            STEPS
                .get(step)
                .ok_or("native spend invalid dispatch step")?
                .name,
        )
        .global_work_size(1usize);
    match step {
        0 => {
            b.arg(&matrices[INPUT].storage.buffer)
                .arg((input_layout::WORDS as u64))
                .arg((input_layout::ENTROPY_KEY as u64))
                .arg(0u64)
                .arg(&matrices[RNG].storage.buffer)
                .arg(limits.random_call_limit)
                .arg(limits.proposal_limit)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        1 => {
            b.arg(&matrices[INPUT].storage.buffer)
                .arg((input_layout::WORDS as u64))
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        2 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        3 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(59417u64)
                .arg(0u64)
                .arg(9u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(30u32);
        }
        4 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(61721u64)
                .arg(0u64)
                .arg(9u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(30u32);
        }
        5 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        6 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(limits.max_attempts)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        7 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(154349u64)
                .arg(0u64)
                .arg(4u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        8 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(137197u64)
                .arg(0u64)
                .arg(0u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        9 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(139501u64)
                .arg(0u64)
                .arg(0u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        10 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(148461u64)
                .arg(0u64)
                .arg(0u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        11 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(176365u64)
                .arg(0u64)
                .arg(11u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        12 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(181997u64)
                .arg(0u64)
                .arg(1u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        13 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(184813u64)
                .arg(0u64)
                .arg(1u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(40u32);
        }
        14 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(40u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        15 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(235501u64)
                .arg(0u64)
                .arg(10u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(50u32);
        }
        16 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(238061u64)
                .arg(0u64)
                .arg(2u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(50u32);
        }
        17 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(247021u64)
                .arg(0u64)
                .arg(3u32)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(50u32);
        }
        18 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(50u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        19 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(60u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        20 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(127265u64)
                .arg(255981u64)
                .arg(0u64)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(60u32);
        }
        21 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(70u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        22 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(132641u64)
                .arg(258797u64)
                .arg(0u64)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(70u32);
        }
        23 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg(80u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        24 => {
            b.arg(&matrices[RNG].storage.buffer)
                .arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[REJECTION_OFFSETS_BUFFER].storage.buffer)
                .arg(10u32)
                .arg(0u64)
                .arg(1u32)
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core())
                .arg(80u32);
        }
        25 => {
            b.arg(&matrices[ARENA].storage.buffer)
                .arg((ARENA_WORDS as u64))
                .arg(&matrices[OFFSETS].storage.buffer)
                .arg((SLOT_OFFSETS.len() as u32))
                .arg_buf::<u32, _>(matrices[STATUS].storage.buffer.as_core());
        }
        _ => return Err("native spend invalid dispatch step".into()),
    }
    b.build().map_err(|e| e.to_string())
}

// Additional real device dispatches internal to logical steps14 and18. The
// caller records every returned kernel before granting the original step bit.
#[allow(deprecated)]
pub(super) fn preparations(
    engine: &Engine,
    program: &ocl::Program,
    buffers: &Scratch,
    step: usize,
) -> Result<Vec<(&'static str, ocl::Kernel)>, String> {
    let (phase, lanes): (u32, usize) = match step {
        14 => (40, 72),
        18 => (50, 80),
        _ => return Ok(Vec::new()),
    };
    let mut descriptions = vec![
        ("pq_spend_parallel_admit", 1usize),
        ("pq_spend_parallel_polynomials", lanes),
    ];
    if step == 14 {
        descriptions.push(("pq_spend_parallel_early_rows", 24));
    }
    let m = &buffers.matrices;
    descriptions
        .into_iter()
        .map(|(name, work_items)| {
            let kernel = ocl::Kernel::builder()
                .program(program)
                .queue(engine.pq.queue().clone())
                .name(name)
                .global_work_size(work_items)
                .arg(&m[ARENA].storage.buffer)
                .arg(ARENA_WORDS as u64)
                .arg(&m[OFFSETS].storage.buffer)
                .arg(SLOT_OFFSETS.len() as u32)
                .arg(phase)
                .arg_buf::<u32, _>(m[STATUS].storage.buffer.as_core())
                .build()
                .map_err(|e| e.to_string())?;
            Ok((name, kernel))
        })
        .collect()
}
