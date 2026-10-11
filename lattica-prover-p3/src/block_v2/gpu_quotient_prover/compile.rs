//! Explicit symbolic compilation, once per AIR and proof attempt. Graphs are
//! dropped before the next AIR; only bounded immutable instructions survive.
use super::program::Program;
use crate::block_v2::{
    gpu_hash::device::DeviceSession,
    machine::{compiler_constants::Constants, symbolic},
};
use crate::proving::Run;
use p3_air::{symbolic::AirLayout, Air};
use p3_lookup::{LogUpGadget, Lookup};
use std::sync::Arc;

const MAX_BATCH_BYTES: usize = 16 << 20;

pub(super) struct Compiled {
    pub program: Arc<Program>,
    pub log_chunks: usize,
    pub base_constraints: usize,
}

pub(super) struct Batch {
    entries: Vec<Compiled>,
    bytes: usize,
    limit: usize,
}

impl Batch {
    pub fn new(count: usize, host_allowance: usize) -> Result<Self, String> {
        if host_allowance < symbolic::HOST_BYTES as usize {
            return Err("GPU quotient symbolic/compiler scratch exceeds host allowance".into());
        }
        let bytes = count
            .checked_mul(core::mem::size_of::<Compiled>())
            .ok_or("GPU quotient batch count overflow")?;
        if bytes > MAX_BATCH_BYTES {
            return Err("GPU quotient batch metadata exceeds host allowance".into());
        }
        Ok(Self {
            entries: Vec::with_capacity(count),
            bytes,
            limit: count,
        })
    }

    pub fn push(
        &mut self,
        program: Program,
        log_chunks: usize,
        base_constraints: usize,
    ) -> Result<(), String> {
        if self.entries.len() == self.limit {
            return Err("GPU quotient batch exceeds admitted AIR count".into());
        }
        // Include Vec capacity and the Arc header, not just instruction length.
        let bytes = program
            .instructions
            .capacity()
            .checked_mul(core::mem::size_of::<u64>())
            .and_then(|n| {
                n.checked_add(core::mem::size_of::<Program>() + 2 * core::mem::size_of::<usize>())
            })
            .and_then(|n| n.checked_add(self.bytes))
            .ok_or("GPU quotient program storage overflow")?;
        if bytes > MAX_BATCH_BYTES {
            return Err("GPU quotient batch instructions exceed host allowance".into());
        }
        self.bytes = bytes;
        self.entries.push(Compiled {
            program: Arc::new(program),
            log_chunks,
            base_constraints,
        });
        Ok(())
    }

    pub fn report(&self) {
        eprintln!(
            "bounded_gpu_quotient_compiler airs={} cached_host_bytes={} scratch_allowance_bytes={}",
            self.entries.len(),
            self.bytes,
            symbolic::HOST_BYTES
        );
    }

    pub fn get(&self, index: usize) -> &Compiled {
        &self.entries[index]
    }
}

// Conservative transient lowering allowance: capacity growth, compiler maps,
// schedules, register allocation and instruction output, plus the batch cache.
// Symbolic recording/normalization has its separate 64 MiB sub-allowance.
const _: () = assert!(
    (super::program::MAX_NODES as u64) * 384
        + (super::program::MAX_CONSTRAINTS as u64) * 128
        + MAX_BATCH_BYTES as u64
        <= symbolic::HOST_BYTES - (64 << 20)
);

pub(super) fn air<A: Air<symbolic::Builder>>(
    session: &DeviceSession,
    run: &Run,
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<crate::config::Val>],
    is_zk: usize,
) -> Result<(Program, usize, usize), String> {
    let gadget = LogUpGadget::new();
    let layout = symbolic::batch_layout(layout, lookups, &gadget)
        .map_err(|e| format!("GPU quotient layout: {e:?}"))?;
    Program::input_shape(layout)?;
    let constraints = symbolic::batch_with_layout(
        air,
        layout,
        lookups,
        &gadget,
        Constants::device(session, run),
    )
    .map_err(|e| format!("GPU quotient symbolic evaluation: {e:?}"))?;
    let log_chunks = symbolic::batch_log_chunks(air, &constraints, lookups, &gadget, is_zk)
        .map_err(|e| format!("GPU quotient degree: {e:?}"))?;
    let count = constraints.base.len();
    if air.num_constraints().is_some_and(|n| n != count) {
        return Err(
            "GPU quotient base constraint count hint differs from symbolic evaluation".into(),
        );
    }
    let program = Program::from_constraints(layout, &constraints)?;
    Ok((program, log_chunks, count))
}
