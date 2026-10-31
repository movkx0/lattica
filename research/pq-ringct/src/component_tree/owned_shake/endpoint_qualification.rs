//! Release/x86_64 test-only constraint evaluation, never a proof or dispatch.
//!
//! Keep the existing output/request reservations live, then admit all newly
//! simultaneous evaluation storage before inspecting capacities or evaluating.
//! No raw program escapes and no caller-selected limit or token is accepted.

use super::{requirement, Bytes, Category, Ledger, OwnedCompiledShake, Reservation, MAX_ROWS};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    program::{ExecutionError, Val, Wire, MAX_WIRES},
    MachineAir, WIDTH,
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Poseidon2Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Geometry,
    Authority,
    Admission,
    RetainedStorage,
    Execution(ExecutionError),
}

// Pinned p3-goldilocks 0.6.1 x86_64 constructor allocates two four-round,
// eight-element external tables and one 22-element internal table. Constructors
// move the Vecs without cloning. One scalar permutation is alive at a time.
const POSEIDON_BYTES: usize = (2 * 4 * 8 + 22) * size_of::<Val>()
    + size_of::<Poseidon2Goldilocks<8>>()
    + 4 * size_of::<[Val; 8]>();
// Program retained-size error paths create only these short fixed diagnostics;
// keep their old/new String backing covered before invoking that query.
const SOURCE_ERROR_BYTES: usize =
    4 * "machine source capacity overflow".len() + 2 * size_of::<String>();
// trace() holds reads()/writes() simultaneously for one operation. Both have
// at most eight wires; cubic and Poseidon trace rows use stack arrays instead.
const HELPER_BYTES: usize = POSEIDON_BYTES
    + SOURCE_ERROR_BYTES
    + 16 * size_of::<Wire>()
    + 2 * size_of::<Vec<Wire>>()
    + size_of::<Vec<Val>>()
    + size_of::<RowMajorMatrix<Val>>()
    + size_of::<MachineAir>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scratch {
    wire_bytes: usize,
    trace_bytes: usize,
    helper_bytes: usize,
    total_bytes: usize,
}

impl Scratch {
    fn for_geometry(wires: usize, rows: usize) -> Result<Self, Error> {
        if wires > MAX_WIRES || !(8..=MAX_ROWS).contains(&rows) || !rows.is_power_of_two() {
            return Err(Error::Geometry);
        }
        let wire_bytes = wires.checked_mul(size_of::<Val>()).ok_or(Error::Geometry)?;
        let trace_bytes = rows
            .checked_mul(WIDTH)
            .and_then(|n| n.checked_mul(size_of::<Val>()))
            .ok_or(Error::Geometry)?;
        let helper_bytes = HELPER_BYTES + size_of::<Evaluator<'_, '_>>();
        let total_bytes = wire_bytes
            .checked_add(trace_bytes)
            .and_then(|n| n.checked_add(helper_bytes))
            .ok_or(Error::Geometry)?;
        Ok(Self {
            wire_bytes,
            trace_bytes,
            helper_bytes,
            total_bytes,
        })
    }
}

struct Evaluator<'scope, 'request> {
    output: &'scope mut OwnedCompiledShake<'request>,
    scratch: Scratch,
    retained_program_bytes: usize,
    retained_input_bytes: usize,
    // Every returned trace and temporary wire Vec dies inside run() before this
    // reservation can retire. The borrowed output keeps its original tokens.
    _reservation: Reservation,
}

impl<'scope, 'request> Evaluator<'scope, 'request> {
    fn new(
        output: &'scope mut OwnedCompiledShake<'request>,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device > 8 << 30
            || !output._program.belongs_to(ledger)
            || !output._inputs.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        let scratch = Scratch::for_geometry(
            output.compiled.program.wire_count(),
            output.compiled.program.height(),
        )?;
        let reservation = ledger
            .admit_phase(
                requirement(Category::PhaseScratch, scratch.total_bytes)
                    .map_err(|_| Error::Geometry)?,
            )
            .map_err(|_| Error::Admission)?;
        // The query's rare String error transients are covered by the admitted
        // helper term. No observed capacity shrinks the retained 2 GiB charge.
        let retained_program_bytes = output
            .compiled
            .program
            .retained_host_bytes()
            .map_err(|_| Error::RetainedStorage)?;
        let retained_input_bytes = output
            .compiled
            .public
            .capacity()
            .checked_add(output.compiled.witness.capacity())
            .and_then(|n| n.checked_mul(size_of::<Val>()))
            .ok_or(Error::RetainedStorage)?;
        if retained_program_bytes as u64
            > output
                ._program
                .requirements()
                .get(Category::SymbolicCompiler)
                .host
            || retained_input_bytes as u64
                > output
                    ._inputs
                    .requirements()
                    .get(Category::CompilerInputs)
                    .host
            || output.compiled.public.len() != output.compiled.program.public_values()
            || output.compiled.witness.len() != output.compiled.program.witness_values()
        {
            return Err(Error::RetainedStorage);
        }
        Ok(Self {
            output,
            scratch,
            retained_program_bytes,
            retained_input_bytes,
            _reservation: reservation,
        })
    }

    fn run(&self) -> Result<(), Error> {
        self.run_witness_prefix(self.output.compiled.witness.len())
    }

    fn run_witness_prefix(&self, len: usize) -> Result<(), Error> {
        let node = &self.output.compiled;
        let trace = MachineAir::from_shared_program(Arc::clone(&node.program))
            .trace(&node.public, &node.witness[..len])
            .map_err(Error::Execution)?;
        assert_eq!(
            trace.values.len() * size_of::<Val>(),
            self.scratch.trace_bytes
        );
        drop(trace);
        Ok(())
    }

    fn changed_public(&mut self, index: usize) -> Result<(), Error> {
        self.output.compiled.public[index] += Val::ONE;
        let result = self.run();
        self.output.compiled.public[index] -= Val::ONE;
        result
    }

    fn changed_witness(&mut self, index: usize) -> Result<(), Error> {
        self.output.compiled.witness[index] += Val::ONE;
        let result = self.run();
        self.output.compiled.witness[index] -= Val::ONE;
        result
    }

    fn reordered_pair(&mut self, first_inputs: usize) -> Result<(), Error> {
        assert_eq!(self.output.compiled.witness.len(), 2 * first_inputs);
        let (left, right) = self.output.compiled.witness.split_at_mut(first_inputs);
        left.swap_with_slice(right);
        let result = self.run();
        let (left, right) = self.output.compiled.witness.split_at_mut(first_inputs);
        left.swap_with_slice(right);
        result
    }
}

mod tests;
