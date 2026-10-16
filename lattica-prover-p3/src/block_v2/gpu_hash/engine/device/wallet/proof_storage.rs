//! Necessary storage for the maintained hiding wallet PCS. These checked
//! lower bounds reject impossible shapes before witness arithmetic; they are
//! not a prediction of all transient workspace peaks or a host-memory budget.
use super::super::PeriodicShape;
use super::super::{Extension, MatrixSpec, RowOrder};
use crate::block_v2::gpu_quotient_prover::program::ProgramShape;
use crate::block_v2::profile;

mod phases;
pub(crate) use phases::Plan as WalletDevicePlan;

/// Immutable geometry contract, derived without evaluating AIR constraints or
/// allocating a trace. Only quadratic/cubic wallet profiles are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WalletProofMinimum {
    largest_allocation: usize,
    simultaneous_bytes: usize,
    rows: usize,
    columns: usize,
    periodic_columns: usize,
    extension: Extension,
    program: Option<ProgramShape>,
    host_allowance: usize,
    periodic: Option<PeriodicShape>,
}

impl WalletProofMinimum {
    pub(crate) fn new(
        rows: usize,
        columns: usize,
        periodic_columns: usize,
        extension: Extension,
    ) -> Result<Self, String> {
        if rows < 2 || !rows.is_power_of_two() || extension == Extension::Base {
            return Err("unsupported wallet proof geometry".into());
        }
        let log_rows = rows.ilog2();
        let log_hidden = log_rows.checked_add(1).ok_or("wallet degree overflow")?;
        let log_lde = log_hidden
            .checked_add(profile::LOG_BLOWUP as u32)
            .filter(|&n| n <= 25)
            .ok_or("wallet proof exceeds device FRI height")?;
        let matrix = |log, width, ext| {
            MatrixSpec::new(log, width, ext, RowOrder::Natural, 1).map(|s| s.bytes())
        };
        let hidden_columns = columns
            .checked_add(profile::NUM_RANDOM_CODEWORDS)
            .ok_or("wallet hidden width overflow")?;
        let auxiliary_columns = extension
            .degree()
            .checked_add(profile::NUM_RANDOM_CODEWORDS)
            .ok_or("wallet auxiliary width overflow")?;
        let trace = matrix(log_rows, columns, Extension::Base)?;
        let main_prefix = matrix(log_hidden, hidden_columns, Extension::Base)?;
        let auxiliary_prefix = matrix(log_hidden, auxiliary_columns, Extension::Base)?;
        let fri = matrix(log_lde, 1, extension)?;
        let tree = super::super::super::retained_layout(
            1usize
                .checked_shl(log_lde)
                .ok_or("wallet LDE height overflow")?,
            0,
            usize::MAX,
        )?
        .elements
        .checked_mul(8)
        .ok_or("wallet tree storage overflow")?;

        // uni::prove retains main, quotient and random ProverData through
        // opening. The hiding quotient has at least two chunks, each with a
        // doubled-trace prefix, plus one prefix for the random commitment.
        // The full extension FRI accumulator coexists with those commitments.
        // More quotient chunks and temporary workspaces can only increase it.
        let opening = sum(&[
            tree,
            tree,
            tree,
            main_prefix,
            auxiliary_prefix,
            auxiliary_prefix,
            auxiliary_prefix,
            fri,
        ])?;
        let mut largest_allocation = [trace, main_prefix, auxiliary_prefix, tree, fri]
            .into_iter()
            .max()
            .unwrap();
        let mut simultaneous_bytes = opening.max(trace);
        if periodic_columns != 0 {
            let periodic = matrix(log_rows, periodic_columns, Extension::Base)?;
            // periodic_prefix borrows the expanded input for lde(). The raw
            // trace, input, output, scratch, both root tables and two scalar
            // parameters are all live before any of them can be released.
            let constants = (2 * log_rows as usize + 2) * 8;
            let transform = sum(&[trace, periodic, periodic, periodic, constants])?;
            largest_allocation = largest_allocation.max(periodic);
            simultaneous_bytes = simultaneous_bytes.max(transform);
        }
        Ok(Self {
            largest_allocation,
            simultaneous_bytes,
            rows,
            columns,
            periodic_columns,
            extension,
            program: None,
            host_allowance: 0,
            periodic: None,
        })
    }

    /// A storage floor without recorded program geometry cannot admit a proof.
    pub(crate) fn with_program(
        mut self,
        program: ProgramShape,
        host_allowance: usize,
    ) -> Result<Self, String> {
        if program.extension != self.extension
            || self
                .columns
                .checked_add(self.periodic_columns)
                .and_then(|n| n.checked_mul(2))
                != Some(program.row_words)
        {
            return Err("wallet program geometry differs from storage shape".into());
        }
        self.program = Some(program);
        self.host_allowance = host_allowance;
        Ok(self)
    }

    pub(crate) fn plan(
        self,
        engine: &crate::block_v2::gpu_hash::engine::Engine,
        live: usize,
    ) -> Result<WalletDevicePlan, String> {
        if self.periodic_columns != 0 && self.periodic.is_none() {
            return Err("wallet phase admission requires retained periodic source geometry".into());
        }
        WalletDevicePlan::new(self, engine, live)
    }

    pub(crate) fn with_periodic(mut self, periodic: Option<PeriodicShape>) -> Result<Self, String> {
        match periodic {
            Some(p)
                if p.output.rows() == self.rows && p.output.columns() == self.periodic_columns => {}
            None if self.periodic_columns == 0 => {}
            _ => return Err("periodic source differs from wallet proof geometry".into()),
        }
        self.periodic = periodic;
        Ok(self)
    }

    pub(crate) fn check(self, managed_bytes: usize, max_allocation: usize) -> Result<(), String> {
        if self.largest_allocation > max_allocation {
            return Err("wallet proof minimum exceeds device per-allocation limit".into());
        }
        if self.simultaneous_bytes > managed_bytes {
            return Err("wallet proof minimum exceeds managed device capacity".into());
        }
        Ok(())
    }
}

fn sum(parts: &[usize]) -> Result<usize, String> {
    parts
        .iter()
        .try_fold(0usize, |total, &bytes| total.checked_add(bytes))
        .ok_or_else(|| "wallet proof storage overflow".into())
}

#[cfg(test)]
mod tests;
