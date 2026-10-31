//! Operation-only host diagnostics for immutable finalized programs.
use super::{ExecutionError, Program, Val};

impl Program {
    /// Execute the same host operation checks that precede `MachineAir::trace`,
    /// then destroy the wire values without materializing its row matrix.
    ///
    /// This has the same accepted/rejected inputs as `trace` for a well-formed
    /// immutable program produced by `ProgramBuilder::finish` (and `pad_to`).
    /// Finalization already validates wire topology and generates every row's
    /// operation index/type; trace serialization adds no input predicate for
    /// such a program. This method does not validate arbitrary private program
    /// internals, check AIR constraints independently, or verify a proof.
    ///
    /// This is not allocation admission. Before entry the caller must account
    /// for retained program/input storage, one field value per program wire,
    /// fixed operation scratch and enclosing allocator/process overhead.
    pub fn check_host_constraints(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<(), ExecutionError> {
        self.evaluate(public, witness).map(drop)
    }
}

#[cfg(test)]
mod tests;
