//! One public source column at a time, owned by the construction allowance.
use super::{expressions, CompileError};
use crate::block_v2::{
    leaf::ContextJoinSplitAir,
    machine::{
        circuit::Extension,
        compiler_constants::Constants,
        program::{ScopedProgramBuilder, Val},
        MachineAir,
    },
    typed_leaf::ContextAir,
};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;

/// Internal implementations report geometry without allocating and fill only
/// borrowed output. No owned AIR table or intermediate index vectors are built.
pub(crate) trait Source {
    fn count(&self) -> usize;
    fn len(&self, index: usize) -> Option<usize>;
    fn fill(&self, index: usize, output: &mut [Val]) -> Result<(), CompileError>;
}

macro_rules! source {
    ($air:ty, $module:ident) => {
        impl Source for $air {
            fn count(&self) -> usize {
                crate::$module::N_PERIODIC
            }
            fn len(&self, index: usize) -> Option<usize> {
                crate::$module::periodic_source::len(index)
            }
            fn fill(&self, index: usize, output: &mut [Val]) -> Result<(), CompileError> {
                if crate::$module::periodic_source::fill(index, output) {
                    Ok(())
                } else {
                    Err(CompileError::Shape("periodic source geometry"))
                }
            }
        }
    };
}
source!(ContextJoinSplitAir, joinsplit_air);
source!(
    ContextAir<crate::joinsplit_air::JoinSplitAir>,
    joinsplit_air
);
source!(ContextAir<crate::htlc_air::HtlcAir>, htlc_air);

impl Source for MachineAir {
    fn count(&self) -> usize {
        self.num_periodic_columns()
    }
    fn len(&self, _: usize) -> Option<usize> {
        None
    }
    fn fill(&self, _: usize, _: &mut [Val]) -> Result<(), CompileError> {
        Err(CompileError::Unsupported("machine periodic columns"))
    }
}

/// Compatibility adapter for callers that already own a CPU AIR table. Its
/// original table is caller-owned storage, outside this compiler allowance.
pub(super) struct Borrowed<'a>(pub &'a [Vec<Val>]);
impl Source for Borrowed<'_> {
    fn count(&self) -> usize {
        self.0.len()
    }
    fn len(&self, index: usize) -> Option<usize> {
        self.0.get(index).map(Vec::len)
    }
    fn fill(&self, index: usize, output: &mut [Val]) -> Result<(), CompileError> {
        let column = self
            .0
            .get(index)
            .filter(|c| c.len() == output.len())
            .ok_or(CompileError::Shape("periodic source geometry"))?;
        output.copy_from_slice(column);
        Ok(())
    }
}

fn length(source: &dyn Source, index: usize, log_height: usize) -> Result<usize, CompileError> {
    source
        .len(index)
        .filter(|n| n.is_power_of_two() && (*n as u64) <= 1u64 << log_height)
        .ok_or(CompileError::Shape("periodic source height"))
}

pub(crate) fn values_into(
    b: &mut ScopedProgramBuilder,
    source: &dyn Source,
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
    values: &mut [Extension],
) -> Result<(), CompileError> {
    if log_height > 32 || values.len() != source.count() {
        return Err(CompileError::Shape("periodic source geometry"));
    }
    // Check every column before emitting instructions or invoking fill/backend
    // callbacks. Recheck at allocation rather than trusting mutable metadata.
    for index in 0..values.len() {
        length(source, index, log_height)?;
    }
    for (index, out) in values.iter_mut().enumerate() {
        let n = length(source, index, log_height)?;
        *out = b.with_compiler_scratch("periodic-source", n, Val::ZERO, |b, column| {
            source.fill(index, column)?;
            expressions::periodic_value(b, column, zeta, log_height, constants)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
