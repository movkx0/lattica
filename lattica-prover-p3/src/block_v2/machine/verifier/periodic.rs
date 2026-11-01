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
    /// Immutable caller-owned public columns may be compared and borrowed.
    /// Generated sources retain the admitted fill path by default.
    fn borrowed(&self, _index: usize) -> Option<&[Val]> {
        None
    }
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
source!(crate::joinsplit_air::JoinSplitAir, joinsplit_air);
source!(crate::htlc_air::HtlcAir, htlc_air);
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
    fn borrowed(&self, index: usize) -> Option<&[Val]> {
        self.0.get(index).map(Vec::as_slice)
    }
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
    values_into_profiled(b, source, zeta, log_height, constants, values, None)
}

pub(crate) fn values_into_profiled(
    b: &mut ScopedProgramBuilder,
    source: &dyn Source,
    zeta: Extension,
    log_height: usize,
    constants: Constants<'_>,
    values: &mut [Extension],
    mut timings: Option<&mut super::uni::shape::NativeLoweringTimings>,
) -> Result<(), CompileError> {
    if log_height > 32 || values.len() != source.count() {
        return Err(CompileError::Shape("periodic source geometry"));
    }
    // Check every column before emitting instructions or invoking fill/backend
    // callbacks. Recheck at allocation rather than trusting mutable metadata.
    for index in 0..values.len() {
        length(source, index, log_height)?;
    }
    if matches!(constants, Constants::Cpu(_)) && !values.is_empty() && source.borrowed(0).is_some()
    {
        use std::hash::BuildHasher;
        let hash = std::collections::hash_map::RandomState::new();
        return b.with_compiler_scratch(
            "periodic-fingerprints",
            values.len(),
            0u64,
            |b, fingerprints| {
                for index in 0..values.len() {
                    let n = length(source, index, log_height)?;
                    let column = source
                        .borrowed(index)
                        .filter(|c| c.len() == n)
                        .ok_or(CompileError::Shape("borrowed periodic geometry"))?;
                    let fingerprint = hash.hash_one(column);
                    fingerprints[index] = fingerprint;
                    // Hashes are a comparison accelerator only. Exact source
                    // equality and one builder/zeta/height scope bind reused wires.
                    let previous = (0..index).find(|&prior| {
                        fingerprints[prior] == fingerprint && source.borrowed(prior) == Some(column)
                    });
                    values[index] = if let Some(prior) = previous {
                        values[prior]
                    } else {
                        expressions::periodic_value_profiled(
                            b,
                            column,
                            zeta,
                            log_height,
                            constants,
                            timings.as_deref_mut(),
                        )?
                    };
                }
                Ok(())
            },
        );
    }
    for (index, out) in values.iter_mut().enumerate() {
        let n = length(source, index, log_height)?;
        *out = b.with_compiler_scratch("periodic-source", n, Val::ZERO, |b, column| {
            source.fill(index, column)?;
            expressions::periodic_value_profiled(
                b,
                column,
                zeta,
                log_height,
                constants,
                timings.as_deref_mut(),
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
