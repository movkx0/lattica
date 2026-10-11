//! Input values have a separate staging reservation from program construction.
//! Keep each value backing array within the builder's input-value bound and
//! admit an entire returned wire array before allocation or input callbacks.
use super::{ScopedProgramBuilder as ProgramBuilder, Val, Wire};
use crate::block_v2::machine::{circuit::Extension, merkle::Digest, verifier::CompileError};
use crate::block_v2::profile::{Challenge, Config};
use p3_field::BasedVectorSpace;

#[derive(Default)]
pub struct ProofInputs {
    pub values: Vec<Val>,
}

fn reject(b: &mut ProgramBuilder<'_>) -> CompileError {
    b.memory.reject();
    b.memory.report("rejected");
    CompileError::Shape("proof input storage allowance")
}

impl ProofInputs {
    pub(in super::super) fn report(&self, b: &ProgramBuilder<'_>) {
        if b.memory.limit.is_some() {
            eprintln!("bounded_proof_inputs values={} capacity_values={} capacity_bytes={} input_limit={} rejected={}",
                self.values.len(), self.values.capacity(), self.values.capacity() * std::mem::size_of::<Val>(),
                b.memory.input_limit, b.memory.failed);
        }
    }

    fn admit(&self, b: &mut ProgramBuilder<'_>, fields: usize) -> Result<(), CompileError> {
        if b.memory.failed
            || self.values.capacity() > b.memory.input_limit
            || b.witnesses
                .checked_add(fields)
                .is_none_or(|n| n > b.memory.input_limit)
            || b.wires
                .checked_add(fields)
                .is_none_or(|n| n > b.memory.wire_limit)
            || self
                .values
                .len()
                .checked_add(fields)
                .is_none_or(|n| n > b.memory.input_limit)
        {
            return Err(reject(b));
        }
        Ok(())
    }

    fn reserve_value(&mut self, b: &mut ProgramBuilder<'_>) -> Result<(), CompileError> {
        if self.values.len() < self.values.capacity() {
            return Ok(());
        }
        let old = self.values.capacity();
        let capacity = old
            .checked_mul(2)
            .ok_or_else(|| reject(b))?
            .max(4)
            .min(b.memory.input_limit);
        if capacity <= old {
            return Err(reject(b));
        }
        let mut next = Vec::new();
        next.try_reserve_exact(capacity).map_err(|_| reject(b))?;
        if next.capacity() != capacity {
            return Err(reject(b));
        }
        // Both arrays remain live while moving values. Each is <= input_limit,
        // so their combined requested storage is <= twice that input bound.
        if b.memory.limit.is_some() {
            eprintln!("bounded_proof_input_growth old_values={old} new_values={capacity} live_bytes={} value_limit={}",
                (old + capacity) * std::mem::size_of::<Val>(), b.memory.input_limit);
        }
        next.append(&mut self.values);
        self.values = next;
        Ok(())
    }

    pub fn base(&mut self, b: &mut ProgramBuilder<'_>, value: Val) -> Wire {
        if self.admit(b, 1).is_err() {
            return Wire(0);
        }
        let wire = b.input();
        if b.resource_failure().is_none() && self.reserve_value(b).is_ok() {
            self.values.push(value);
        }
        wire
    }

    fn collect<T>(
        &mut self,
        b: &mut ProgramBuilder<'_>,
        count: usize,
        fields_per_value: usize,
        mut value: impl FnMut(&mut Self, &mut ProgramBuilder<'_>, usize) -> T,
    ) -> Result<Vec<T>, CompileError> {
        let fields = count
            .checked_mul(fields_per_value)
            .ok_or_else(|| reject(b))?;
        self.admit(b, fields)?;
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|_| reject(b))?;
        if result.capacity() != count {
            return Err(reject(b));
        }
        for i in 0..count {
            let next = value(self, b, i);
            if b.resource_failure().is_some() {
                return Err(reject(b));
            }
            result.push(next);
        }
        Ok(result)
    }

    pub fn bases(
        &mut self,
        b: &mut ProgramBuilder<'_>,
        values: &[Val],
    ) -> Result<Vec<Wire>, CompileError> {
        self.collect(b, values.len(), 1, |inputs, b, i| inputs.base(b, values[i]))
    }

    pub fn extension(&mut self, b: &mut ProgramBuilder<'_>, value: Challenge) -> Extension {
        let values: &[Val] = value.as_basis_coefficients_slice();
        core::array::from_fn(|i| self.base(b, values[i]))
    }

    pub fn extensions(
        &mut self,
        b: &mut ProgramBuilder<'_>,
        values: &[Challenge],
    ) -> Result<Vec<Extension>, CompileError> {
        self.collect(b, values.len(), 3, |inputs, b, i| {
            inputs.extension(b, values[i])
        })
    }

    pub fn digest(&mut self, b: &mut ProgramBuilder<'_>, value: &[Val; 4]) -> Digest {
        value.map(|v| self.base(b, v))
    }

    pub fn cap(
        &mut self,
        b: &mut ProgramBuilder<'_>,
        value: &p3_batch_stark::Commitment<Config>,
        log_height: usize,
    ) -> Result<Vec<Digest>, CompileError> {
        if value.roots().len() != 1 << log_height.min(crate::block_v2::profile::CAP_HEIGHT) {
            return Err(CompileError::Shape("Merkle cap length"));
        }
        self.collect(b, value.roots().len(), 4, |inputs, b, i| {
            inputs.digest(b, &value.roots()[i])
        })
    }
}

#[cfg(test)]
mod tests;
