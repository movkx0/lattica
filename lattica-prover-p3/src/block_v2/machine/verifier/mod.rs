//! Compilers for the pinned candidate proof protocols. Proof values are witness
//! inputs; all acceptance equalities are instructions in the execution program.
pub mod batch;
pub mod expressions;
pub mod pcs;
pub mod template;
pub mod uni;

use super::circuit::Extension;
use super::merkle::Digest;
use super::program::Val;
use super::{ProgramBuilder, Wire};
use crate::block_v2::profile::{Challenge, Config};
use p3_field::BasedVectorSpace;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    Shape(&'static str),
    Unsupported(&'static str),
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CompileError {}

#[derive(Default)]
pub struct ProofInputs {
    pub values: Vec<Val>,
}
impl ProofInputs {
    pub fn base(&mut self, b: &mut ProgramBuilder, value: Val) -> Wire {
        self.values.push(value);
        b.input()
    }
    pub fn bases(&mut self, b: &mut ProgramBuilder, values: &[Val]) -> Vec<Wire> {
        values.iter().map(|&v| self.base(b, v)).collect()
    }
    pub fn extension(&mut self, b: &mut ProgramBuilder, value: Challenge) -> Extension {
        let values: &[Val] = value.as_basis_coefficients_slice();
        core::array::from_fn(|i| self.base(b, values[i]))
    }
    pub fn extensions(&mut self, b: &mut ProgramBuilder, values: &[Challenge]) -> Vec<Extension> {
        values.iter().map(|&v| self.extension(b, v)).collect()
    }
    pub fn digest(&mut self, b: &mut ProgramBuilder, value: &[Val; 4]) -> Digest {
        value.map(|v| self.base(b, v))
    }
    pub fn cap(
        &mut self,
        b: &mut ProgramBuilder,
        value: &p3_batch_stark::Commitment<Config>,
        log_height: usize,
    ) -> Result<Vec<Digest>, CompileError> {
        if value.roots().len() != 1 << log_height.min(crate::block_v2::profile::CAP_HEIGHT) {
            return Err(CompileError::Shape("Merkle cap length"));
        }
        Ok(value.roots().iter().map(|d| self.digest(b, d)).collect())
    }
}

pub(crate) fn ext_base(b: &mut ProgramBuilder, value: Wire) -> Extension {
    use p3_field::PrimeCharacteristicRing;
    let zero = b.constant(Val::ZERO);
    [value, zero, zero]
}

pub(crate) fn observe_cap(
    t: &mut super::transcript::Transcript,
    b: &mut ProgramBuilder,
    cap: &[Digest],
) {
    for digest in cap {
        t.observe_slice(b, digest);
    }
}
