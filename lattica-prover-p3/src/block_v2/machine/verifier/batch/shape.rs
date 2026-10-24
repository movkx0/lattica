//! Bounds-only planning of registered-machine verifier cores.
//!
//! The templates and opaque-cap programs built here are invalid proof fixtures.
//! They never leave this module. This API conveys no key, proof, registration,
//! admission token or acceptance authority. See `shape/OPAQUE_CAPS.md` for the
//! restricted specialization argument; this is not a general optimizer theorem.
use super::super::super::{
    backend::retained_proof_capacity_bytes,
    program::{
        ConstructionLimits, Op, Program, ProgramBuilder, EXT_LANES, LANES, MAX_PUBLIC_VALUES,
        MAX_WIRES, PUBLICS_PER_ROW,
    },
    MachineAir,
};
use super::super::{CompileError, ProofInputs};
use crate::block_v2::profile;
use p3_field::PrimeCharacteristicRing;

mod storage;
pub use storage::PlanningStorage;

pub const MAX_CHILDREN: usize = 4;

/// Trusted public geometry, never values taken from an unverified proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredChildShape {
    pub public_values: usize,
    pub height: usize,
    pub preprocessing_cap_roots: usize,
}

impl RegisteredChildShape {
    fn validate(self) -> Result<(), CompileError> {
        if self.public_values > MAX_PUBLIC_VALUES
            || !(8..=1 << 24).contains(&self.height)
            || !self.height.is_power_of_two()
        {
            return Err(CompileError::Shape("registered shape geometry"));
        }
        let log_lde = self.height.ilog2() as usize + 1 + profile::LOG_BLOWUP;
        if self.preprocessing_cap_roots != 1usize << log_lde.min(profile::CAP_HEIGHT) {
            return Err(CompileError::Shape("registered shape cap geometry"));
        }
        Ok(())
    }
}

/// Primitive classes are kept separate because they pack into different rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationCounts {
    pub scalar: usize,
    pub cubic: usize,
    pub poseidon: usize,
}

impl OperationCounts {
    fn from_program(program: &Program) -> Self {
        let mut counts = Self::default();
        for op in &program.operations {
            match op {
                Op::Poseidon { .. } => counts.poseidon += 1,
                Op::CubicMul { .. } | Op::CubicInverse { .. } => counts.cubic += 1,
                _ => counts.scalar += 1,
            }
        }
        counts
    }

    /// Add separately source-derived binding operations, then pack once.
    /// Supplying arbitrary overhead does not establish full workflow closure.
    pub fn with_overhead(self, overhead: Self) -> Result<Self, CompileError> {
        Ok(Self {
            scalar: storage::add(self.scalar, overhead.scalar)?,
            cubic: storage::add(self.cubic, overhead.cubic)?,
            poseidon: storage::add(self.poseidon, overhead.poseidon)?,
        })
    }

    pub fn active_rows(self, public_values: usize) -> Result<usize, CompileError> {
        if public_values > MAX_PUBLIC_VALUES {
            return Err(CompileError::Shape("registered shape outer public width"));
        }
        // Divide without n + denominator - 1, which can overflow.
        let ceil = |n: usize, d: usize| n / d + usize::from(n % d != 0);
        [
            ceil(public_values, PUBLICS_PER_ROW),
            self.poseidon,
            ceil(self.scalar, LANES),
            ceil(self.cubic, EXT_LANES),
        ]
        .into_iter()
        .try_fold(0, storage::add)
    }

    pub fn padded_rows(self, public_values: usize) -> Result<usize, CompileError> {
        self.active_rows(public_values)?
            .max(8)
            .checked_next_power_of_two()
            .filter(|&height| height <= 1 << 24)
            .ok_or(CompileError::Shape("registered shape output height"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierCoreBound {
    pub operations: OperationCounts,
    pub wire_upper_bound: usize,
    /// Includes the deliberately opaque cap inputs, hence also bounds the
    /// actual compiler's witness count when trusted caps become constants.
    pub input_values_upper_bound: usize,
    pub active_rows_upper_bound: usize,
    pub padded_rows_upper_bound: usize,
    /// The planner's observed requested peak, NOT a specialized compiler bound.
    pub planner_requested_program_bytes_peak: usize,
    pub storage: PlanningStorage,
}

/// Compile only core verifiers with independent fresh public/proof inputs.
/// Every cap word is a distinct unknown input, including equal actual words.
/// Actual caps may identify/hash fewer leaves but cannot increase these class
/// counts under the pinned paths. No endpoint, context, merge binding, graph
/// manifest, final aggregation, proving or independent-verifier scratch is
/// included. Callers must account for and close those phases separately.
pub fn verifier_core_bound(
    outer_public_values: usize,
    children: &[RegisteredChildShape],
    construction: ConstructionLimits,
    auxiliary_host_allowance: usize,
) -> Result<VerifierCoreBound, CompileError> {
    let storage = PlanningStorage::for_children(outer_public_values, children, construction)?;
    if storage.auxiliary_peak_bytes > auxiliary_host_allowance {
        return Err(CompileError::ResourceAdmission(
            "registered shape auxiliary allowance",
        ));
    }
    // No template, symbolic graph, builder or input storage exists before the
    // preceding allocation-free shape/storage/overflow/allowance checks.
    let mut builder =
        ProgramBuilder::new_with_construction_limits(outer_public_values, construction).map_err(
            |e| CompileError::from_builder_admission(e, "registered shape builder allowance"),
        )?;
    let mut inputs = ProofInputs::default();
    for &child in children {
        let air = empty_air(child)?;
        let template = super::super::template::batch_bounded_shape(&air)?;
        // Conformance audit only. The source-derived bound was reserved before
        // allocation; an observation cannot authorize a previously owned proof.
        retained_proof_capacity_bytes(&template, storage.template_retained_bytes)
            .map_err(|_| CompileError::Shape("registered shape template capacity drift"))?;
        let values = [super::Val::ZERO; MAX_PUBLIC_VALUES];
        let public = inputs.bases(&mut builder, &values[..child.public_values])?;
        let mut cap = [[super::Wire(0); 4]; 64];
        for digest in &mut cap[..child.preprocessing_cap_roots] {
            *digest = core::array::from_fn(|_| inputs.base(&mut builder, super::Val::ZERO));
        }
        if let Some(error) = builder.resource_failure() {
            return Err(CompileError::from_builder_admission(
                error,
                "registered shape cap inputs",
            ));
        }
        super::verify_bounded_shape(
            &mut builder,
            &mut inputs,
            &air,
            &public,
            &cap[..child.preprocessing_cap_roots],
            &template,
        )?;
        // Each template/shape drops here; cumulative proof inputs and emitted
        // instructions remain inside their separately enforced quotas.
    }
    let program = builder.finish(None).map_err(|e| {
        CompileError::from_builder_admission(e, "registered shape packing allowance")
    })?;
    let operations = OperationCounts::from_program(&program);
    let result = VerifierCoreBound {
        operations,
        wire_upper_bound: program.wire_count(),
        input_values_upper_bound: program.witness_values(),
        active_rows_upper_bound: operations.active_rows(outer_public_values)?,
        padded_rows_upper_bound: operations.padded_rows(outer_public_values)?,
        planner_requested_program_bytes_peak: program.construction_host_bytes(),
        storage,
    };
    debug_assert_eq!(result.active_rows_upper_bound, program.active_rows());
    debug_assert_eq!(result.input_values_upper_bound, inputs.values.len());
    // No callback or caller access to either invalid object is provided.
    drop(program);
    drop(inputs);
    Ok(result)
}

fn empty_air(child: RegisteredChildShape) -> Result<MachineAir, CompileError> {
    let program = ProgramBuilder::new(child.public_values)
        .and_then(|b| b.finish(Some(child.height)))
        .map_err(|_| CompileError::Shape("registered shape empty program"))?;
    Ok(MachineAir::new(program))
}

#[cfg(test)]
mod tests;
