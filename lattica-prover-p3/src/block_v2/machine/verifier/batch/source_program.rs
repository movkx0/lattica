//! Reconstruct a registered single-child verifier program from trusted public
//! source geometry and a trusted preprocessing cap. The caller authenticates
//! both; this constructor grants no proof, registration or acceptance authority.
//!
//! A private invalid proof supplies only the pinned proof layout. Every proof
//! field becomes a fresh unknown input. The invalid proof and its input values
//! are destroyed here, without hint evaluation. Only the verifier program exits.
use super::super::super::{
    backend::retained_proof_capacity_bytes,
    program::{ConstructionLimits, Program, ProgramBuilder, Val, Wire},
    MachineAir,
};
use super::super::{CompileError, ProofInputs};
use super::shape::{PlanningStorage, RegisteredChildShape};
use core::mem::size_of;

/// Fixed public bindings around one through four complete registered verifiers.
/// This returns source only; authenticating every supplied cap is the caller's duty.
pub mod fixed_batch;

const PUBLICS: usize = 4;
const ROOTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Storage {
    planning: PlanningStorage,
    helper_bytes: usize,
    required_bytes: usize,
}

impl Storage {
    /// Allocation-free complete source-construction storage. This is requested
    /// backing, not RSS, enclosing admission, or trust in a supplied cap.
    pub fn new(
        child: RegisteredChildShape,
        construction: ConstructionLimits,
    ) -> Result<Self, CompileError> {
        if child.public_values != PUBLICS || child.preprocessing_cap_roots > ROOTS {
            return Err(CompileError::Shape("single registered source geometry"));
        }
        let planning = PlanningStorage::for_children(PUBLICS, &[child], construction)?;
        let helper_bytes = [
            4 * size_of::<Self>(),
            4 * size_of::<Result<Self, CompileError>>(),
            4 * size_of::<ProgramBuilder>(),
            4 * size_of::<Program>(),
            4 * size_of::<ProofInputs>(),
            4 * size_of::<Result<Program, CompileError>>(),
            4 * size_of::<MachineAir>(),
            4 * size_of::<RegisteredChildShape>(),
            4 * size_of::<ConstructionLimits>(),
            4 * size_of::<[[Wire; 4]; ROOTS]>(),
            4 * size_of::<[Wire; PUBLICS]>(),
            4 * size_of::<[Result<Wire, crate::block_v2::machine::ExecutionError>; PUBLICS]>(),
            // Iterator, reference, error and checked-arithmetic return frames.
            128 * size_of::<usize>(),
        ]
        .into_iter()
        .try_fold(0usize, |a, b| a.checked_add(b))
        .ok_or(CompileError::ResourceAdmission(
            "single source helper overflow",
        ))?;
        let required_bytes = planning
            .total_requested_bytes
            .checked_add(helper_bytes)
            .ok_or(CompileError::ResourceAdmission(
                "single source storage overflow",
            ))?;
        Ok(Self {
            planning,
            helper_bytes,
            required_bytes,
        })
    }

    pub fn required_bytes(self) -> usize {
        self.required_bytes
    }
}

/// Build the same four-public verifier as the genuine-proof compiler, using
/// source-derived layout only. The supplied cap is embedded as constants; its
/// authentication is a mandatory enclosing responsibility. No synthetic hints
/// are evaluated, and neither a template proof nor its input values escape.
pub fn reconstruct_single_child(
    child: RegisteredChildShape,
    trusted_cap: &[[Val; 4]],
    construction: ConstructionLimits,
    admitted_host_bytes: usize,
) -> Result<Program, CompileError> {
    let storage = Storage::new(child, construction)?;
    if storage.required_bytes > admitted_host_bytes
        || trusted_cap.len() != child.preprocessing_cap_roots
    {
        return Err(CompileError::ResourceAdmission("single source admission"));
    }
    let mut builder = ProgramBuilder::new_with_construction_limits(PUBLICS, construction)
        .map_err(|e| CompileError::from_builder_admission(e, "single source builder"))?;
    let public_results = [
        builder.public(0),
        builder.public(1),
        builder.public(2),
        builder.public(3),
    ];
    let mut public = [Wire(0); PUBLICS];
    for (destination, result) in public.iter_mut().zip(public_results) {
        *destination =
            result.map_err(|e| CompileError::from_builder_admission(e, "single source public"))?;
    }
    let mut cap = [[Wire(0); 4]; ROOTS];
    for (destination, digest) in cap.iter_mut().zip(trusted_cap) {
        *destination = digest.map(|word| builder.constant(word));
    }
    if let Some(error) = builder.resource_failure() {
        return Err(CompileError::from_builder_admission(
            error,
            "single source cap",
        ));
    }
    let empty = ProgramBuilder::new(PUBLICS)
        .and_then(|b| b.finish(Some(child.height)))
        .map_err(|_| CompileError::Shape("single source child AIR"))?;
    let air = MachineAir::new(empty);
    let template = super::super::template::batch_bounded_shape(&air)?;
    retained_proof_capacity_bytes(&template, storage.planning.template_retained_bytes)
        .map_err(|_| CompileError::Shape("single source template drift"))?;
    let mut inputs = ProofInputs::default();
    super::verify_bounded_shape(
        &mut builder,
        &mut inputs,
        &air,
        &public,
        &cap[..child.preprocessing_cap_roots],
        &template,
    )?;
    drop(template);
    drop(air);
    let program = builder
        .finish(None)
        .map_err(|e| CompileError::from_builder_admission(e, "single source finalization"))?;
    if program.witness_values() != inputs.values.len() {
        return Err(CompileError::Shape("single source input geometry"));
    }
    drop(inputs);
    Ok(program)
}

#[cfg(test)]
mod tests;
