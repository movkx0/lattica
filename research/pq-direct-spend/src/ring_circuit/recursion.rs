//! Research-only recursive constraint qualification for one genuine direct-ring
//! proof. This is not an outer proof, transaction aggregate or acceptance API.
//!
//! The expected public statement is reconstructed and freshly registered by the
//! independent verifier. Its actual program supplies preflight geometry; its
//! actual preprocessing cap and independently verified child remain private
//! owners. No caller-written geometry, verification report or transport key can
//! construct the recursive compiler input. All phases use the existing worker
//! allowance, with original child storage and fixed caller state included.
use super::{
    artifact::{Artifact, MAX_RETAINED_PROOF_BYTES},
    proving::TerminalReceipt,
    verification::{self, VerificationFailure, VerificationReport, VerifiedRecursiveChild},
    CompiledRelation, CompilerCapacityProfile, CompilerRepresentation, Context, Error, Program,
    Statement, Val,
};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ConstructionLimits, ProgramBuilder, ProofInputs, Wire},
        verifier::{
            batch::{
                self,
                shape::{
                    self, OperationCounts, PlanningStorage, RegisteredChildShape, VerifierCoreBound,
                },
            },
            CompileError,
        },
        MachineAir, REGISTERED_GPU_CALLER_HOST_BYTES,
    },
    profile,
};
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;
use std::{
    mem::size_of,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

#[cfg(feature = "ring-recursive-outer-experiment")]
pub mod outer;

const HOST_BYTES: usize = 32 << 30;
const PROGRAM_BYTES: usize = 2 << 30;
const MAX_ROWS: usize = 1 << 20;
const MAX_WIRES: usize = 1 << 26;
const MAX_INPUTS: usize = 1 << 20;
const PUBLICS: usize = 4;
const CAP_ROOTS: usize = 1 << profile::CAP_HEIGHT;

fn construction() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: PROGRAM_BYTES,
        max_wires: MAX_WIRES,
        max_input_values: MAX_INPUTS,
    }
}

fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0usize, |sum, &part| {
        sum.checked_add(part).ok_or(Error::ResourceLimit)
    })
}

fn fields(values: usize) -> Result<usize, Error> {
    values
        .checked_mul(size_of::<Val>())
        .ok_or(Error::ResourceLimit)
}

fn admit(required: usize) -> Result<(), Error> {
    if required > HOST_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

/// Requested backing/storage bounds. These are not measured RSS or GPU peaks.
/// Every phase includes the original child proof and the existing caller
/// reservation; source compilation additionally retains the reconstructed child.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct MemoryBounds {
    pub worker_host_bytes: usize,
    pub retained_child_allowance_bytes: usize,
    pub fixed_caller_allowance_bytes: usize,
    pub reconstructed_program_bytes: usize,
    pub reconstructed_witness_bytes: usize,
    pub program_allowance_bytes: usize,
    pub auxiliary_allowance_bytes: usize,
    pub source_planning_bytes: usize,
    pub recursive_compilation_bytes: usize,
    pub recursive_evaluation_bytes: usize,
}

fn memory_bounds(
    source_program_bytes: usize,
    source_witness_bytes: usize,
    storage: PlanningStorage,
) -> Result<MemoryBounds, Error> {
    // The bounded compiler follows the same registry/PCS/ProofInputs paths as
    // the source planner. Its genuine child is separately retained below. We
    // conservatively retain the planner's entire template-construction charge
    // even though the actual compiler allocates no invalid proof template.
    let recursive_compilation_bytes = sum(&[
        storage.total_requested_bytes,
        MAX_RETAINED_PROOF_BYTES,
        REGISTERED_GPU_CALLER_HOST_BYTES,
    ])?;
    let source_planning_bytes = sum(&[
        recursive_compilation_bytes,
        source_program_bytes,
        source_witness_bytes,
    ])?;
    // Finalized program, full bounded input backing (including growth overlap),
    // one value per possible wire, original proof and caller frames. No trace
    // matrix is materialized. The same reservation covers each sequential
    // public-binding mutation check; the previous values are already destroyed.
    let recursive_evaluation_bytes = sum(&[
        PROGRAM_BYTES,
        fields(MAX_INPUTS)?
            .checked_mul(2)
            .ok_or(Error::ResourceLimit)?,
        fields(MAX_WIRES)?,
        MAX_RETAINED_PROOF_BYTES,
        REGISTERED_GPU_CALLER_HOST_BYTES,
    ])?;
    for required in [
        source_planning_bytes,
        recursive_compilation_bytes,
        recursive_evaluation_bytes,
    ] {
        admit(required)?;
    }
    Ok(MemoryBounds {
        worker_host_bytes: HOST_BYTES,
        retained_child_allowance_bytes: MAX_RETAINED_PROOF_BYTES,
        fixed_caller_allowance_bytes: REGISTERED_GPU_CALLER_HOST_BYTES,
        reconstructed_program_bytes: source_program_bytes,
        reconstructed_witness_bytes: source_witness_bytes,
        program_allowance_bytes: PROGRAM_BYTES,
        auxiliary_allowance_bytes: storage.auxiliary_peak_bytes,
        source_planning_bytes,
        recursive_compilation_bytes,
        recursive_evaluation_bytes,
    })
}

/// Private source result, never accepted from a caller. The shape is taken
/// directly from expected-public reconstruction before registration. It grants
/// no proof or verifier authority; only VerifiedRecursiveChild may carry it to
/// the compiler after independent numerical verification.
pub(super) struct SourceBound {
    child: RegisteredChildShape,
    core: RetainedCoreBound,
    memory: MemoryBounds,
    elapsed_ns: u128,
}

// Only conformance geometry survives preflight. The full planner result and
// its storage identity are checked first; its diagnostic peak, hint backing
// count and duplicate PlanningStorage are never needed by the later compiler.
// This private subset grants no key, proof, admission or verifier authority.
struct RetainedCoreBound {
    operations: OperationCounts,
    wire_upper_bound: usize,
    input_values_upper_bound: usize,
    active_rows_upper_bound: usize,
    padded_rows_upper_bound: usize,
}

impl RetainedCoreBound {
    fn checked(core: &VerifierCoreBound, storage: &PlanningStorage) -> Result<Self, Error> {
        if core.storage != *storage
            || core.padded_rows_upper_bound > MAX_ROWS
            || core.wire_upper_bound > MAX_WIRES
            || core.input_values_upper_bound > MAX_INPUTS
        {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            operations: core.operations,
            wire_upper_bound: core.wire_upper_bound,
            input_values_upper_bound: core.input_values_upper_bound,
            active_rows_upper_bound: core.active_rows_upper_bound,
            padded_rows_upper_bound: core.padded_rows_upper_bound,
        })
    }
}

fn source_shape(relation: &CompiledRelation) -> Result<RegisteredChildShape, Error> {
    let program = &relation.program;
    if program.public_values() != PUBLICS
        || !(8..=MAX_ROWS).contains(&program.height())
        || !program.height().is_power_of_two()
        || relation.summary.deferred_crypto_obligations != 0
        || relation.summary.active_rows != program.active_rows()
        || relation.summary.padded_rows != program.height()
        || relation.summary.wires != program.wire_count()
        || relation.summary.witness_values != program.witness_values()
        || relation.witness.len() != program.witness_values()
    {
        return Err(Error::Geometry);
    }
    let roots =
        1 << (program.height().ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    if roots != CAP_ROOTS {
        return Err(Error::Geometry);
    }
    Ok(RegisteredChildShape {
        public_values: PUBLICS,
        height: program.height(),
        preprocessing_cap_roots: roots,
    })
}

pub(super) fn preflight(relation: &CompiledRelation) -> Result<SourceBound, Error> {
    let started = Instant::now();
    let child = source_shape(relation)?;
    let storage = PlanningStorage::for_children(PUBLICS, &[child], construction())
        .map_err(|_| Error::ResourceLimit)?;
    let memory = memory_bounds(
        relation
            .program
            .retained_host_bytes()
            .map_err(|_| Error::ResourceLimit)?,
        fields(relation.witness.capacity())?,
        storage,
    )?;
    // The complete overlapping source/program/proof/caller envelope has been
    // admitted before the first symbolic graph, template or builder allocation.
    let planned = catch_unwind(AssertUnwindSafe(|| {
        shape::verifier_core_bound(
            PUBLICS,
            &[child],
            construction(),
            storage.auxiliary_peak_bytes,
        )
    }));
    let core = match planned {
        Ok(result) => result.map_err(|_| Error::ResourceLimit)?,
        Err(payload) => {
            drop(payload);
            return Err(Error::ResourceLimit);
        }
    };
    let retained_core = RetainedCoreBound::checked(&core, &storage)?;
    Ok(SourceBound {
        child,
        core: retained_core,
        memory,
        elapsed_ns: started.elapsed().as_nanos(),
    })
}

#[derive(Debug, Serialize)]
pub struct Failure {
    pub schema: &'static str,
    pub phase: &'static str,
    pub reason: &'static str,
    pub recursive_proof_generated: bool,
    pub child_verification: Option<VerificationFailure>,
    /// Preserved when compilation/evaluation fails after verifier retirement.
    pub child_verification_terminal: Option<TerminalReceipt>,
}

impl Failure {
    fn new(phase: &'static str, reason: &'static str) -> Self {
        Self {
            schema: "lattica-research-direct-ring-recursive-constraint-failure-v1",
            phase,
            reason,
            recursive_proof_generated: false,
            child_verification: None,
            child_verification_terminal: None,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.phase, self.reason)
    }
}

impl std::error::Error for Failure {}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct CompilerReport {
    pub public_values: usize,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub wires: usize,
    pub witness_values: usize,
    pub retained_program_bytes: usize,
    pub retained_input_bytes: usize,
    pub source_active_rows_upper_bound: usize,
    pub source_padded_rows_upper_bound: usize,
    pub source_wires_upper_bound: usize,
    pub source_input_values_upper_bound: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub scope: &'static str,
    pub independently_verified_children: u32,
    pub recursive_proofs_generated: u32,
    pub complete_transaction_aggregate: bool,
    pub final_aggregate: bool,
    pub all_recursive_constraints_satisfied: bool,
    pub public_binding_mutation_rejections: u32,
    pub compiler: CompilerReport,
    pub memory: MemoryBounds,
    /// Also included in child_verification.total_verification_lifecycle_ns.
    pub source_preflight_ns: u128,
    pub recursive_compilation_ns: u128,
    pub recursive_constraint_evaluation_ns: u128,
    pub public_binding_mutation_checks_ns: u128,
    pub total_qualification_ns: u128,
    pub child_verification: Box<VerificationReport>,
}

struct CompiledChild {
    program: Program,
    inputs: ProofInputs,
    child: VerifiedRecursiveChild,
    public: [Val; PUBLICS],
    report: CompilerReport,
}

/// Exact fixed orchestration/result census, called before independent verifier
/// reconstruction. These owners are inside its existing 1 MiB caller allowance.
pub(super) fn inline_bytes() -> Result<usize, Error> {
    #[cfg(feature = "ring-recursive-outer-experiment")]
    let outer_bytes = outer::inline_bytes()?;
    #[cfg(not(feature = "ring-recursive-outer-experiment"))]
    let outer_bytes = 0;
    sum(&[
        outer_bytes,
        4 * size_of::<ProgramBuilder>(),
        4 * size_of::<Program>(),
        4 * size_of::<ProofInputs>(),
        4 * size_of::<MachineAir>(),
        4 * size_of::<CompiledChild>(),
        4 * size_of::<Result<CompiledChild, Failure>>(),
        4 * size_of::<Report>(),
        4 * size_of::<Result<Report, Failure>>(),
        4 * size_of::<Failure>(),
        4 * size_of::<CompileError>(),
        4 * size_of::<Result<(Program, ProofInputs), Failure>>(),
        4 * size_of::<std::thread::Result<Result<(Program, ProofInputs), Failure>>>(),
        4 * size_of::<Result<VerifierCoreBound, CompileError>>(),
        4 * size_of::<std::thread::Result<Result<VerifierCoreBound, CompileError>>>(),
        // The full planner value/result/catch slots still exist before the
        // checked subset is retained. Add all conversion/value/result/borrow
        // frames; do not credit moves or shrink the original planner terms.
        4 * size_of::<VerifierCoreBound>(),
        4 * size_of::<RetainedCoreBound>(),
        4 * size_of::<Result<RetainedCoreBound, Error>>(),
        4 * size_of::<&VerifierCoreBound>(),
        4 * size_of::<&PlanningStorage>(),
        4 * size_of::<[[Wire; 4]; CAP_ROOTS]>(),
        8 * size_of::<[Val; PUBLICS]>(),
        8 * size_of::<Instant>(),
        // catch_unwind payload/result headers, operation scratch, scalar maps,
        // array temporaries, source/storage helpers and formatting metadata.
        8 << 10,
    ])
}

fn compile(child: VerifiedRecursiveChild) -> Result<CompiledChild, Failure> {
    let bound = child.bound();
    admit(bound.memory.recursive_compilation_bytes)
        .map_err(|_| Failure::new("recursive_compilation", "host admission"))?;
    if child.cap().len() != bound.child.preprocessing_cap_roots {
        return Err(Failure::new(
            "recursive_compilation",
            "trusted cap geometry",
        ));
    }
    let public = child.public();
    let attempted = catch_unwind(AssertUnwindSafe(|| {
        let mut builder = ProgramBuilder::new_with_construction_limits(PUBLICS, construction())
            .map_err(|_| Failure::new("recursive_compilation", "program admission"))?;
        let public_wires = [
            builder.public(0),
            builder.public(1),
            builder.public(2),
            builder.public(3),
        ];
        let placeholder = builder
            .public(0)
            .map_err(|_| Failure::new("recursive_compilation", "public placeholder"))?;
        let mut public = [placeholder; PUBLICS];
        for (target, wire) in public.iter_mut().zip(public_wires) {
            *target = wire.map_err(|_| Failure::new("recursive_compilation", "public wire"))?;
        }
        let mut cap = [[placeholder; 4]; CAP_ROOTS];
        for (target, digest) in cap.iter_mut().zip(child.cap()) {
            *target = digest.map(|word| builder.constant(word));
        }
        if builder.public(0).is_err() {
            return Err(Failure::new(
                "recursive_compilation",
                "cap constant admission",
            ));
        }
        // Registered machine constraints depend on the exact registered height
        // and public width; the trusted preprocessing cap binds the full child
        // program. This empty AIR supplies that exact verifier geometry only.
        let empty = ProgramBuilder::new(PUBLICS)
            .and_then(|builder| builder.finish(Some(bound.child.height)))
            .map_err(|_| Failure::new("recursive_compilation", "child AIR geometry"))?;
        let air = MachineAir::new(empty);
        let mut inputs = ProofInputs::default();
        batch::verify_with_bounded_cpu_symbolic(
            &mut builder,
            &mut inputs,
            &air,
            &public,
            &cap,
            child.proof(),
        )
        .map_err(|_| Failure::new("recursive_compilation", "bounded child verifier"))?;
        drop(air);
        let program = builder
            .finish(None)
            .map_err(|_| Failure::new("recursive_compilation", "program finalization"))?;
        Ok((program, inputs))
    }));
    let (program, inputs) = match attempted {
        Ok(result) => result?,
        Err(payload) => {
            drop(payload);
            return Err(Failure::new("recursive_compilation", "compiler panicked"));
        }
    };
    let counts = OperationCounts::from_program(&program);
    let retained_program_bytes = program
        .retained_host_bytes()
        .map_err(|_| Failure::new("recursive_compilation", "program capacity"))?;
    let retained_input_bytes = fields(inputs.values.capacity())
        .map_err(|_| Failure::new("recursive_compilation", "input capacity"))?;
    if counts.scalar > bound.core.operations.scalar
        || counts.cubic > bound.core.operations.cubic
        || counts.poseidon > bound.core.operations.poseidon
        || program.public_values() != PUBLICS
        || program.witness_values() != inputs.values.len()
        || inputs.values.capacity() > MAX_INPUTS
        || program.wire_count() > bound.core.wire_upper_bound
        || program.witness_values() > bound.core.input_values_upper_bound
        || program.active_rows() > bound.core.active_rows_upper_bound
        || program.height() > bound.core.padded_rows_upper_bound
        || program.height() > MAX_ROWS
        || retained_program_bytes > PROGRAM_BYTES
    {
        return Err(Failure::new(
            "recursive_compilation",
            "source bound conformance",
        ));
    }
    let report = CompilerReport {
        public_values: program.public_values(),
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        witness_values: program.witness_values(),
        retained_program_bytes,
        retained_input_bytes,
        source_active_rows_upper_bound: bound.core.active_rows_upper_bound,
        source_padded_rows_upper_bound: bound.core.padded_rows_upper_bound,
        source_wires_upper_bound: bound.core.wire_upper_bound,
        source_input_values_upper_bound: bound.core.input_values_upper_bound,
    };
    Ok(CompiledChild {
        program,
        inputs,
        child,
        public,
        report,
    })
}

impl CompiledChild {
    fn check(&self, public: &[Val; PUBLICS]) -> Result<bool, Failure> {
        admit(self.child.bound().memory.recursive_evaluation_bytes)
            .map_err(|_| Failure::new("recursive_evaluation", "host admission"))?;
        match catch_unwind(AssertUnwindSafe(|| {
            self.program
                .check_host_constraints(public, &self.inputs.values)
        })) {
            Ok(result) => Ok(result.is_ok()),
            Err(payload) => {
                drop(payload);
                Err(Failure::new("recursive_evaluation", "evaluation panicked"))
            }
        }
    }
}

/// Consume one genuine full direct-ring artifact, reconstruct/verify it using
/// independently supplied expected inputs, then compile and execute its full
/// recursive verifier. Every public binding word is separately mutated and must
/// fail the emitted constraints. No outer cryptographic proof is generated.
///
/// Callers must keep their external orchestration within the existing verifier
/// caller allowance and run under the unchanged process/thread/zero-swap guard.
/// This initial path always freshly registers the reconstructed child verifier.
pub fn qualify_single_child(
    artifact: Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
) -> Result<Report, Failure> {
    let started = Instant::now();
    let child = verification::verify_for_recursion(
        artifact,
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
    )
    .map_err(|failure| Failure {
        child_verification: Some(failure),
        ..Failure::new(
            "independent_child_verification",
            "child verification failed",
        )
    })?;
    let terminal = child.terminal();
    qualify_verified(child, started).map_err(|mut failure| {
        failure.child_verification_terminal = Some(terminal);
        failure
    })
}

fn qualify_verified(child: VerifiedRecursiveChild, started: Instant) -> Result<Report, Failure> {
    let compile_started = Instant::now();
    let compiled = compile(child)?;
    let recursive_compilation_ns = compile_started.elapsed().as_nanos();
    let evaluation_started = Instant::now();
    if !compiled.check(&compiled.public)? {
        return Err(Failure::new(
            "recursive_evaluation",
            "valid child constraints rejected",
        ));
    }
    let recursive_constraint_evaluation_ns = evaluation_started.elapsed().as_nanos();
    let mutations_started = Instant::now();
    for index in 0..PUBLICS {
        let mut changed = compiled.public;
        changed[index] += Val::ONE;
        if compiled.check(&changed)? {
            return Err(Failure::new(
                "recursive_evaluation",
                "changed public binding accepted",
            ));
        }
    }
    let public_binding_mutation_checks_ns = mutations_started.elapsed().as_nanos();
    let memory = compiled.child.bound().memory;
    let source_preflight_ns = compiled.child.bound().elapsed_ns;
    let CompiledChild {
        program,
        inputs,
        child,
        report: compiler,
        ..
    } = compiled;
    // No large program, recursive witness, child proof or trusted cap is kept
    // in a report or cache. Release all these owners before returning evidence.
    drop(program);
    drop(inputs);
    let child_verification = child.into_report();
    Ok(Report {
        schema: "lattica-research-direct-ring-recursive-constraints-v1",
        scope: "one-full-direct-ring-child-recursive-constraints-only",
        independently_verified_children: 1,
        recursive_proofs_generated: 0,
        complete_transaction_aggregate: false,
        final_aggregate: false,
        all_recursive_constraints_satisfied: true,
        public_binding_mutation_rejections: PUBLICS as u32,
        compiler,
        memory,
        source_preflight_ns,
        recursive_compilation_ns,
        recursive_constraint_evaluation_ns,
        public_binding_mutation_checks_ns,
        total_qualification_ns: started.elapsed().as_nanos(),
        child_verification,
    })
}

#[cfg(test)]
mod tests;
