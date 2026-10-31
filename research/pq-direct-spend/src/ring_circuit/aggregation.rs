//! Default-disabled, fixed N3/N4 direct-ring aggregate research.
//!
//! Each child is a fresh proof of the whole unchanged direct-ring relation.
//! Independent expected statements determine every source key; artifact claims
//! never determine a circuit. All phases partition the original worker budget.
//! This module supplies no production transaction-acceptance route.
use super::{artifact, proving, verification, CompiledRelation, CompilerCapacityProfile,
    CompilerMemoryProfile, CompilerRepresentation, CompilerWireProfile, Context, Error,
    Program, Statement, Val};
use crate::ring::Witness;
use lattica_prover_p3::block_v2::{machine::{
    backend::{RegisteredProgram, RegisteredVerifier},
    program::{ConstructionLimits, ProgramBuilder, ProofInputs, Wire},
    verifier::batch::{self, shape::{self, OperationCounts, PlanningStorage, RegisteredChildShape}, source_program::fixed_batch},
    MachineAir, RegisteredGpuAdmission, RegisteredGpuFootprint, RegisteredGpuLimits, RegisteredGpuMemoryPlan,
    REGISTERED_GPU_CALLER_HOST_BYTES,
}, profile};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::Serialize;
use std::{mem::size_of, sync::Arc, time::Instant};

mod binding;
mod bounds;
mod compiler;
mod diagnostics;
mod runtime;
mod workflow;
pub use binding::{BatchInput, ExpectedBatch, Selection};
pub use workflow::{prove_complete, verify_independently, Outcome, VerifiedAggregate};
pub use artifact::aggregate::{AggregateArtifact, RoundtripReport};

const HOST_BYTES: usize = 32 << 30;
const DEVICE_BYTES: u64 = 8 << 30;
const CONTEXT_BYTES: u64 = 4 << 30;
const MAX_ROWS: usize = 1 << 20;
const MAX_INPUTS: usize = 1 << 20;
const MAX_WIRES: usize = 1 << 26;
const PROGRAM_BYTES: usize = 2 << 30;
const MAX_CHILDREN: usize = 4;
const ROOTS: usize = 64;
const PUBLICS: usize = 4;
const MAX_PHASES: usize = 16;
const CAPACITY: CompilerCapacityProfile = CompilerCapacityProfile::new(
    CompilerMemoryProfile::Program2GiB, CompilerWireProfile::Research16M);
const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;

fn construction() -> ConstructionLimits {
    ConstructionLimits { max_requested_program_bytes: PROGRAM_BYTES,
        max_wires: MAX_WIRES, max_input_values: MAX_INPUTS }
}
fn sum(parts: &[usize]) -> Result<usize, Failure> {
    parts.iter().try_fold(0usize, |a, &b| a.checked_add(b))
        .ok_or_else(|| Failure::new("admission", "storage overflow"))
}
fn attempt<T>(phase: &'static str, run: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(value) => value,
        Err(payload) => { drop(payload); Err(Failure::new(phase, "backend panicked")) }
    }
}

/// A bounded failure, retaining all completed phase receipts on workflow error.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub phase: &'static str,
    pub reason: &'static str,
    pub proof_started: bool,
    pub terminal: Option<proving::TerminalReceipt>,
    pub cleanup_failed: bool,
    pub admission: Option<diagnostics::AdmissionFailure>,
    pub progress: Option<Report>,
}
impl Failure {
    fn new(phase: &'static str, reason: &'static str) -> Self {
        Self { phase, reason, proof_started: false, terminal: None,
            cleanup_failed: false, admission: None, progress: None }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.phase, self.reason)?;
        if let Some(admission) = &self.admission {
            write!(f, " (actual active_rows={}, padded_rows={}; {})",
                admission.actual_program.active_rows, admission.actual_program.padded_rows,
                admission.core_error)?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub scope: &'static str,
    pub selection: Selection,
    pub proof_generation: &'static str,
    pub fresh_whole_transaction_proofs: usize,
    pub fresh_recursive_aggregate_proofs: usize,
    pub independent_child_cpu_acceptances: usize,
    pub independent_final_cpu_acceptances: usize,
    pub public_mutation_rejections: usize,
    pub opening_mutation_rejections: usize,
    pub restored_proof_acceptances: usize,
    pub envelope_rejections: usize,
    pub public_setup_reused_for_child_cpu_checks: usize,
    pub synthetic_hints_evaluated: bool,
    pub faithful_ringct_protocol: bool,
    pub production_acceptance: bool,
    pub redesign_2x_gate_passed: bool,
    pub security_adoption_review_complete: bool,
    pub compilation_ns: u128,
    pub source_planning_ns: u128,
    pub cpu_verification_ns: u128,
    pub mutation_checks_ns: u128,
    /// Starts with the already-owned batch; fixture generation/final owner
    /// destruction are included separately by the complete guarded driver.
    pub owned_workflow_ns: u128,
    pub source: Option<compiler::SourceReport>,
    pub storage: Option<bounds::StorageReport>,
    pub artifact_roundtrip: Option<RoundtripReport>,
    pub phases: Vec<runtime::PhaseReport>,
}
impl Report {
    fn new(selection: Selection) -> Result<Self, Failure> {
        bounds::caller_census()?;
        let mut phases = Vec::new();
        phases.try_reserve_exact(MAX_PHASES)
            .map_err(|_| Failure::new("report", "bounded report allocation"))?;
        if phases.capacity() != MAX_PHASES { return Err(Failure::new("report", "report capacity")); }
        Ok(Self { schema: "lattica-research-direct-ring-fixed-aggregate-v1",
            scope: "complete owned direct-ring N3/N4 research aggregation",
            selection, proof_generation: "FreshOnly", fresh_whole_transaction_proofs: 0,
            fresh_recursive_aggregate_proofs: 0, independent_child_cpu_acceptances: 0,
            independent_final_cpu_acceptances: 0, public_mutation_rejections: 0,
            opening_mutation_rejections: 0, restored_proof_acceptances: 0, envelope_rejections: 0,
            public_setup_reused_for_child_cpu_checks: 0, synthetic_hints_evaluated: false,
            faithful_ringct_protocol: false, production_acceptance: false,
            redesign_2x_gate_passed: false, security_adoption_review_complete: false,
            compilation_ns: 0, source_planning_ns: 0, cpu_verification_ns: 0,
            mutation_checks_ns: 0, owned_workflow_ns: 0, source: None,
            storage: None, artifact_roundtrip: None, phases })
    }
    fn push(&mut self, phase: runtime::PhaseReport) -> Result<(), Failure> {
        if self.phases.len() == MAX_PHASES || self.phases.capacity() != MAX_PHASES {
            return Err(Failure { terminal: Some(phase.terminal), proof_started: phase.fresh_proof,
                ..Failure::new("report", "phase count") });
        }
        if phase.footprint.physical_device_uuid.is_none() || self.phases.first().is_some_and(|prior|
            prior.footprint.physical_device_uuid != phase.footprint.physical_device_uuid) {
            return Err(Failure { terminal: Some(phase.terminal), proof_started: phase.fresh_proof,
                ..Failure::new("report", "physical device changed between sequential phases") });
        }
        self.phases.push(phase);
        Ok(())
    }
}

struct SecretInputs(Vec<Val>);
impl Drop for SecretInputs {
    fn drop(&mut self) {
        for value in &mut self.0 { unsafe { std::ptr::write_volatile(value, Val::ZERO) }; }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
struct Compiled {
    program: Arc<Program>,
    inputs: SecretInputs,
    public: [Val; PUBLICS],
    manifest: [u8; 32],
}
/// Private key provenance: only expected-public reconstruction plus fresh
/// registration can create this owner. No artifact cap or report is accepted.
struct PublicSource {
    shape: RegisteredChildShape,
    cap: [[Val; 4]; ROOTS],
    public: [Val; PUBLICS],
    descriptor: artifact::ProofDescriptor,
    verifier: RegisteredVerifier,
}
struct OwnedProof {
    proof: BatchProof<profile::Config>,
    descriptor: artifact::ProofDescriptor,
}

#[cfg(test)]
mod tests;
