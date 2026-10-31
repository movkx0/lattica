//! Conservative original-worker partitions. Every simultaneous owner is charged;
//! observations after allocation never authorize a larger reservation.
use super::*;
use lattica_prover_p3::proving::{ComponentObservation, Observation, Report as NativeReport, StageCapability};

const CALLER_BYTES: usize = 4 << 20;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct StorageReport {
    pub worker_host_bytes: usize,
    pub device_bytes: u64,
    pub context_reserve_bytes: u64,
    pub native_host_ceiling_bytes: u64,
    pub caller_reserved_bytes: usize,
    pub expected_statement_bytes: usize,
    pub native_witness_bytes: usize,
    pub verifier_lifecycle_bytes_each: usize,
    pub verifier_slots: usize,
    pub proof_slots: usize,
    pub proof_bytes_each: usize,
    pub all_retained_reservation_bytes: usize,
    pub active_host_partition_bytes: usize,
}

pub(super) struct Budget {
    pub report: StorageReport,
    pub limits: RegisteredGpuLimits,
}

pub(super) fn caller_census() -> Result<usize, Failure> {
    // Add source/caller/move/Result/catch frames without move-elision credit.
    // All large compiler/template/symbolic/codec backing is separately admitted.
    let bytes = sum(&[
        4 * size_of::<Budget>(), 4 * size_of::<StorageReport>(),
        8 * size_of::<BatchInput>(), 8 * size_of::<ExpectedBatch>(),
        4 * size_of::<CompiledRelation>(), 8 * size_of::<Compiled>(),
        8 * size_of::<PublicSource>(), 8 * size_of::<OwnedProof>(),
        4 * size_of::<Program>(), 4 * size_of::<ProgramBuilder>(), 4 * size_of::<ProofInputs>(),
        8 * size_of::<RegisteredProgram>(), 8 * size_of::<RegisteredVerifier>(),
        8 * size_of::<RegisteredGpuFootprint>(),
        8 * size_of::<RegisteredGpuMemoryPlan<'static>>(),
        8 * size_of::<RegisteredGpuAdmission<'static>>(),
        8 * size_of::<RegisteredGpuLimits>(),
        8 * size_of::<Report>(), 8 * size_of::<Failure>(),
        8 * size_of::<Result<Compiled, Failure>>(),
        8 * size_of::<std::thread::Result<Result<Compiled, Failure>>>(),
        8 * size_of::<Result<PublicSource, Failure>>(),
        8 * size_of::<std::thread::Result<Result<PublicSource, Failure>>>(),
        8 * size_of::<Result<OwnedProof, Failure>>(),
        8 * size_of::<std::thread::Result<Result<OwnedProof, Failure>>>(),
        8 * size_of::<Result<workflow::Outcome, Failure>>(),
        8 * size_of::<workflow::Outcome>(),
        8 * size_of::<compiler::Bound>(), 8 * size_of::<compiler::Identity>(),
        8 * size_of::<shape::VerifierCoreBound>(), 8 * size_of::<PlanningStorage>(),
        8 * size_of::<[RegisteredChildShape; MAX_CHILDREN]>(),
        8 * size_of::<[fixed_batch::Child<'static>; MAX_CHILDREN]>(),
        8 * size_of::<[[Wire; 4]; ROOTS]>(),
        8 * size_of::<[Val; PUBLICS]>(),
        MAX_CHILDREN * (size_of::<PublicSource>() + size_of::<OwnedProof>()),
        MAX_PHASES * size_of::<runtime::PhaseReport>(),
        // The original receipt validator enforces128 observations/16 components
        // per report. At most two report owners per phase are retained.
        (2 * MAX_PHASES + 8) * (size_of::<NativeReport>()
            + 128 * size_of::<Observation>() + 16 * size_of::<ComponentObservation>()
            // Capabilities::cpu collects at most17 fixed stages by a bounded
            // filter, then scoped retains without growth.32 covers backing.
            + 32 * size_of::<StageCapability>()),
        8 * size_of::<Vec<Statement>>(), 8 * size_of::<Vec<Witness>>(),
        // Native witness/statement transient argument and generation frames.
        4 * size_of::<Witness>(), 4 * size_of::<Statement>(),
        8 * size_of::<Instant>(), 8 * size_of::<std::path::PathBuf>(),
        8 * size_of::<std::fs::File>(),
        verification::mutation::caller_bytes(),
        // Existing reconstruction/session receipt census remains fully charged.
        REGISTERED_GPU_CALLER_HOST_BYTES,
        // Bounded path/hash/error/scalar/iterator/Arc/session-report helpers.
        128 << 10,
    ])?;
    if bytes > CALLER_BYTES { return Err(Failure::new("caller", "fixed caller census")); }
    Ok(bytes)
}

impl Budget {
    pub fn new(expected: &ExpectedBatch, witness_capacity: usize) -> Result<Self, Failure> {
        caller_census()?;
        if witness_capacity > MAX_CHILDREN { return Err(Failure::new("batch", "witness capacity")); }
        // The complete maximum-height CPU lifecycle includes one64MiB proof.
        // Reserve it for every child and the root, then add separate proof slots
        // conservatively; no proof credit is borrowed during decoder overlap.
        let cpu = RegisteredVerifier::host_reservation_bytes(PUBLICS, MAX_ROWS, ROOTS, ROOTS)
            .map_err(|_| Failure::new("admission", "CPU lifecycle source bound"))?;
        let slots = expected.selection.transactions() + 1;
        let statements = expected.owned_bytes()?;
        let witnesses = witness_capacity * size_of::<Witness>();
        let retained = sum(&[CALLER_BYTES, statements, witnesses,
            slots * cpu, slots * artifact::MAX_RETAINED_PROOF_BYTES])?;
        let active = HOST_BYTES.checked_sub(retained)
            .ok_or_else(|| Failure::new("admission", "retained owners exceed worker"))?;
        // Capture execution policy once. Every phase checks this exact selection.
        let limits = RegisteredGpuLimits::new(active as u64, DEVICE_BYTES, CONTEXT_BYTES, MAX_ROWS)
            .map_err(|_| Failure::new("admission", "active worker partition"))?;
        Ok(Self { report: StorageReport {
            worker_host_bytes: HOST_BYTES, device_bytes: DEVICE_BYTES,
            context_reserve_bytes: CONTEXT_BYTES, native_host_ceiling_bytes: 24 << 30,
            caller_reserved_bytes: CALLER_BYTES, expected_statement_bytes: statements,
            native_witness_bytes: witnesses, verifier_lifecycle_bytes_each: cpu,
            verifier_slots: slots, proof_slots: slots, proof_bytes_each: artifact::MAX_RETAINED_PROOF_BYTES,
            all_retained_reservation_bytes: retained, active_host_partition_bytes: active,
        }, limits })
    }
    pub fn active(&self) -> usize { self.report.active_host_partition_bytes }
    pub fn admit(&self, active_bytes: usize) -> Result<(), Failure> {
        if active_bytes > self.active() { return Err(Failure::new("admission", "active phase exceeds partition")); }
        Ok(())
    }
    pub fn compiler(&self) -> Result<usize, Failure> {
        self.admit(CAPACITY.limits().required_host_bytes as usize)?;
        Ok(self.active())
    }
    pub fn evaluation(&self) -> Result<(), Failure> {
        self.admit(sum(&[PROGRAM_BYTES, 2 * CAPACITY.limits().witness_byte_limit as usize,
            MAX_WIRES * size_of::<Val>()])?)
    }
}
