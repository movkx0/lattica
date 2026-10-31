//! Requested report backing for the closed raw graph preparation entry.
//!
//! The research caller reserves this additional storage in its original ledger
//! before entering with_operations and keeps it through report destruction.
//! This type alone neither reserves memory nor authorizes a GPU operation.
use super::*;
use core::mem::size_of;

const INVENTORY: usize = 16;
const STAGES: usize = 19;
const BACKENDS: usize = 6;
const OBSERVATIONS: usize = STAGES * BACKENDS;
const JSON_BYTES: usize = 4096 + INVENTORY * 128 + OBSERVATIONS * 512;
// Error Display uses fixed text plus Debug StageCapability entries. Raw graph
// reports have no component names. Each closed enum pair fits 128 bytes.
const ERROR_BYTES: usize = 256 + (INVENTORY + OBSERVATIONS) * 128;

// Exhaustive matches require review when either closed key enum changes.
fn stage_slot(stage: Stage) -> usize {
    match stage {
        Stage::PublicValues => 0,
        Stage::WitnessTrace => 1,
        Stage::Preprocessing => 2,
        Stage::Lookup => 3,
        Stage::Transform => 4,
        Stage::Quotient => 5,
        Stage::Randomness => 6,
        Stage::Hiding => 7,
        Stage::Commitment => 8,
        Stage::Opening => 9,
        Stage::FriFold => 10,
        Stage::FriQuery => 11,
        Stage::FinalPolynomial => 12,
        Stage::Scalar => 13,
        Stage::Transcript => 14,
        Stage::Grinding => 15,
        Stage::UpstreamProver => 16,
        Stage::ConstraintAudit => 17,
        Stage::Serialization => 18,
    }
}

fn backend_slot(backend: Backend) -> usize {
    match backend {
        Backend::Cpu => 0,
        Backend::OpenCl => 1,
        Backend::Metal => 2,
        Backend::Cuda => 3,
        Backend::Mixed => 4,
        Backend::Unknown => 5,
    }
}

fn arc_bytes<T>() -> usize {
    #[repr(C)]
    struct Allocation<T> {
        strong: std::sync::atomic::AtomicUsize,
        weak: std::sync::atomic::AtomicUsize,
        value: T,
    }
    size_of::<Allocation<T>>()
}

// Pinned Rust 1.96 Vec collect/push growth, including old/new backing during
// reallocation. No supplied Vec, reserve amount or iterator hint is accepted.
fn vector<T>(count: usize) -> usize {
    if count == 0 || size_of::<T>() == 0 {
        0
    } else {
        3 * count.next_power_of_two().max(4) * size_of::<T>()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RawPreparationReportStorage {
    pub capability_backing_bytes: usize,
    pub observation_backing_bytes: usize,
    pub finish_temporary_bytes: usize,
    pub publication_overlap_bytes: usize,
    pub inline_and_shared_owner_bytes: usize,
    pub maximum_json_bytes: usize,
    pub maximum_error_bytes: usize,
    pub error_format_overlap_bytes: usize,
    pub required_host_bytes: usize,
}

impl RawPreparationReportStorage {
    /// Source-bound to native_gpu::with_operations: fixed entry label,
    /// BlockV2Cubic, Operation scope, one WitnessTrace/OpenCl capability and
    /// no composition parent. Count even invalid enum-key observations, which
    /// cause strict completion to fail. The caller separately owns runtime,
    /// diagnostics/errors, adapters, retained graph and allocation overhead.
    pub fn new() -> Result<Self, Error> {
        if Stage::ARITHMETIC.len() != INVENTORY
            || stage_slot(Stage::Serialization) + 1 != STAGES
            || backend_slot(Backend::Unknown) + 1 != BACKENDS
            || JSON_BYTES > 1 << 16
        {
            return Err(Error::ComponentRejected);
        }
        // cpu().scoped() retains the bootstrap Vec's allocation. Its source
        // inventory is at most sixteen; the later one-element clone is
        // counted separately below. Request::admit's gaps are also counted.
        let capability_backing_bytes = 2 * vector::<StageCapability>(INVENTORY);
        let observation_backing_bytes = vector::<Observation>(OBSERVATIONS);
        // finish's missing/unaccounted Vecs coexist with a capability clone.
        // Empty components and missing_components have no requested backing.
        let finish_temporary_bytes = vector::<StageCapability>(INVENTORY)
            + vector::<StageCapability>(OBSERVATIONS)
            + vector::<StageCapability>(INVENTORY);
        // Fixed enum labels, <=20 decimal u64 digits and <=39 u128 digits,
        // no arbitrary strings/components and the exact static entry label
        // fit JSON_BYTES. serde_json::to_string uses a growing Vec writer.
        let publication_overlap_bytes = 3 * JSON_BYTES.next_power_of_two();
        let error_format_overlap_bytes = 3 * ERROR_BYTES.next_power_of_two();
        let inline_and_shared_owner_bytes = size_of::<Run>()
            + size_of::<Report>()
            + size_of::<Capabilities>()
            + size_of::<Error>()
            + size_of::<Timer<'static>>()
            + arc_bytes::<Mutex<State>>()
            + size_of::<Self>();
        let required_host_bytes = [
            capability_backing_bytes,
            observation_backing_bytes,
            finish_temporary_bytes,
            publication_overlap_bytes,
            error_format_overlap_bytes,
            inline_and_shared_owner_bytes,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(Error::ComponentRejected)?;
        Ok(Self {
            capability_backing_bytes,
            observation_backing_bytes,
            finish_temporary_bytes,
            publication_overlap_bytes,
            error_format_overlap_bytes,
            inline_and_shared_owner_bytes,
            maximum_json_bytes: JSON_BYTES,
            maximum_error_bytes: ERROR_BYTES,
            required_host_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
