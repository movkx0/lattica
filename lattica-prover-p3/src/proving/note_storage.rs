//! Fixed private-note operation reporting. The enclosing producer owns the
//! cumulative reservation; this module does not allocate a ledger or admit GPU
//! work. Ordinary Run construction, completion and publication are unchanged.
use super::*;
use crate::block_v2::legacy_wallet::note_admission::WorkerPolicyAbsent;
use core::mem::size_of;

const ENTRY: &str = "private_note_gpu";
const INVENTORY: usize = 15;
// A Run merges observations by its closed (Stage, Backend) enum key. Reserve
// every key, including observations which will make strict completion fail.
// This prevents a rejected or exceptional observation from growing the table.
const STAGES: usize = 19;
const BACKENDS: usize = 6;
const OBSERVATIONS: usize = STAGES * BACKENDS;
const JSON_BYTES: usize = 4096 + INVENTORY * 128 + OBSERVATIONS * 512;

// Exhaustive matches make adding a variant a compile error until the bound is
// reviewed. They also avoid deriving this fixed inventory from external input.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NoteReportResources {
    pub retained_table_bytes: usize,
    pub finish_temporary_bytes: usize,
    pub publication_overlap_bytes: usize,
    pub inline_and_shared_owner_bytes: usize,
    pub maximum_json_bytes: usize,
    pub required_host_bytes: usize,
}

impl NoteReportResources {
    /// Pure source-owned payload bound. Stacks, allocator metadata and the
    /// receiving stderr/log transport remain in the enclosing process budget.
    /// The source-owned worker-policy-absence capability is required by the
    /// constructor; its capture belongs to the enclosing configuration census.
    pub(crate) fn new() -> Result<Self, Error> {
        if Stage::ARITHMETIC.len() != 16
            || stage_slot(Stage::Serialization) + 1 != STAGES
            || backend_slot(Backend::Unknown) + 1 != BACKENDS
            || JSON_BYTES > 1 << 16
        {
            return Err(Error::ComponentRejected);
        }
        let retained_table_bytes =
            INVENTORY * size_of::<StageCapability>() + OBSERVATIONS * size_of::<Observation>();
        // finish() retains missing and unaccounted vectors while cloning the
        // capabilities for its Report. Filter/collect may grow geometrically:
        // count the old and new allocations together for both vectors. The
        // empty component list and missing-component list allocate no backing.
        let missing = INVENTORY.next_power_of_two();
        let unaccounted = OBSERVATIONS.next_power_of_two();
        let finish_temporary_bytes =
            (missing + missing / 2 + unaccounted + unaccounted / 2 + INVENTORY)
                * size_of::<StageCapability>();
        // Run::publish uses serde_json::to_string, whose Vec writer starts at
        // 128 bytes and grows geometrically. Fixed ASCII labels, <=20 decimal
        // digits per u64, <=39 per u128, and no components fit JSON_BYTES. Keep
        // both old/new backing at the largest reallocation. eprintln formats
        // the already-owned string without building another report string.
        let publication_overlap_bytes = 3 * JSON_BYTES.next_power_of_two();
        let inline_and_shared_owner_bytes = size_of::<NoteRun>()
            + size_of::<Report>()
            + size_of::<Error>()
            + size_of::<Timer<'static>>()
            + arc_bytes::<Mutex<State>>()
            + size_of::<Self>();
        let required_host_bytes = retained_table_bytes
            .checked_add(finish_temporary_bytes)
            .and_then(|n| n.checked_add(publication_overlap_bytes))
            .and_then(|n| n.checked_add(inline_and_shared_owner_bytes))
            .ok_or(Error::ComponentRejected)?;
        Ok(Self {
            retained_table_bytes,
            finish_temporary_bytes,
            publication_overlap_bytes,
            inline_and_shared_owner_bytes,
            maximum_json_bytes: JSON_BYTES,
            required_host_bytes,
        })
    }
}

/// Source-bound single operation. No Clone, mutable Run, parent attachment or
/// dynamically supplied entry point/inventory is exposed. Keep the enclosing
/// reservation through returned Report destruction or any failure publication.
pub(crate) struct NoteRun {
    run: Run,
}

impl NoteRun {
    pub(crate) fn new(
        preclaimed_host_bytes: usize,
        policy: &WorkerPolicyAbsent,
    ) -> Result<Self, Error> {
        if preclaimed_host_bytes < NoteReportResources::new()?.required_host_bytes {
            return Err(Error::ComponentRejected);
        }
        // Run::new/Request::admit retain their existing checks. This closed note
        // path cannot enter assignment parsing: both overrides and an already
        // installed wallet assignment must remain absent. The immutable worker
        // environment is also recaptured by the enclosing producer at handoffs.
        policy.recheck().map_err(|_| Error::ComponentRejected)?;
        let mut stages = Vec::new();
        stages
            .try_reserve_exact(INVENTORY)
            .map_err(|_| Error::ComponentRejected)?;
        for stage in Stage::ARITHMETIC {
            if stage != Stage::Lookup {
                stages.push(StageCapability {
                    stage,
                    backend: Backend::OpenCl,
                });
            }
        }
        if stages.len() != INVENTORY || stages.capacity() != INVENTORY {
            return Err(Error::ComponentRejected);
        }
        let run = Run::new(
            ENTRY,
            Request {
                policy: Policy::GpuRequired,
                emit_report: true,
            },
            Capabilities {
                scope: CoverageScope::ProofRequest,
                profile: Profile::LegacyQuadratic,
                max_log_fri_arity: 4,
                stages,
            },
        )?;
        run.state
            .lock()
            .map_err(|_| Error::ComponentRejected)?
            .observations
            .try_reserve_exact(OBSERVATIONS)
            .map_err(|_| Error::ComponentRejected)?;
        Ok(Self { run })
    }

    pub(crate) fn run(&self) -> &Run {
        &self.run
    }

    pub(crate) fn finish(self, succeeded: bool) -> Result<Report, Error> {
        self.run.finish(succeeded)
    }
}

#[cfg(test)]
mod tests;
