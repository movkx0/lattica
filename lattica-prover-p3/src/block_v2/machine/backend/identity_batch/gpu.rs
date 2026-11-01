use super::*;
use super::super::{identity_stream, identity_receipt, MachineAir, RegisteredIdentityReceipt};
use crate::block_v2::{machine::{program::{Program, Val}, analysis, symbolic, compiler_constants, fingerprint}, profile};
use crate::block_v2::gpu_hash::device::public_hash::batched;
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Report, Request, Run, Stage};
use p3_field::PrimeField64;
use p3_uni_stark::StarkGenericConfig;
use std::{marker::PhantomData, sync::{Arc, atomic::{AtomicU64, Ordering}}};

const DOMAIN: u64 = 0x4c42563210;
type Cursor<'a> = std::iter::Take<identity_stream::Cursor<'a>>;
/// Additional immutable prefix storage; Program storage is charged separately.
pub const IDENTITY_PREFIX_HOST_BYTES: u64 = fingerprint::bounded::HOST_BYTES as u64 + 4096;

/// One process-local workflow authority; it is deliberately not Clone.
pub struct IdentityBatchContext { authority: Arc<()>, next_batch: AtomicU64 }
impl Default for IdentityBatchContext { fn default() -> Self { Self::new() } }
impl IdentityBatchContext {
    pub fn new() -> Self { Self { authority: Arc::new(()), next_batch: AtomicU64::new(0) } }
    pub fn plan(&self, limits: IdentityBatchLimits, programs: Vec<(u64, Arc<Program>)>,
        host_allowance: u64, managed_allowance: u64) -> Result<IdentityBatchPlan, String> {
        self.plan_storage(limits, programs, host_allowance, managed_allowance,
            IdentityProgramStorage::Standalone)
    }

    /// The caller retains and separately charges each immutable program owner.
    /// Only incremental prefix storage is charged here. The borrow lasts through
    /// GPU retirement; completed tokens must remain under the original program
    /// owners until registration consumes them. This grants no ledger credit.
    pub fn plan_borrowed<'program>(&self, limits: IdentityBatchLimits,
        programs: Vec<(u64, &'program Arc<Program>)>, host_allowance: u64,
        managed_allowance: u64) -> Result<BorrowedIdentityBatchPlan<'program>, String> {
        if programs.is_empty() || programs.len() > limits.max_streams()
            || programs.capacity() > MAX_IDENTITY_STREAMS {
            return Err("borrowed identity batch admission geometry".into());
        }
        let mut shared = Vec::new();
        shared.try_reserve_exact(programs.len()).map_err(|_| "borrowed identity batch handles")?;
        for (job, program) in programs { shared.push((job, Arc::clone(program))); }
        let plan = self.plan_storage(limits, shared, host_allowance, managed_allowance,
            IdentityProgramStorage::Borrowed)?;
        Ok(BorrowedIdentityBatchPlan { plan, owners: PhantomData })
    }

    fn plan_storage(&self, limits: IdentityBatchLimits, programs: Vec<(u64, Arc<Program>)>,
        host_allowance: u64, managed_allowance: u64, storage: IdentityProgramStorage)
        -> Result<IdentityBatchPlan, String> {
        if limits.schedule != IdentityHashSchedule::BatchedV1 || programs.is_empty()
            || programs.len() > limits.max_streams() || programs.capacity() > MAX_IDENTITY_STREAMS || host_allowance > 32 << 30
            || managed_allowance > 8 << 30
        { return Err("identity batch admission geometry".into()); }
        for (i, (id, program)) in programs.iter().enumerate() {
            if programs[..i].iter().any(|(other, _)| id == other)
                || !program.height().is_power_of_two() {
                return Err("identity batch duplicate job or invalid program height".into());
            }
        }
        let source_bytes = programs.iter().try_fold(0u64, |sum, (_, p)| {
            sum.checked_add(p.source_host_bytes()? as u64).ok_or_else(|| "identity batch source size overflow".to_string())
        })?;
        let footprint = IdentityBatchFootprint::for_storage(programs.len(), source_bytes, storage)?;
        if footprint.host_bytes > host_allowance || footprint.managed_bytes > managed_allowance {
            return Err("identity batch exceeds supplied admission".into());
        }
        let batch = self.next_batch.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |n| n.checked_add(1)).map_err(|_| "identity batch ordinal overflow")?;
        Ok(IdentityBatchPlan { authority: Arc::clone(&self.authority), batch, programs, footprint })
    }
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityProgramStorage { Standalone, Borrowed }

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct IdentityBatchFootprint {
    pub program_storage: IdentityProgramStorage,
    /// Diagnostic backing held by the caller, excluded from this operation's
    /// host_bytes and retained_host_bytes. Never subtracted from another claim.
    pub borrowed_program_host_bytes: u64,
    pub host_bytes: u64,
    pub retained_host_bytes: u64,
    pub managed_bytes: u64,
    pub max_allocation_bytes: u64,
}
impl IdentityBatchFootprint {
    /// Allocation-free source bound, available before any witness or proof.
    pub fn for_program_bounds(streams: usize, total_source_bytes: u64) -> Result<Self, String> {
        Self::for_storage(streams, total_source_bytes, IdentityProgramStorage::Standalone)
    }
    /// Additional storage when original compiler owners remain charged in the
    /// enclosing workflow. The source bound is reported separately, not credit.
    pub fn for_borrowed_program_bounds(streams: usize, total_source_bytes: u64) -> Result<Self, String> {
        Self::for_storage(streams, total_source_bytes, IdentityProgramStorage::Borrowed)
    }
    fn for_storage(streams: usize, total_source_bytes: u64, storage: IdentityProgramStorage)
        -> Result<Self, String> {
        let stream = batched::Footprint::for_streams::<Cursor<'_>>(streams)?;
        let owned_source = if storage == IdentityProgramStorage::Standalone { total_source_bytes } else { 0 };
        let retained_host_bytes = (streams as u64).checked_mul(IDENTITY_PREFIX_HOST_BYTES)
            .and_then(|n| n.checked_add(owned_source)).ok_or("identity batch retained size overflow")?;
        let host_bytes = retained_host_bytes.checked_add(symbolic::HOST_BYTES)
            .and_then(|n| n.checked_add(stream.host_bytes)).ok_or("identity batch host size overflow")?;
        // Check the enclosing sum too, even though the caller charges the two
        // parts separately. A reported bound must not hide arithmetic overflow.
        let borrowed_program_host_bytes = if storage == IdentityProgramStorage::Borrowed { total_source_bytes } else { 0 };
        host_bytes.checked_add(borrowed_program_host_bytes).ok_or("identity batch enclosing size overflow")?;
        Ok(Self { program_storage: storage, borrowed_program_host_bytes,
            host_bytes, retained_host_bytes, managed_bytes: stream.device_bytes,
            max_allocation_bytes: stream.max_allocation_bytes })
    }
}

/// The caller reserves this entire footprint in its existing worker ledger.
/// The plan is not a substitute for an owned runtime or source authorization.
pub struct IdentityBatchPlan {
    authority: Arc<()>, batch: u64, programs: Vec<(u64, Arc<Program>)>, footprint: IdentityBatchFootprint,
}

/// A distinct borrowing path; it cannot be converted into a standalone plan.
pub struct BorrowedIdentityBatchPlan<'program> {
    plan: IdentityBatchPlan,
    owners: PhantomData<&'program Arc<Program>>,
}
impl<'program> BorrowedIdentityBatchPlan<'program> {
    pub fn footprint(&self) -> IdentityBatchFootprint { self.plan.footprint() }
    pub fn execute(self, request: Request) -> Result<PendingBorrowedIdentityBatch<'program>, String> {
        Ok(PendingBorrowedIdentityBatch { pending: self.plan.execute(request)?, owners: PhantomData })
    }
}
pub struct PendingBorrowedIdentityBatch<'program> {
    pending: PendingIdentityBatch,
    owners: PhantomData<&'program Arc<Program>>,
}
impl PendingBorrowedIdentityBatch<'_> {
    pub fn complete_after_retirement(self) -> Result<(Vec<CompletedIdentityPrefix>, IdentityBatchReport), String> {
        self.pending.complete_after_retirement()
    }
}
impl IdentityBatchPlan {
    pub fn footprint(&self) -> IdentityBatchFootprint { self.footprint }
    pub fn execute(self, request: Request) -> Result<PendingIdentityBatch, String> {
        if request.policy != Policy::GpuRequired { return Err("identity prefix batches require GPU-only execution".into()); }
        crate::block_v2::machine::gpu_backend::check_selected()?;
        let _phase = crate::block_v2::worker_memory::PhaseGuard::acquire("preprocessing")?;
        let mut caps = Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, false)
            .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
        caps.set(Stage::Preprocessing, Backend::OpenCl);
        let run = Run::new("block_v2_identity_prefix_batch", request, caps).map_err(|e| e.to_string())?;
        let started = std::time::Instant::now();
        let config = profile::preprocessing_config_with_host_budget(self.footprint.host_bytes as usize)
            .map_err(|e| e.to_string())?;
        let session = config.pcs().quotient_session()?;
        let mut prepared = Vec::with_capacity(self.programs.len());
        for (job, program) in self.programs {
            let air = MachineAir::from_shared_program(Arc::clone(&program));
            let symbolic = symbolic::prepare_machine(&air, compiler_constants::Constants::device(&session, &run))
                .map_err(|e| format!("identity prefix analysis: {e:?}"))?;
            let analysis = analysis::analyze_prepared(&air, &symbolic).map_err(|e| format!("identity prefix analysis: {e:?}"))?;
            let (_, constraints) = symbolic.into_parts();
            let fingerprint = fingerprint::bounded::encode(&constraints.base, &constraints.extension,
                &constraints.order, fingerprint::bounded::HOST_BYTES)?;
            let mut fields = 0usize;
            let mut tail = [0u64; 3];
            for field in identity_stream::Cursor::new(&air, &analysis, &fingerprint) {
                let field = field?;
                if field >= crate::block_v2::commitment::MODULUS { return Err("identity prefix noncanonical metadata".into()); }
                // A three-word rolling tail avoids another full metadata walk.
                tail.rotate_left(1); tail[2] = field;
                fields = fields.checked_add(1).ok_or("identity prefix size overflow")?;
            }
            let tail_len = fields % 4;
            let tail = tail[3 - tail_len..].to_vec();
            let cap_fields = 4usize << ((air.program().height().ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT));
            let total_fields = fields.checked_add(cap_fields).ok_or("identity prefix size overflow")?;
            prepared.push(Prepared { job, program, air, analysis, fingerprint, fields: fields - tail_len,
                total_fields, cap_fields, tail });
        }
        let analysis_ns = started.elapsed().as_nanos();
        let inputs = prepared.iter().map(|p| batched::Input { domain: DOMAIN, total_fields: p.total_fields,
            prefix_fields: p.fields, fields: identity_stream::Cursor::new(&p.air, &p.analysis, &p.fingerprint).take(p.fields) }).collect();
        let before = session.stats();
        let hashing = std::time::Instant::now();
        let prefixes = session.hash_public_prefix_batch(inputs, &run, self.footprint.host_bytes)?;
        let hash_wall_ns = hashing.elapsed().as_nanos();
        let after = session.stats();
        let report = IdentityBatchReport { schema: "identity-prefix-batch-v2", batch: self.batch,
            streams: prepared.len(), analysis_ns, hash_wall_ns,
            device_ns: after.public_hash_device_ns - before.public_hash_device_ns,
            fields: after.public_hash_fields - before.public_hash_fields,
            uploaded_bytes: after.uploaded_bytes - before.uploaded_bytes,
            downloaded_bytes: after.downloaded_bytes - before.downloaded_bytes,
            footprint: self.footprint, preprocessing: run.finish(true).map_err(|e| e.to_string())? };
        let pending = prepared.into_iter().zip(prefixes).map(|(p, prefix)| CompletedIdentityPrefix {
            authority: Arc::clone(&self.authority), batch: self.batch, job: p.job, program: p.program,
            header: identity_stream::header(&p.air), trailer: identity_stream::trailer(&p.analysis),
            fingerprint: p.fingerprint, cap_fields: p.cap_fields, tail: p.tail, fields: p.fields, prefix,
        }).collect();
        Ok(PendingIdentityBatch { pending, report })
    }
}

struct Prepared {
    job: u64, program: Arc<Program>, air: MachineAir, analysis: analysis::MachineAnalysis,
    fingerprint: Vec<u64>, fields: usize, total_fields: usize, cap_fields: usize, tail: Vec<u64>,
}

#[derive(serde::Serialize)]
pub struct IdentityBatchReport {
    pub schema: &'static str, pub batch: u64, pub streams: usize, pub analysis_ns: u128,
    pub hash_wall_ns: u128, pub device_ns: u128, pub fields: u64,
    pub uploaded_bytes: u64, pub downloaded_bytes: u64,
    pub footprint: IdentityBatchFootprint, pub preprocessing: Report,
}

pub struct PendingIdentityBatch { pending: Vec<CompletedIdentityPrefix>, report: IdentityBatchReport }
impl PendingIdentityBatch {
    /// A weak reference to the actual GPU lease, not a caller-supplied receipt,
    /// proves that every originating context owner has been destroyed.
    pub fn complete_after_retirement(self) -> Result<(Vec<CompletedIdentityPrefix>, IdentityBatchReport), String> {
        if self.pending.iter().any(|p| !p.prefix.origin_retired()) {
            return Err("identity prefix GPU epoch has not retired".into());
        }
        Ok((self.pending, self.report))
    }
}

pub struct CompletedIdentityPrefix {
    authority: Arc<()>, batch: u64, job: u64, program: Arc<Program>, header: [u64; 10],
    trailer: [u64; 18], fingerprint: Vec<u64>, cap_fields: usize, tail: Vec<u64>,
    fields: usize, prefix: batched::Prefix,
}
impl CompletedIdentityPrefix {
    pub fn job(&self) -> u64 { self.job }
    pub fn batch(&self) -> u64 { self.batch }
    pub fn retained_host_bytes(&self) -> u64 {
        (std::mem::size_of::<Self>() + self.fingerprint.capacity() * 8 + self.tail.capacity() * 8) as u64
    }
    pub(in crate::block_v2::machine::backend) fn check_owner(&self, context: &IdentityBatchContext,
        job: u64, air: &MachineAir) -> Result<(), String> {
        if !Arc::ptr_eq(&self.authority, &context.authority) || self.job != job
            || !std::ptr::eq(self.program.as_ref(), air.program()) || !self.prefix.origin_retired() {
            return Err("identity prefix workflow, job, program or retirement mismatch".into());
        }
        Ok(())
    }
    pub(in crate::block_v2::machine::backend) fn finish(self, air: &MachineAir,
        analysis: &analysis::MachineAnalysis, fingerprint: &[u64], common: &p3_batch_stark::CommonData<profile::Config>,
        config: &profile::Config, run: &Run) -> Result<([u64; 4], RegisteredIdentityReceipt, bool), String> {
        let roots = common.preprocessed.as_ref().ok_or("identity prefix missing commitment")?.commitment.roots();
        if !std::ptr::eq(self.program.as_ref(), air.program()) || self.header != identity_stream::header(air)
            || self.trailer != identity_stream::trailer(analysis) || self.fingerprint != fingerprint
            || roots.len().checked_mul(4) != Some(self.cap_fields) {
            return Err("identity prefix metadata or commitment geometry changed".into());
        }
        let cache_fingerprint = identity_receipt::fingerprint_stream(DOMAIN, |emit| {
            super::super::emit_program_identity(air, common, analysis, fingerprint, emit)
        })?;
        let mut suffix = self.tail;
        suffix.try_reserve_exact(self.cap_fields).map_err(|_| "identity prefix suffix allocation")?;
        suffix.extend(roots.iter().flatten().map(|x| x.as_canonical_u64()));
        let session = config.pcs().quotient_session()?;
        let id = session.finish_public_prefix(self.prefix, &suffix, run, 1 << 20)?;
        eprintln!("bounded_gpu_identity_prefix_consumed batch={} job={} prefix_fields={} suffix_fields={} prefix_fresh_device_credit=0",
            self.batch, self.job, self.fields, suffix.len());
        Ok((id, RegisteredIdentityReceipt::from_gpu_result(id, cache_fingerprint), false))
    }
}
