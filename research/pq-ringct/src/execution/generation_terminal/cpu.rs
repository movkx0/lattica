//! Typed, same-ledger CPU completion. No GPU session exists in this stage.
use super::*;
use crate::native::{
    self,
    cpu_generation::{Configuration, Generator, Output, Statistics},
    FixtureAmounts,
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Default, serde::Serialize)]
pub(crate) struct CpuTotals {
    pub(crate) run_id: u64,
    pub(crate) verified: u64,
    pub(crate) whole_stage_ns: u128,
    pub(crate) spend_ns: u128,
    pub(crate) verification_ns: u128,
    pub(crate) attempts: u64,
    pub(crate) random_calls: u64,
    pub(crate) random_blocks: u64,
    pub(crate) proposals: u64,
    pub(crate) parameter_cache_hits: u64,
    pub(crate) cleanup_complete: bool,
    pub(crate) gpu_contexts: u64,
    pub(crate) gpu_generation_calls: u64,
}
#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct CpuSpendSummary {
    pub(crate) run_id: u64,
    pub(crate) ordinal: usize,
    pub(crate) elapsed_ns: u128,
    pub(crate) generation_ns: u64,
    pub(crate) verification_ns: u128,
    pub(crate) statistics: Statistics,
}
impl report_transport::FixedPayload for CpuSpendSummary {}

/// Constructible only after the independent native verifier accepts output.
pub(crate) struct VerifiedCpuOutput {
    statement: Vec<u8>,
    proof: Vec<u8>,
}
impl VerifiedCpuOutput {
    pub(crate) fn into_encoded(self) -> (Vec<u8>, Vec<u8>) {
        (self.statement, self.proof)
    }
}
pub(crate) struct CpuGenerationPlan {
    expected: usize,
    runtime: Requirements,
    terminal: Requirements,
    operation_minimum: u64,
    verifier_minimum: u64,
    shared_minimum: u64,
}
pub(crate) struct OwnedCpuGeneration {
    // Drop private workspace before any original reservation on every exit.
    owner: Option<Generator>,
    context: [u8; 32],
    plan: CpuGenerationPlan,
    ledger: Ledger,
    runtime: Option<Reservation>,
    terminal: Option<Reservation>,
    totals: CpuTotals,
    started: Instant,
    failed: bool,
}
impl CpuGenerationPlan {
    pub(crate) fn new(
        expected: usize,
        census: native::declared_footprint::DeclaredNativeFootprint,
    ) -> GenerationResult<Self> {
        if cfg!(debug_assertions)
            || !matches!(expected, 3 | 4)
            || cfg!(any(
                feature = "native-generation-oracle",
                feature = "native-spend-oracle"
            ))
        {
            return Err(GenerationError::Authority);
        }
        let frames = [
            size_of::<Self>(),
            size_of::<OwnedCpuGeneration>(),
            size_of::<Generator>(),
            size_of::<Output>(),
            size_of::<VerifiedCpuOutput>(),
            size_of::<CpuSpendSummary>(),
            size_of::<CpuTotals>(),
            size_of::<Configuration>(),
            size_of::<Statistics>(),
            size_of::<Result<Output, native::cpu_generation::Error>>(),
            size_of::<Instant>(),
            size_of::<[&Reservation; 4]>(),
            size_of::<GenerationResult<(VerifiedCpuOutput, CpuSpendSummary)>>(),
        ]
        .into_iter()
        .try_fold(0usize, |a, b| {
            a.checked_add(b).ok_or(GenerationError::Overflow)
        })?
        .checked_mul(8)
        .ok_or(GenerationError::Overflow)?;
        let bytes = Generator::allocation_bytes()
            .map_err(|_| GenerationError::Resource)?
            .checked_add(frames)
            .ok_or(GenerationError::Overflow)?;
        let runtime = Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: bytes as u64,
                device: 0,
            },
        );
        let terminal = memory::terminal_requirements()?;
        Ok(Self {
            expected,
            runtime,
            terminal,
            operation_minimum: census
                .fixture_bytes()
                .checked_add(census.cpu_generation_frames())
                .ok_or(GenerationError::Overflow)?,
            verifier_minimum: census.verifier_bytes(),
            shared_minimum: census.shared_static_bytes(),
        })
    }
    pub(crate) fn total_requirements(&self) -> GenerationResult<Requirements> {
        memory::combine(self.runtime, self.terminal)
    }
    pub(crate) fn start(
        self,
        mut original: Reservation,
        ledger: &Ledger,
        seed: [u8; 32],
        context: [u8; 32],
    ) -> GenerationResult<OwnedCpuGeneration> {
        if !original.belongs_to(ledger) || original.requirements() != self.total_requirements()? {
            return Err(GenerationError::Authority);
        }
        let runtime = original
            .split(self.runtime)
            .map_err(|_| GenerationError::Resource)?;
        let run_id = NEXT_RUN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
            .map_err(|_| GenerationError::Overflow)?;
        let started = Instant::now();
        let owner = Generator::new(seed, context, Configuration::default())
            .map_err(|_| GenerationError::Startup)?;
        Ok(OwnedCpuGeneration {
            owner: Some(owner),
            context,
            plan: self,
            ledger: ledger.clone(),
            runtime: Some(runtime),
            terminal: Some(original),
            totals: CpuTotals {
                run_id,
                ..Default::default()
            },
            started,
            failed: false,
        })
    }
}
impl OwnedCpuGeneration {
    pub(crate) fn create_spend(
        &mut self,
        index: u64,
        amounts: FixtureAmounts,
        operation_original: &Reservation,
        verifier_original: &Reservation,
        shared_original: &Reservation,
        output_original: &Reservation,
    ) -> GenerationResult<(VerifiedCpuOutput, CpuSpendSummary)> {
        if self.failed
            || self.totals.verified >= self.plan.expected as u64
            || !output_original.belongs_to(&self.ledger)
            || !operation_original.belongs_to(&self.ledger)
            || !verifier_original.belongs_to(&self.ledger)
            || !shared_original.belongs_to(&self.ledger)
            || operation_original
                .requirements()
                .get(Category::PhaseScratch)
                .host
                < self.plan.operation_minimum
            || verifier_original
                .requirements()
                .get(Category::IndependentVerifier)
                .host
                < self.plan.verifier_minimum
            || shared_original
                .requirements()
                .get(Category::RegisteredMetadata)
                .host
                < self.plan.shared_minimum
            || output_original
                .requirements()
                .get(Category::NativeProof)
                .host
                < (crate::native_packet::STATEMENT_BYTES + crate::native_packet::PROOF_BYTES) as u64
        {
            self.failed = true;
            return Err(GenerationError::Authority);
        }
        self.failed = true;
        let started = Instant::now();
        let output = self
            .owner
            .as_mut()
            .ok_or(GenerationError::Authority)?
            .generate(index, amounts)
            .map_err(|_| GenerationError::NativeSpend)?;
        let verification = Instant::now();
        if !native::verify(&self.context, &output.statement, &output.proof)
            .map_err(|_| GenerationError::Output)?
        {
            return Err(GenerationError::Output);
        }
        let verification_ns = verification.elapsed().as_nanos();
        let summary = CpuSpendSummary {
            run_id: self.totals.run_id,
            ordinal: self.totals.verified as usize,
            elapsed_ns: started.elapsed().as_nanos(),
            generation_ns: output.generation_ns,
            verification_ns,
            statistics: output.statistics,
        };
        self.totals.verified += 1;
        self.totals.spend_ns += output.statistics.spend_ns as u128;
        self.totals.verification_ns += verification_ns;
        self.totals.attempts += output.statistics.attempts;
        self.totals.random_calls += output.statistics.random_calls;
        self.totals.random_blocks += output.statistics.random_blocks;
        self.totals.proposals += output.statistics.proposals;
        self.totals.parameter_cache_hits += output.statistics.parameter_cache_hits;
        report_transport::emit(b"owned_generation_cpu_spend ", &summary)
            .map_err(|_| GenerationError::Report)?;
        self.failed = false;
        Ok((
            VerifiedCpuOutput {
                statement: output.statement,
                proof: output.proof,
            },
            summary,
        ))
    }
    pub(crate) fn finish(mut self) -> GenerationResult<NativeGenerationTerminal> {
        if self.failed || self.totals.verified != self.plan.expected as u64 {
            return Err(GenerationError::Completion);
        }
        // Consume the actual owner before releasing its original reservation.
        drop(self.owner.take());
        drop(self.runtime.take());
        self.totals.whole_stage_ns = self.started.elapsed().as_nanos();
        self.totals.cleanup_complete = true;
        let record = TerminalRecord {
            schema: "ringct-cpu-generation-terminal-v1",
            session_id: None,
            cpu_run_id: Some(self.totals.run_id),
            session: None,
            stark_proofs: 0,
            registrations: 0,
            operations: NativeGenerationTotals {
                cpu: Some(self.totals),
                spends: self.totals.verified,
                seconds: self.totals.whole_stage_ns as f64 / 1e9,
                managed_peak_bytes: 0,
                witness_completed_calls: 0,
                witness_device_calls: 0,
                witness_device_ns: 0,
            },
        };
        report_transport::emit(b"owned_generation_terminal ", &record)
            .map_err(|_| GenerationError::Report)?;
        Ok(NativeGenerationTerminal {
            record,
            ledger: self.ledger.clone(),
            original: self.terminal.take().ok_or(GenerationError::Authority)?,
        })
    }
}

#[cfg(all(
    test,
    not(feature = "native-spend-oracle"),
    not(feature = "native-generation-oracle")
))]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    #[test]
    fn cpu_dispatch_requires_original_native_scratch_and_shared_claims() {
        if cfg!(debug_assertions) {
            return;
        }
        let ledger = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 8 << 30,
        });
        let census = native::declared_footprint::DeclaredNativeFootprint::reviewed().unwrap();
        let plan = CpuGenerationPlan::new(3, census).unwrap();
        let original = ledger
            .admit_phase(plan.total_requirements().unwrap())
            .unwrap();
        let mut owner = plan.start(original, &ledger, [17; 32], [34; 32]).unwrap();
        let output = ledger
            .reserve(
                Category::NativeProof,
                Bytes {
                    host: (crate::native_packet::STATEMENT_BYTES
                        + crate::native_packet::PROOF_BYTES) as u64,
                    device: 0,
                },
            )
            .unwrap();
        let short = ledger
            .reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 })
            .unwrap();
        assert!(owner
            .create_spend(
                0,
                FixtureAmounts {
                    input: [7, 11],
                    output: [5, 13]
                },
                &short,
                &short,
                &short,
                &output
            )
            .is_err());
        assert!(owner.finish().is_err());
        drop(output);
        drop(short);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    #[test]
    fn premature_cpu_terminal_releases_workspace_without_minting_completion() {
        if cfg!(debug_assertions) {
            return;
        }
        let ledger = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 8 << 30,
        });
        let plan = CpuGenerationPlan::new(
            3,
            native::declared_footprint::DeclaredNativeFootprint::reviewed().unwrap(),
        )
        .unwrap();
        let original = ledger
            .admit_phase(plan.total_requirements().unwrap())
            .unwrap();
        let owner = plan.start(original, &ledger, [17; 32], [34; 32]).unwrap();
        assert!(owner.finish().is_err());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
