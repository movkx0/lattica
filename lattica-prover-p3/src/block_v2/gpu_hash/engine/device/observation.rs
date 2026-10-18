//! Explicit, per-attempt execution receipts. No ambient backend or run is stored
//! in matrices, immutable programs, or worker messages.
use super::super::Engine;
use super::{DeviceSession, Session, SessionStats};
use crate::block_v2::compute;
use crate::proving::{Backend, Run, Stage};
use std::sync::atomic::Ordering;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counter {
    calls: u64,
    device_ns: u128,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ArithmeticStats {
    counters: [Counter; Stage::ARITHMETIC.len()],
    errors: u64,
}

const PIPELINE: &[Stage] = &[
    Stage::Preprocessing,
    Stage::Lookup,
    Stage::Transform,
    Stage::Quotient,
    Stage::Hiding,
    Stage::Commitment,
    Stage::Opening,
    Stage::FriFold,
    Stage::FriQuery,
    Stage::FinalPolynomial,
];

// A single AIR without lookups must not claim a lookup receipt or require a
// fictitious operation merely to satisfy the registered-prover inventory.
const SINGLE_AIR_PIPELINE: &[Stage] = &[
    Stage::Preprocessing,
    Stage::Transform,
    Stage::Quotient,
    Stage::Hiding,
    Stage::Commitment,
    Stage::Opening,
    Stage::FriFold,
    Stage::FriQuery,
    Stage::FinalPolynomial,
];

fn index(stage: Stage) -> usize {
    Stage::ARITHMETIC
        .iter()
        .position(|&s| s == stage)
        .expect("device receipt requires an arithmetic stage")
}

impl SessionStats {
    pub(super) fn record_execution(&mut self, stage: Stage, calls: u64, device_ns: u128) {
        let counter = &mut self.arithmetic.counters[index(stage)];
        match (
            counter.calls.checked_add(calls),
            counter.device_ns.checked_add(device_ns),
        ) {
            (Some(calls), Some(device_ns)) => *counter = Counter { calls, device_ns },
            _ => self.arithmetic.errors = self.arithmetic.errors.saturating_add(1),
        }
    }
}

impl Session {
    #[cfg(all(test, feature = "gpu-tuning"))]
    pub(super) fn test_receipt(&self, stage: Stage) -> (u64, u128, u64) {
        let stats = self.stats.lock().unwrap();
        let counter = stats.arithmetic.counters[index(stage)];
        (counter.calls, counter.device_ns, stats.arithmetic.errors)
    }

    pub(super) fn record_execution(&self, stage: Stage, calls: u64, device_ns: u128) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.record_execution(stage, calls, device_ns);
        }
    }

    pub(super) fn record_event(
        &self,
        engine: &mut Engine,
        stage: Stage,
        label: &'static str,
        event: &compute::Event,
    ) -> Result<u128, String> {
        let ns = engine.timeline.record(label, event).map_err(|error| {
            self.observation_failed();
            error
        })?;
        self.record_execution(stage, 1, ns);
        Ok(ns)
    }

    pub(super) fn observation_failed(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.arithmetic.errors = stats.arithmetic.errors.saturating_add(1);
        }
    }
}

impl DeviceSession {
    pub(super) fn record_event(
        &self,
        engine: &mut Engine,
        stage: Stage,
        label: &'static str,
        event: &compute::Event,
    ) -> Result<u128, String> {
        self.session.record_event(engine, stage, label, event)
    }

    /// Attribute NTT and hash event intervals while the engine is exclusively
    /// borrowed. These counters exclude transfer/wall time and have no ambient
    /// owner. Preserve completed intervals on errors and resume original panics.
    pub(in crate::block_v2::gpu_hash::engine) fn observe_engine<T>(
        &self,
        engine: &mut Engine,
        body: impl FnOnce(&mut Engine) -> Result<T, String>,
    ) -> Result<T, String> {
        let before = [
            engine.stats.lde_transform_ns,
            engine.stats.leaf_kernel_ns,
            engine.stats.compress_kernel_ns,
        ];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(engine)));
        let after = [
            engine.stats.lde_transform_ns,
            engine.stats.leaf_kernel_ns,
            engine.stats.compress_kernel_ns,
        ];
        let delta: [Option<u128>; 3] = std::array::from_fn(|i| after[i].checked_sub(before[i]));
        if let [Some(transform), Some(leaf), Some(compress)] = delta {
            if let Some(hash) = leaf.checked_add(compress) {
                for (stage, ns) in [(Stage::Transform, transform), (Stage::Commitment, hash)] {
                    if ns != 0 {
                        self.record_execution(stage, u64::from(matches!(result, Ok(Ok(_)))), ns);
                    }
                }
            } else {
                self.session.observation_failed();
            }
        } else {
            self.session.observation_failed();
        }
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    pub(in crate::block_v2::gpu_hash::engine) fn record_execution(
        &self,
        stage: Stage,
        calls: u64,
        device_ns: u128,
    ) {
        self.session.record_execution(stage, calls, device_ns);
    }

    pub(crate) fn observe_execution<'a>(
        &self,
        run: &'a Run,
    ) -> Result<ExecutionObservation<'a>, String> {
        ExecutionObservation::new(run, self.clone(), PIPELINE)
    }

    pub(crate) fn observe_witness<'a>(
        &self,
        run: &'a Run,
    ) -> Result<ExecutionObservation<'a>, String> {
        ExecutionObservation::new(run, self.clone(), &[Stage::WitnessTrace])
    }

    pub(crate) fn observe_single_air<'a>(
        &self,
        run: &'a Run,
    ) -> Result<ExecutionObservation<'a>, String> {
        ExecutionObservation::new(run, self.clone(), SINGLE_AIR_PIPELINE)
    }

    /// Observe a standalone FRI operation, including its final interpolation
    /// only when the final polynomial has more than one coefficient.
    pub(crate) fn observe_fri<'a>(
        &self,
        run: &'a Run,
        interpolates: bool,
    ) -> Result<ExecutionObservation<'a>, String> {
        let stages: &'static [Stage] = if interpolates {
            &[
                Stage::Transform,
                Stage::Commitment,
                Stage::FriFold,
                Stage::FriQuery,
                Stage::FinalPolynomial,
            ]
        } else {
            &[
                Stage::Commitment,
                Stage::FriFold,
                Stage::FriQuery,
                Stage::FinalPolynomial,
            ]
        };
        ExecutionObservation::new(run, self.clone(), stages)
    }

    /// Prefix transformations and evaluation/reduction for an owned PCS opening.
    /// This can accompany a constant-final-polynomial FRI observer without
    /// overlapping its exclusive receipt stages.
    pub(crate) fn observe_opening<'a>(
        &self,
        run: &'a Run,
    ) -> Result<ExecutionObservation<'a>, String> {
        ExecutionObservation::new(run, self.clone(), &[Stage::Transform, Stage::Opening])
    }
}

pub(crate) struct ExecutionObservation<'a> {
    run: &'a Run,
    session: DeviceSession,
    stages: &'static [Stage],
    before: ArithmeticStats,
    mask: u32,
}

impl<'a> ExecutionObservation<'a> {
    fn new(run: &'a Run, session: DeviceSession, stages: &'static [Stage]) -> Result<Self, String> {
        for &stage in stages {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        let mask = stages
            .iter()
            .fold(0u32, |mask, &stage| mask | (1 << index(stage)));
        session
            .session
            .observed_stages
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active & mask == 0).then_some(active | mask)
            })
            .map_err(|_| "overlapping GPU execution observations")?;
        let Some(before) = session.try_stats().map(|stats| stats.arithmetic) else {
            session
                .session
                .observed_stages
                .fetch_and(!mask, Ordering::Release);
            return Err("GPU execution statistics poisoned".into());
        };
        Ok(Self {
            run,
            session,
            stages,
            before,
            mask,
        })
    }
}

impl Drop for ExecutionObservation<'_> {
    fn drop(&mut self) {
        let after = self.session.try_stats().map(|s| s.arithmetic);
        self.session
            .session
            .observed_stages
            .fetch_and(!self.mask, Ordering::Release);
        if let Some(after) = after {
            record_delta(self.run, &self.before, &after, self.stages);
        } else {
            self.run.observation_failed();
        }
    }
}

fn record_delta(run: &Run, before: &ArithmeticStats, after: &ArithmeticStats, stages: &[Stage]) {
    if after.errors != before.errors {
        run.observation_failed();
    }
    for &stage in stages {
        let before = before.counters[index(stage)];
        let after = after.counters[index(stage)];
        let (Some(calls), Some(ns)) = (
            after.calls.checked_sub(before.calls),
            after.device_ns.checked_sub(before.device_ns),
        ) else {
            run.observation_failed();
            continue;
        };
        if run
            .observe_device(stage, Backend::OpenCl, calls, ns)
            .is_err()
        {
            run.observation_failed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::{Capabilities, Profile, Request};

    #[test]
    fn executor_counter_deltas_reject_overflow_and_rollback() {
        let run = Run::new(
            "counter_test",
            Request::compatible(),
            Capabilities::cpu(Profile::BlockV2Cubic, true, true),
        )
        .unwrap();
        let mut stats = SessionStats::default();
        let before = stats.arithmetic;
        stats.record_execution(Stage::Transform, 2, 400);
        record_delta(&run, &before, &stats.arithmetic, &[Stage::Transform]);
        let before = stats.arithmetic;
        stats.record_execution(Stage::Transform, u64::MAX, 1);
        record_delta(&run, &before, &stats.arithmetic, &[Stage::Transform]);
        record_delta(
            &run,
            &before,
            &ArithmeticStats::default(),
            &[Stage::Transform],
        );
        let report = run.finish(true).unwrap();
        assert_eq!(report.observation_errors, 2);
        assert!(!report.stage_coverage_complete);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].device_calls, 2);
        assert_eq!(report.observations[0].device_ns, 400);
    }

    #[test]
    #[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
    fn gpu_observations_are_exclusive_isolated_and_survive_unwind() {
        use super::super::{Extension, MatrixSpec, RowOrder};
        use crate::block_v2::gpu_hash;
        let _shutdown = gpu_hash::TestShutdownGuard;
        gpu_hash::initialize_quotient_test_engine(gpu_hash::Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 16 << 20,
            staging_bytes: 64 << 10,
        })
        .unwrap();
        let make_run = || {
            Run::new(
                "gpu_observation_test",
                Request::compatible(),
                Capabilities::cpu(Profile::BlockV2Cubic, true, true),
            )
            .unwrap()
        };
        let session = DeviceSession::new().unwrap();
        let foreign = DeviceSession::new().unwrap();
        let spec = MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::BitReversed, 1).unwrap();
        let input = session.upload(spec, &vec![0; spec.words()]).unwrap();
        let other = foreign.upload(spec, &vec![0; spec.words()]).unwrap();
        let run = make_run();
        let before = session.stats();
        assert!(session.final_polynomial(&input, usize::MAX).is_err());
        assert!(session.final_polynomial(&input, 3).is_err());
        assert!(session.final_polynomial(&other, 4).is_err());
        assert_eq!(session.stats(), before);
        let observation = session.observe_execution(&run).unwrap();
        assert!(session.observe_execution(&run).is_err());
        assert_eq!(session.stats(), before);
        drop(foreign.fold_cubic(&other, [7, 0, 0]).unwrap());
        drop(observation);
        assert!(run.finish(true).unwrap().observations.is_empty());
        let failed = make_run();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _observation = session.observe_execution(&failed).unwrap();
            drop(session.fold_cubic(&input, [7, 0, 0]).unwrap());
            panic!("later proof stage failed");
        }));
        assert!(outcome.is_err());
        let report = failed.finish(false).unwrap();
        assert!(!report.succeeded && !report.stage_coverage_complete);
        assert_eq!(report.observation_errors, 0);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].stage, Stage::FriFold);
        assert_eq!(report.observations[0].device_calls, 1);
        assert!(report.observations[0].device_ns > 0);
        let run = make_run();
        drop(session.observe_execution(&run).unwrap());
        assert!(run.finish(true).unwrap().observations.is_empty());
        let run = make_run();
        {
            let _observation = session.observe_execution(&run).unwrap();
            assert_eq!(session.final_polynomial(&input, 4).unwrap(), [0; 3]);
        }
        let report = run.finish(true).unwrap();
        assert_eq!(report.observation_errors, 0);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].stage, Stage::FinalPolynomial);
        assert_eq!(report.observations[0].device_calls, 1);
        assert!(report.observations[0].device_ns > 0);
        drop((input, other, session, foreign));
        gpu_hash::shutdown().unwrap();
    }
}
