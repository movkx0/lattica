//! Closed host-constraint diagnostic admission. This does not generate or verify
//! a cryptographic proof, and does not admit any GPU or production workflow.
use super::{CompiledRelation, CompilerCapacityProfile, CompilerLimits, Error, Summary, Val};
use lattica_prover_p3::block_v2::machine::{MachineAir, WIDTH};
use serde::Serialize;

const HOST_MAX: u64 = 32 << 30;

/// Independently selected host diagnostic. Neither backend verifies a proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum EvaluationBackend {
    #[default]
    #[serde(rename = "trace")]
    Trace,
    #[serde(rename = "constraints-only")]
    ConstraintsOnly,
}

impl EvaluationBackend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::ConstraintsOnly => "constraints-only",
        }
    }
}

impl core::str::FromStr for EvaluationBackend {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "trace" => Ok(Self::Trace),
            "constraints-only" => Ok(Self::ConstraintsOnly),
            _ => Err("evaluation backend must be trace or constraints-only"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EvaluationFootprint {
    pub backend: EvaluationBackend,
    pub selected_program_allowance_bytes: u64,
    pub retained_program_bytes: u64,
    pub retained_witness_allowance_bytes: u64,
    pub auxiliary_allowance_bytes: u64,
    pub wire_value_bytes: u64,
    pub trace_bytes: u64,
    pub required_host_bytes: u64,
    pub worker_host_byte_limit: u64,
}

/// A checked storage description bound to its exact immutable compiled owner.
/// Planning allocates no trace and grants no execution permission. The owner
/// cannot be replaced, cloned or extracted; execution still checks its allowance.
pub struct EvaluationPlan {
    relation: CompiledRelation,
    footprint: EvaluationFootprint,
}

fn byte_count(count: usize, width: usize) -> Result<u64, Error> {
    count
        .checked_mul(width)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(Error::ResourceLimit)
}

fn total_bytes(parts: &[u64]) -> Result<u64, Error> {
    let total = parts
        .iter()
        .try_fold(0_u64, |sum, &bytes| sum.checked_add(bytes))
        .ok_or(Error::ResourceLimit)?;
    usize::try_from(total).map_err(|_| Error::ResourceLimit)?;
    Ok(total)
}

// This helper is descriptive arithmetic, not admission authority. Its only
// production caller supplies geometry freshly read from its immutable owner.
fn footprint(
    backend: EvaluationBackend,
    limits: CompilerLimits,
    retained_program_bytes: usize,
    wire_count: usize,
    padded_rows: usize,
) -> Result<EvaluationFootprint, Error> {
    let canonical =
        CompilerCapacityProfile::new(limits.memory_profile, limits.wire_profile).limits();
    let retained_program_bytes =
        u64::try_from(retained_program_bytes).map_err(|_| Error::ResourceLimit)?;
    if limits != canonical
        || retained_program_bytes > limits.program_byte_limit
        || wire_count > limits.wire_limit
        || padded_rows > limits.row_limit
    {
        return Err(Error::ResourceLimit);
    }
    let wire_value_bytes = byte_count(wire_count, core::mem::size_of::<Val>())?;
    let trace_bytes = match backend {
        EvaluationBackend::Trace => byte_count(padded_rows, WIDTH)?
            .checked_mul(core::mem::size_of::<Val>() as u64)
            .ok_or(Error::ResourceLimit)?,
        EvaluationBackend::ConstraintsOnly => 0,
    };
    let required_host_bytes = total_bytes(&[
        retained_program_bytes,
        limits.witness_byte_limit,
        limits.auxiliary_byte_limit,
        wire_value_bytes,
        trace_bytes,
    ])?;
    Ok(EvaluationFootprint {
        backend,
        selected_program_allowance_bytes: limits.program_byte_limit,
        retained_program_bytes,
        retained_witness_allowance_bytes: limits.witness_byte_limit,
        auxiliary_allowance_bytes: limits.auxiliary_byte_limit,
        wire_value_bytes,
        trace_bytes,
        required_host_bytes,
        worker_host_byte_limit: HOST_MAX,
    })
}

impl CompiledRelation {
    /// A source-derived requested-storage bound, not a measured RSS peak.
    /// The returned description cannot authorize an allocation; evaluation
    /// recomputes admission from this exact immutable compiled owner.
    pub fn evaluation_footprint(&self) -> Result<EvaluationFootprint, Error> {
        self.evaluation_footprint_for_backend(EvaluationBackend::Trace)
    }

    fn evaluation_footprint_for_backend(
        &self,
        backend: EvaluationBackend,
    ) -> Result<EvaluationFootprint, Error> {
        let limits = self.summary.limits;
        let retained_program_bytes = self
            .program
            .retained_host_bytes()
            .map_err(|_| Error::ResourceLimit)?;
        if byte_count(self.witness.capacity(), core::mem::size_of::<Val>())?
            > limits.witness_byte_limit
        {
            return Err(Error::ResourceLimit);
        }
        // Both backends hold all wire values with the immutable program and
        // input witness. Trace additionally materializes its full row matrix.
        // Keep every retained capacity, the future Arc (conservatively even
        // without one), and the entire fixed witness/auxiliary allowances.
        // Geometry and compiler ceilings still apply to either backend.
        footprint(
            backend,
            limits,
            retained_program_bytes,
            self.program.wire_count(),
            self.program.height(),
        )
    }

    /// Scan retained source capacities once, then keep that description sealed
    /// with the same immutable owner through inspection and execution admission.
    pub fn plan_evaluation(self) -> Result<EvaluationPlan, Error> {
        self.plan_evaluation_with_backend(EvaluationBackend::Trace)
    }

    /// Seal the diagnostic choice and its complete live footprint with this
    /// exact owner. Caller-edited descriptions cannot switch the backend later.
    pub fn plan_evaluation_with_backend(
        self,
        backend: EvaluationBackend,
    ) -> Result<EvaluationPlan, Error> {
        let footprint = self.evaluation_footprint_for_backend(backend)?;
        Ok(EvaluationPlan {
            relation: self,
            footprint,
        })
    }

    /// Execute every compiled constraint only after admitting its whole live
    /// logical footprint within the unchanged worker host allowance. The caller
    /// separately accounts for enclosing fixture/process/allocator storage.
    pub fn evaluate_with_host_allowance(
        self,
        host_allowance: u64,
    ) -> Result<(Summary, EvaluationFootprint), Error> {
        self.plan_evaluation()?
            .evaluate_with_host_allowance(host_allowance)
    }
}

impl EvaluationPlan {
    /// Descriptive copy only; modifying it cannot alter this sealed plan.
    pub fn footprint(&self) -> EvaluationFootprint {
        self.footprint
    }

    /// Admit this exact immutable owner before creating any trace or Arc.
    pub fn evaluate_with_host_allowance(
        self,
        host_allowance: u64,
    ) -> Result<(Summary, EvaluationFootprint), Error> {
        let footprint = self.footprint;
        if host_allowance > HOST_MAX || footprint.required_host_bytes > host_allowance {
            return Err(Error::ResourceLimit);
        }
        let CompiledRelation {
            program,
            witness,
            public,
            summary,
        } = self.relation;
        // Every allocation follows whole-live admission. Both temporary wire
        // storage and the optional full trace are destroyed before returning.
        match footprint.backend {
            EvaluationBackend::Trace => MachineAir::new(program).trace(&public, &witness).map(drop),
            EvaluationBackend::ConstraintsOnly => program.check_host_constraints(&public, &witness),
        }
        .map_err(|error| Error::Backend(format!("{error:?}")))?;
        Ok((summary, footprint))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CompilerMemoryProfile, ProgramBuilder, REPRESENTATION};
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    fn tiny_relation(valid: bool) -> CompiledRelation {
        let mut builder = ProgramBuilder::new(4).unwrap();
        let input = builder.input();
        let public = builder.public(0).unwrap();
        builder.assert_equal(input, public);
        let program = builder.finish(None).unwrap();
        let summary = Summary {
            representation: REPRESENTATION,
            limits: CompilerCapacityProfile::default().limits(),
            host_allowance_bytes: 400 << 20,
            active_rows: program.active_rows(),
            padded_rows: program.height(),
            wires: program.wire_count(),
            witness_values: 1,
            compiler_requested_bytes_peak: 0,
            compiler_packed_admitted_bytes_peak: program.construction_host_bytes(),
            deferred_crypto_obligations: 0,
            cryptographic_proof_available: false,
        };
        CompiledRelation {
            program,
            witness: vec![Val::from_u64(if valid { 7 } else { 8 })],
            public: [Val::from_u64(7), Val::ZERO, Val::ZERO, Val::ZERO],
            summary,
        }
    }

    #[test]
    fn evaluation_admits_exact_live_bound_and_rejects_short_or_oversized_allowance() {
        let relation = tiny_relation(true);
        let footprint = relation.evaluation_footprint().unwrap();
        assert_eq!(footprint.selected_program_allowance_bytes, 256 << 20);
        assert_eq!(
            footprint.retained_program_bytes,
            relation.program.retained_host_bytes().unwrap() as u64
        );
        assert!(footprint.retained_program_bytes < footprint.selected_program_allowance_bytes);
        assert_eq!(
            footprint.required_host_bytes,
            footprint.retained_program_bytes
                + (144 << 20)
                + footprint.wire_value_bytes
                + footprint.trace_bytes
        );
        assert!(matches!(
            relation.evaluate_with_host_allowance(footprint.required_host_bytes - 1),
            Err(Error::ResourceLimit)
        ));
        assert!(matches!(
            tiny_relation(true).evaluate_with_host_allowance(HOST_MAX + 1),
            Err(Error::ResourceLimit)
        ));
        let (summary, admitted) = tiny_relation(true)
            .evaluate_with_host_allowance(footprint.required_host_bytes)
            .unwrap();
        assert_eq!(admitted, footprint);
        assert!(!summary.cryptographic_proof_available);
    }

    #[test]
    fn evaluation_rejects_an_unsatisfied_witness_after_admission() {
        assert!(matches!(
            tiny_relation(false).evaluate_with_host_allowance(HOST_MAX),
            Err(Error::Backend(_))
        ));
    }

    #[test]
    fn compiler_allowance_remains_a_separate_ceiling_not_retained_storage() {
        let small = tiny_relation(true).evaluation_footprint().unwrap();
        let mut larger_allowance = tiny_relation(true);
        larger_allowance.summary.limits = CompilerMemoryProfile::Program24GiB.limits();
        larger_allowance.summary.host_allowance_bytes =
            larger_allowance.summary.limits.required_host_bytes;
        let large = larger_allowance.evaluation_footprint().unwrap();
        assert_eq!(large.selected_program_allowance_bytes, 24 << 30);
        assert_eq!(small.retained_program_bytes, large.retained_program_bytes);
        assert_eq!(small.required_host_bytes, large.required_host_bytes);
        let limits = CompilerCapacityProfile::default().limits();
        assert!(matches!(
            footprint(
                EvaluationBackend::Trace,
                limits,
                limits.program_byte_limit as usize + 1,
                4,
                8
            ),
            Err(Error::ResourceLimit)
        ));
    }

    #[test]
    fn altered_descriptive_limits_and_overflow_cannot_grant_storage() {
        for field in 0..4 {
            let mut relation = tiny_relation(true);
            match field {
                0 => relation.summary.limits.program_byte_limit = u64::MAX,
                1 => relation.summary.limits.witness_byte_limit = 0,
                2 => relation.summary.limits.auxiliary_byte_limit = 0,
                _ => relation.summary.limits.worker_host_byte_limit = u64::MAX,
            }
            assert!(matches!(
                relation.evaluation_footprint(),
                Err(Error::ResourceLimit)
            ));
        }
        assert!(matches!(
            byte_count(usize::MAX, 2),
            Err(Error::ResourceLimit)
        ));
        assert!(matches!(
            total_bytes(&[u64::MAX, 1]),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(total_bytes(&[0, HOST_MAX]), Ok(HOST_MAX));
    }

    #[test]
    fn stale_summary_or_foreign_footprint_cannot_replace_actual_owner_geometry() {
        let small = tiny_relation(true).evaluation_footprint().unwrap();
        let mut relation = tiny_relation(true);
        let mut builder = ProgramBuilder::new(4).unwrap();
        let public = builder.public(0).unwrap();
        for _ in 0..64 {
            let input = builder.input();
            builder.assert_equal(input, public);
        }
        relation.program = builder.finish(Some(64)).unwrap();
        relation.witness = vec![Val::from_u64(7); 64];
        // Keep the small owner's descriptive counters. They cannot determine
        // allocation admission; the private Program and witness determine it.
        let plan = relation.plan_evaluation().unwrap();
        let own = plan.footprint();
        assert!(own.retained_program_bytes > small.retained_program_bytes);
        assert!(own.wire_value_bytes > small.wire_value_bytes);
        assert!(own.trace_bytes > small.trace_bytes);
        assert!(own.required_host_bytes > small.required_host_bytes);
        let mut reported = plan.footprint();
        reported.retained_program_bytes = small.retained_program_bytes;
        reported.required_host_bytes = small.required_host_bytes;
        assert_ne!(reported, own);
        assert_eq!(plan.footprint(), own);
        assert!(matches!(
            plan.evaluate_with_host_allowance(reported.required_host_bytes),
            Err(Error::ResourceLimit)
        ));
    }

    #[test]
    fn constraints_only_admission_removes_only_the_full_trace_term() {
        assert_eq!(EvaluationBackend::default(), EvaluationBackend::Trace);
        let trace = tiny_relation(true).evaluation_footprint().unwrap();
        let plan = tiny_relation(true)
            .plan_evaluation_with_backend(EvaluationBackend::ConstraintsOnly)
            .unwrap();
        let small = plan.footprint();
        assert_eq!(trace.backend, EvaluationBackend::Trace);
        assert_eq!(small.backend, EvaluationBackend::ConstraintsOnly);
        assert_eq!(small.trace_bytes, 0);
        assert!(trace.trace_bytes > 0);
        assert_eq!(small.retained_program_bytes, trace.retained_program_bytes);
        assert_eq!(
            small.selected_program_allowance_bytes,
            trace.selected_program_allowance_bytes
        );
        assert_eq!(small.retained_witness_allowance_bytes, 128 << 20);
        assert_eq!(small.auxiliary_allowance_bytes, 16 << 20);
        assert_eq!(small.wire_value_bytes, trace.wire_value_bytes);
        assert_eq!(
            small.required_host_bytes,
            trace.required_host_bytes - trace.trace_bytes
        );
        assert_eq!(small.worker_host_byte_limit, HOST_MAX);
        assert!(matches!(
            plan.evaluate_with_host_allowance(small.required_host_bytes - 1),
            Err(Error::ResourceLimit)
        ));
        let (summary, admitted) = tiny_relation(true)
            .plan_evaluation_with_backend(EvaluationBackend::ConstraintsOnly)
            .unwrap()
            .evaluate_with_host_allowance(small.required_host_bytes)
            .unwrap();
        assert_eq!(admitted, small);
        assert!(!summary.cryptographic_proof_available);
        assert!(matches!(
            tiny_relation(true)
                .plan_evaluation_with_backend(EvaluationBackend::ConstraintsOnly)
                .unwrap()
                .evaluate_with_host_allowance(HOST_MAX + 1),
            Err(Error::ResourceLimit)
        ));
    }

    #[test]
    fn editing_reported_backend_cannot_switch_the_sealed_plan_or_its_admission() {
        let plan = tiny_relation(true).plan_evaluation().unwrap();
        let original = plan.footprint();
        let mut forged = original;
        forged.backend = EvaluationBackend::ConstraintsOnly;
        forged.required_host_bytes -= forged.trace_bytes;
        forged.trace_bytes = 0;
        assert_eq!(plan.footprint(), original);
        assert!(matches!(
            plan.evaluate_with_host_allowance(forged.required_host_bytes),
            Err(Error::ResourceLimit)
        ));
        let plan = tiny_relation(true)
            .plan_evaluation_with_backend(EvaluationBackend::ConstraintsOnly)
            .unwrap();
        let original = plan.footprint();
        let mut report = original;
        report.backend = EvaluationBackend::Trace;
        report.required_host_bytes = 0;
        assert_ne!(report, plan.footprint());
        assert_eq!(
            plan.evaluate_with_host_allowance(original.required_host_bytes)
                .unwrap()
                .1,
            original
        );
    }

    #[test]
    fn both_diagnostics_reject_invalid_values_and_counts_after_admission() {
        for missing_witness in [false, true] {
            let outcome = |backend| {
                let mut relation = tiny_relation(false);
                if missing_witness {
                    relation.witness.clear();
                }
                relation
                    .plan_evaluation_with_backend(backend)
                    .unwrap()
                    .evaluate_with_host_allowance(HOST_MAX)
                    .err()
                    .unwrap()
            };
            let trace = outcome(EvaluationBackend::Trace);
            assert!(matches!(trace, Error::Backend(_)));
            assert_eq!(outcome(EvaluationBackend::ConstraintsOnly), trace);
        }
    }

    #[test]
    fn omitting_trace_never_relaxes_program_wire_or_row_ceilings() {
        let limits = CompilerCapacityProfile::default().limits();
        for backend in [EvaluationBackend::Trace, EvaluationBackend::ConstraintsOnly] {
            for (retained, wires, rows) in [
                (1, limits.wire_limit + 1, 8),
                (1, 4, limits.row_limit + 1),
                (limits.program_byte_limit as usize + 1, 4, 8),
            ] {
                assert!(matches!(
                    footprint(backend, limits, retained, wires, rows),
                    Err(Error::ResourceLimit)
                ));
            }
            let mut relation = tiny_relation(true);
            relation.summary.limits.worker_host_byte_limit += 1;
            assert!(matches!(
                relation.plan_evaluation_with_backend(backend),
                Err(Error::ResourceLimit)
            ));
        }
    }

    #[test]
    fn constraints_only_executes_fresh_values_for_the_same_public_program_shape() {
        let first = tiny_relation(true);
        let mut second = tiny_relation(true);
        second.public[0] = Val::from_u64(9);
        second.witness[0] = Val::from_u64(9);
        assert!(first.program == second.program);
        for relation in [first, second] {
            let plan = relation
                .plan_evaluation_with_backend(EvaluationBackend::ConstraintsOnly)
                .unwrap();
            let footprint = plan.footprint();
            assert_eq!(
                plan.evaluate_with_host_allowance(footprint.required_host_bytes)
                    .unwrap()
                    .1,
                footprint
            );
        }
    }
}
