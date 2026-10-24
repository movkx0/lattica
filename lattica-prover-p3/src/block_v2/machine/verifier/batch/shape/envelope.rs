//! Exhaustive finite public-height domain, not a sampled cap/height maximum.
use super::{
    verifier_core_bound, CompileError, ConstructionLimits, OperationCounts, PlanningStorage,
    RegisteredChildShape,
};
use crate::block_v2::profile;

/// Metadata for a single fresh-input registered verifier core at every allowed
/// height from 8 through `maximum_child_height`. Different operation maxima may
/// come from different heights; keeping them separately is conservative.
/// This is neither a proof/registration authority nor complete workflow closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierHeightEnvelope {
    pub public_values: usize,
    pub maximum_child_height: usize,
    pub heights_enumerated: usize,
    pub operations: OperationCounts,
    pub wire_upper_bound: usize,
    pub input_values_upper_bound: usize,
    /// Planner observation only, never a concrete compiler memory admission.
    pub planner_requested_program_bytes_peak: usize,
    pub planning_storage: PlanningStorage,
}

/// Check the entire power-of-two child-height domain before returning any
/// envelope. The caller supplies its existing admitted row ceiling; this API
/// does not raise it or assume the compiler is monotone in log(height).
///
/// One template/program exists at a time. The largest public storage shape is
/// preflighted before the first compilation, then each individual compile also
/// enforces its limits. Any refused height discards the partial accumulator and
/// returns an error. No proof execution, registration, callback or retry occurs.
pub fn verifier_height_envelope(
    public_values: usize,
    maximum_child_height: usize,
    construction: ConstructionLimits,
    auxiliary_host_allowance: usize,
) -> Result<VerifierHeightEnvelope, CompileError> {
    // Validate height before ilog2 or shifting. Source MachineAir permits the
    // complete8..=2^24 domain; an enclosing execution profile may be narrower.
    if !(8..=1 << 24).contains(&maximum_child_height) || !maximum_child_height.is_power_of_two() {
        return Err(CompileError::Shape("registered height envelope domain"));
    }
    let shape = |height: usize| RegisteredChildShape {
        public_values,
        height,
        preprocessing_cap_roots: 1
            << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT),
    };
    let planning_storage =
        PlanningStorage::for_children(0, &[shape(maximum_child_height)], construction)?;
    if planning_storage.auxiliary_peak_bytes > auxiliary_host_allowance {
        return Err(CompileError::ResourceAdmission(
            "registered height envelope auxiliary allowance",
        ));
    }
    let mut envelope = VerifierHeightEnvelope {
        public_values,
        maximum_child_height,
        heights_enumerated: 0,
        operations: OperationCounts::default(),
        wire_upper_bound: 0,
        input_values_upper_bound: 0,
        planner_requested_program_bytes_peak: 0,
        planning_storage,
    };
    for log_height in 3..=maximum_child_height.ilog2() {
        let bound = verifier_core_bound(
            0,
            &[shape(1 << log_height)],
            construction,
            auxiliary_host_allowance,
        )?;
        envelope.operations.scalar = envelope.operations.scalar.max(bound.operations.scalar);
        envelope.operations.cubic = envelope.operations.cubic.max(bound.operations.cubic);
        envelope.operations.poseidon = envelope.operations.poseidon.max(bound.operations.poseidon);
        envelope.wire_upper_bound = envelope.wire_upper_bound.max(bound.wire_upper_bound);
        envelope.input_values_upper_bound = envelope
            .input_values_upper_bound
            .max(bound.input_values_upper_bound);
        envelope.planner_requested_program_bytes_peak = envelope
            .planner_requested_program_bytes_peak
            .max(bound.planner_requested_program_bytes_peak);
        // Source storage formula is nondecreasing in degree (more FRI layers
        // and path elements), with the same trusted public/AIR widths. Never
        // silently use that fact if a future formula violates it.
        if bound.storage.auxiliary_peak_bytes > planning_storage.auxiliary_peak_bytes
            || bound.storage.template_retained_bytes > planning_storage.template_retained_bytes
        {
            return Err(CompileError::Shape(
                "registered height envelope storage drift",
            ));
        }
        envelope.heights_enumerated += 1;
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::machine::program::MAX_WIRES;

    fn limits() -> ConstructionLimits {
        ConstructionLimits {
            max_requested_program_bytes: 2 << 30,
            max_wires: MAX_WIRES,
            max_input_values: 1 << 20,
        }
    }

    #[test]
    fn entire_domain_and_auxiliary_reservation_are_checked_before_compilation() {
        for height in [0, 1, 7, 9, (1 << 20) + 1, 1 << 25, usize::MAX] {
            assert_eq!(
                verifier_height_envelope(28, height, limits(), 512 << 20),
                Err(CompileError::Shape("registered height envelope domain"))
            );
        }
        assert!(matches!(
            verifier_height_envelope(65, 8, limits(), 512 << 20),
            Err(CompileError::Shape(_))
        ));
        if cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
            assert_eq!(
                verifier_height_envelope(28, 1 << 20, limits(), 0),
                Err(CompileError::ResourceAdmission(
                    "registered height envelope auxiliary allowance"
                ))
            );
        }
    }

    #[test]
    #[ignore = "72 exhaustive public shapes at R4 ceiling; serialized release guard and explicit row domain required"]
    fn registered_binary_descendants_close_over_entire_configured_height_domain() {
        assert!(cfg!(all(not(debug_assertions), target_arch = "x86_64")));
        assert_eq!(
            std::env::var("LATTICA_BOUNDED_BATCH_SHAPE_QUALIFICATION").as_deref(),
            Ok("1")
        );
        let max_rows: usize = std::env::var("LATTICA_REGISTERED_CLOSURE_MAX_ROWS")
            .expect("explicit unchanged worker max_rows is required")
            .parse()
            .unwrap();
        // The screen is pinned to the accepted R4 run, not the broader core
        // MachineAir ceiling. The API above remains parameterized.
        assert_eq!(
            max_rows,
            1 << 20,
            "R4 gate must use accepted1048576-row ceiling"
        );
        let mut bounds = [OperationCounts::default(); 4];
        for (index, width) in [25, 28, 38, 46].into_iter().enumerate() {
            let envelope = verifier_height_envelope(width, max_rows, limits(), 512 << 20).unwrap();
            assert_eq!(envelope.heights_enumerated, max_rows.ilog2() as usize - 2);
            bounds[index] = envelope.operations;
            eprintln!("registered_height_envelope publics={} min_height=8 max_height={} exhaustive_heights={} scalar={} cubic={} poseidon={} wires={} inputs={} planner_requested_peak={} auxiliary_reservation={}",
                width, max_rows, envelope.heights_enumerated,
                envelope.operations.scalar, envelope.operations.cubic, envelope.operations.poseidon,
                envelope.wire_upper_bound, envelope.input_values_upper_bound,
                envelope.planner_requested_program_bytes_peak, envelope.planning_storage.auxiliary_peak_bytes);
        }
        // See REGISTERED_DESCENDANTS.md for every binding operation. Adding
        // independent cores is conservative: fresh proof/public inputs remain
        // distinct and shared constant/hash interning only removes work.
        for (name, public, left, right, scalar, poseidon) in [
            ("component-merge", 46, 3, 3, 1419, 0),
            ("graph-merge", 28, 1, 1, 1375, 0),
            ("batch-graph-graph", 25, 1, 1, 136, 8),
            ("batch-aggregate-graph", 25, 0, 1, 132, 6),
            ("batch-aggregate-aggregate", 25, 0, 0, 128, 4),
        ] {
            let counts = bounds[left]
                .with_overhead(bounds[right])
                .unwrap()
                .with_overhead(OperationCounts {
                    scalar,
                    cubic: 0,
                    poseidon,
                })
                .unwrap();
            let active = counts.active_rows(public).unwrap();
            let padded = counts.padded_rows(public).unwrap();
            eprintln!("registered_binary_descendant kind={name} active_rows={active} padded_rows={padded} configured_ceiling={max_rows} native_consumers_closed=false ownership_admitted=false");
            assert!(
                padded <= max_rows,
                "registered descendant {name} fails configured height closure"
            );
        }
        // N3: graph+graph -> aggregate+graph. N4: two graph+graph nodes ->
        // aggregate+aggregate. No fan-in3/4 verifier is invented for either case.
        // Width38 is a producer-branch child; its consuming leaf also needs a
        // native Sparse verifier and graph SourceBinding, deliberately pending.
    }
}
