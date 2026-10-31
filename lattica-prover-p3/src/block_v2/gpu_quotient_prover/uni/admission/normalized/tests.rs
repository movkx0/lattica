use super::*;
use crate::{config::Challenge, joinsplit_air::JoinSplitAir};

// CPU public-metadata fixture only. This uses the maintained AIR recording,
// normalization, degree rule and compiler rather than hand-constructing a
// Normalized owner with invented degree/layout fields. No configuration, GPU
// context, witness, entropy, proof or independent-verifier work occurs here.
fn normalized_note_metadata() -> Normalized {
    let air = JoinSplitAir;
    let prepared = Prepared::new(&air, 4096, Extension::Quadratic, 24 << 30).unwrap();
    let layout = prepared.recorded.layout();
    let periodic_host_allowance = prepared.periodic_host_bytes();
    let operation_host_allowance = prepared.operation_host_allowance().unwrap();
    let constraints = prepared.recorded.normalize(Constants::cpu()).unwrap();
    let log_chunks =
        symbolic::batch_log_chunks(&air, &constraints, &[], &LogUpGadget::new(), 1).unwrap();
    let constraints = constraints.into_base_only::<Challenge>().unwrap();
    let program = Program::from_periodic_constraints(layout, &constraints).unwrap();
    prepared.shape.check(&program).unwrap();
    let mut compiled = compile::Batch::new(1, symbolic::HOST_BYTES as usize).unwrap();
    compiled
        .push(program, log_chunks, constraints.base.len())
        .unwrap();
    Normalized {
        compiled,
        periodic: prepared.periodic,
        rows: prepared.rows,
        extension: prepared.shape.extension,
        layout,
        log_chunks,
        chunks: checked_profile_chunks(log_chunks, 16).unwrap(),
        periodic_host_allowance,
        operation_host_allowance,
    }
}

#[test]
fn normalized_note_binds_all_layout_fields_and_actual_degree_before_private_work() {
    let normalized = normalized_note_metadata();
    assert_eq!(normalized.quotient_chunks(), 16);
    for wrong_profile in [2, 4, 8, 32] {
        assert_eq!(
            checked_profile_chunks(normalized.log_chunks, wrong_profile).unwrap_err(),
            "normalized wallet quotient chunks differ from admitted profile"
        );
    }
    let layout = normalized.layout;
    let configured = normalized.operation_host_allowance();
    let input = Input::Normalized(normalized);
    assert!(input.matches_layout(layout));
    assert!(input.check_operation_host_allowance(configured).is_ok());
    assert!(input
        .check_operation_host_allowance(configured - 1)
        .is_err());
    assert!(input
        .check_operation_host_allowance(configured + 1)
        .is_err());
    for field in 0..7 {
        let mut changed = layout;
        match field {
            0 => changed.main_width += 1,
            1 => changed.preprocessed_width += 1,
            2 => changed.num_public_values += 1,
            3 => changed.permutation_width += 1,
            4 => changed.num_permutation_challenges += 1,
            5 => changed.num_permutation_values += 1,
            6 => changed.num_periodic_columns += 1,
            _ => unreachable!(),
        }
        assert!(
            !input.matches_layout(changed),
            "mutated layout field {field}"
        );
    }
}

#[test]
fn impossible_normalized_degree_cannot_wrap_or_truncate_to_an_admitted_profile() {
    for log_chunks in [usize::BITS as usize - 1, u32::MAX as usize, usize::MAX] {
        assert_eq!(
            checked_profile_chunks(log_chunks, 16).unwrap_err(),
            "uni quotient degree overflow"
        );
    }
}
