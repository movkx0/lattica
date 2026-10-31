use super::*;
use crate::block_v2::{
    gpu_hash::engine::retained_storage::{RetainedTreeStorageMode, Selection},
    machine::ProgramBuilder,
};
use p3_field::PrimeCharacteristicRing;

fn source_fixture() -> Program {
    let mut builder = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let first = builder.input();
    let second = builder.input();
    let bit = builder.input();
    let selected = builder.select_hint(vec![first, second], &[bit]);
    let sum = builder.add(first, selected);
    builder.poseidon([first, second, bit, selected, sum, first, second, sum]);
    builder.finish(None).unwrap()
}

#[test]
fn graph_source_widths_bind_layout_inputs_and_output() {
    for width in [25, 28] {
        let mut builder = ProgramBuilder::new(width).unwrap();
        let input = builder.input();
        builder.poseidon([input; 8]);
        let program = builder.finish(None).unwrap();
        let shape = OuterSourceShape::registered_graph_bounds(
            width,
            OperationCounts::from_program(&program),
            program.wire_count(),
            program.witness_values(),
            0,
        ).unwrap();
        shape.check_program(&program).unwrap();
        let layout = gpu_program::Layout::new(&program).unwrap();
        assert_eq!(shape.instruction_bytes, layout.words * 8);
        assert_eq!(shape.compiler_peak, layout.host_peak_bytes);
        assert_eq!(shape.output_footprint().unwrap().public_values, width as u64);
        let public = vec![Val::ZERO; width];
        let witness = vec![Val::ZERO; program.witness_values()];
        check_compiled_inputs(shape, &program, &public, &witness,
            backing(public.capacity()).unwrap(), backing(witness.capacity()).unwrap()).unwrap();
        let mut wrong = shape;
        wrong.public_values = if width == 25 { 28 } else { 25 };
        assert!(wrong.check_program(&program).is_err());
        assert!(check_compiled_inputs(wrong, &program, &public, &witness,
            backing(public.capacity()).unwrap(), backing(witness.capacity()).unwrap()).is_err());
    }
}

#[test]
fn fixed_public_owner_preserves_exact_shape_and_real_witness_capacity() {
    let mut builder = ProgramBuilder::new(28).unwrap();
    let input = builder.input();
    builder.poseidon([input; 8]);
    let program = builder.finish(None).unwrap();
    let shape = OuterSourceShape::registered_graph_bounds(28,
        OperationCounts::from_program(&program), program.wire_count(),
        program.witness_values(), 0).unwrap();
    let public = [Val::ZERO; 28];
    let witness = vec![Val::ZERO; program.witness_values()];
    let public_backing = backing(public.len()).unwrap();
    let witness_backing = backing(witness.capacity()).unwrap();
    assert_eq!(check_compiled_fixed_public_inputs(shape, &program, &public, &witness,
        public_backing, witness_backing).unwrap(), program.height());
    assert!(check_compiled_fixed_public_inputs(shape, &program, &public, &witness,
        public_backing - 1, witness_backing).is_err());
    assert!(check_compiled_fixed_public_inputs(shape, &program, &[Val::ZERO; 27], &witness,
        public_backing, witness_backing).is_err());
    let mut excess_witness = Vec::with_capacity(witness.capacity() + 17);
    excess_witness.resize(witness.len(), Val::ZERO);
    assert!(check_compiled_fixed_public_inputs(shape, &program, &public, &excess_witness,
        public_backing, witness_backing).is_err());
    // The maintained Vec entry must still audit spare public capacity. It
    // cannot acquire fixed-array semantics merely by exposing a short slice.
    let mut excess_public = Vec::with_capacity(56);
    excess_public.resize(28, Val::ZERO);
    assert!(check_compiled_inputs(shape, &program, &excess_public, &witness,
        public_backing, witness_backing).is_err());
}

#[test]
fn graph_source_profile_does_not_expand_shake_or_accept_other_widths() {
    let program = source_fixture();
    let shape = source_shape(&program);
    assert_eq!(shape.public_values, 46);
    for width in [0, 24, 26, 27, 29, 46, 65, usize::MAX] {
        assert!(OuterSourceShape::registered_graph_bounds(width, shape.operations,
            shape.wires, shape.witness_values.maximum(), shape.hint_words).is_err());
    }
    for width in [25, 28] {
        assert!(OuterSourceShape::registered_graph_bounds(width, shape.operations,
            shape.wires, INPUT_VALUES + 1, shape.hint_words).is_err());
        assert!(OuterSourceShape::registered_graph_bounds(width, shape.operations,
            MAX_WIRES + 1, shape.witness_values.maximum(), shape.hint_words).is_err());
    }
}

fn source_shape(program: &Program) -> OuterSourceShape {
    let hints = program.operations.iter().fold(0, |sum, op| match op {
        Op::SelectHint { entries, bits, .. } => sum + entries.len() + bits.len(),
        _ => sum,
    });
    OuterSourceShape::owned_shake(
        OperationCounts::from_program(program),
        program.wire_count(),
        program.witness_values(),
        hints,
    )
    .unwrap()
}

fn limits() -> RegisteredGpuLimits {
    RegisteredGpuLimits::with_selection(
        32 << 30,
        8 << 30,
        4 << 30,
        1 << 20,
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 8 << 30,
        },
    )
    .unwrap()
}

#[test]
fn source_layout_matches_genuine_hints_and_partial_rows() {
    let program = source_fixture();
    let shape = source_shape(&program);
    assert!(shape.hint_words > 0);
    let actual = gpu_program::Layout::new(&program).unwrap();
    assert_eq!(shape.instruction_bytes, actual.words * 8);
    assert_eq!(shape.compiler_peak, actual.host_peak_bytes);
    assert_eq!(shape.schedule_bytes, actual.schedule_host_bytes);
    assert_eq!(shape.active_rows, program.active_rows());
    assert_eq!(shape.padded_rows, program.height());
    shape.check_program(&program).unwrap();
    let bound = shape.bounds(program.height(), limits()).unwrap();
    let actual = Bounds::for_program_with_tree_storage(&program, true, limits().trees).unwrap();
    assert!(covers(&bound, &actual, shape.witness_values));
}

#[test]
fn source_bound_rejects_each_changed_original_dimension() {
    let program = source_fixture();
    let shape = source_shape(&program);
    let mut bad = shape;
    bad.hint_words -= 1;
    assert!(bad.check_program(&program).is_err());
    bad = shape;
    bad.operations.poseidon -= 1;
    assert!(bad.check_program(&program).is_err());
    bad = shape;
    bad.witness_values = WitnessCount::Exact(u32::try_from(program.witness_values() + 1).unwrap());
    assert!(bad.check_program(&program).is_err());
    bad = shape;
    bad.wires -= 1;
    assert!(bad.check_program(&program).is_err());
    bad = shape;
    bad.source_bytes = program.source_host_bytes().unwrap() - 1;
    assert!(bad.check_program(&program).is_err());
    bad = shape;
    bad.active_rows = program.active_rows() - 1;
    assert!(bad.check_program(&program).is_err());
}

#[test]
fn output_shape_refactor_matches_actual_program_for_every_allowed_height() {
    let mut maximum = None;
    for log in FIRST_LOG..=LAST_LOG {
        let rows = 1usize << log;
        let program = ProgramBuilder::new(PUBLIC_VALUES)
            .unwrap()
            .finish(Some(rows))
            .unwrap();
        let source = program.source_host_bytes().unwrap() as u64;
        let output = output::inspect_shape(PUBLIC_VALUES, rows, source).unwrap();
        let actual = output::inspect_registered_gpu_output(&program).unwrap();
        assert_eq!(output, actual);
        maximum = Some(maximum.map_or(output, |prior| output_max(prior, output)));
        assert_eq!(output_max(maximum.unwrap(), output), maximum.unwrap());
        assert!(!output.dispatch_authority);
        assert!(!output.enclosing_ownership_bound_complete);
    }
    assert_eq!(maximum.unwrap().rows, 1 << LAST_LOG);
    assert!(output::inspect_shape(65, 8, 1).is_err());
    for rows in [0, 7, 9, 1 << 21, usize::MAX] {
        assert!(output::inspect_shape(PUBLIC_VALUES, rows, 1).is_err());
    }
}

#[test]
fn incomplete_selection_and_changed_limits_never_issue_source_envelope() {
    let program = source_fixture();
    let shape = source_shape(&program);
    assert!(OuterSourceEnvelope::inspect(shape, limits(), 20 << 30).is_err());
    let mut changed = limits();
    changed.device_bytes -= 1;
    assert!(OuterSourceEnvelope::inspect(shape, changed, 20 << 30).is_err());
    assert!(OuterSourceEnvelope::additional_metadata_host_bytes().unwrap() < 1 << 20);
}

#[test]
fn capacity_arithmetic_and_row_domain_are_checked_before_planning() {
    let shape = source_shape(&source_fixture());
    let huge = OperationCounts {
        scalar: usize::MAX,
        cubic: 1,
        poseidon: 0,
    };
    assert!(OuterSourceShape::owned_shake(huge, 64, 1, 0).is_err());
    assert!(OuterSourceShape::owned_shake(shape.operations, usize::MAX, 0, 0).is_err());
    assert!(OuterSourceShape::owned_shake(shape.operations, 64, INPUT_VALUES + 1, 0).is_err());
    assert!(OuterSourceShape::owned_shake(shape.operations, 0, 0, 0).is_err());
    assert!(OuterSourceShape::owned_shake(shape.operations, 64, 1, usize::MAX).is_err());
    for rows in [0, 7, 9, shape.padded_rows * 2, usize::MAX] {
        assert!(shape.bounds(rows, limits()).is_err());
    }
}

#[test]
#[ignore = "requires coordinator serialized original host-profile preflight"]
fn captured_profile_screens_all_heights_and_checks_actual_compiler_capacity() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    // Enumeration only: no context, queue, registration or proof dispatch.
    // The coordinator must hold its original source/runtime planning claims.
    let selected = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, 1 << 20).unwrap();
    let program = source_fixture();
    let mut counts = OperationCounts::from_program(&program);
    counts.scalar += 8192;
    let shape = OuterSourceShape::owned_shake(
        counts,
        program.wire_count() + 8192,
        program.witness_values(),
        source_shape(&program).hint_words,
    )
    .unwrap();
    let envelope = OuterSourceEnvelope::inspect(shape, selected, 20 << 30).unwrap();
    let public = vec![Val::ZERO; PUBLIC_VALUES];
    let witness = vec![Val::ZERO; program.witness_values()];
    envelope
        .check_compiled(&program, &public, &witness)
        .unwrap();
    assert_eq!(
        envelope.report.screened_row_geometries,
        (shape.padded_rows.ilog2() - FIRST_LOG + 1) as usize
    );
    assert_eq!(envelope.report.complete_device_phase_ceiling, 8 << 30);
    assert_eq!(envelope.report.backend_scope_host_bytes, 28 << 30);
    assert!(envelope.report.source_phase_bounds_complete);
    assert!(!envelope.report.enclosing_ownership_bound_complete);
    assert!(!envelope.report.workflow_dispatch_authority);
    let mut excess = Vec::with_capacity(2 * PUBLIC_VALUES + 1);
    excess.extend_from_slice(&public);
    assert!(envelope
        .check_compiled(&program, &excess, &witness)
        .is_err());
}

#[test]
fn registered_parent_ceiling_accepts_fewer_inputs_without_changing_exact_mode() {
    let program = source_fixture();
    let actual = source_shape(&program);
    let maximum = program.witness_values() + 7;
    let exact = OuterSourceShape::owned_shake(
        actual.operations,
        actual.wires + 7,
        maximum,
        actual.hint_words,
    )
    .unwrap();
    assert!(exact.check_program(&program).is_err());
    let upper = OuterSourceShape::registered_parent_bounds(
        actual.operations,
        actual.wires + 7,
        maximum,
        actual.hint_words,
    )
    .unwrap();
    upper.check_program(&program).unwrap();
    let bounds = upper.bounds(program.height(), limits()).unwrap();
    assert_eq!(bounds.input_values, (PUBLIC_VALUES + maximum) as u64);
    let genuine = Bounds::for_program_with_tree_storage(&program, true, limits().trees).unwrap();
    assert!(covers(&bounds, &genuine, upper.witness_values));
    assert!(!covers(&bounds, &genuine, exact.witness_values));
    let short = OuterSourceShape::registered_parent_bounds(
        actual.operations,
        actual.wires,
        program.witness_values() - 1,
        actual.hint_words,
    )
    .unwrap();
    assert!(short.check_program(&program).is_err());
    assert!(OuterSourceShape::registered_parent_bounds(
        actual.operations,
        actual.wires,
        INPUT_VALUES + 1,
        actual.hint_words,
    )
    .is_err());
    actual.check_program(&program).unwrap();
}

#[test]
#[ignore = "requires coordinator serialized original host-profile preflight"]
fn parent_upper_bound_still_requires_actual_program_public_and_witness_lengths() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let program = source_fixture();
    let actual = source_shape(&program);
    let mut counts = actual.operations;
    counts.scalar += 8192;
    let maximum = program.witness_values() + 7;
    let shape = OuterSourceShape::registered_parent_bounds(
        counts,
        actual.wires + 8192,
        maximum,
        actual.hint_words,
    )
    .unwrap();
    let public = vec![Val::ZERO; PUBLIC_VALUES];
    let witness = vec![Val::ZERO; program.witness_values()];
    // Exact fixed input ceilings used by the real envelope constructor. This
    // invokes its maintained pure helper without constructing an envelope or
    // a synthetic captured execution selection.
    let public_backing = backing(2 * PUBLIC_VALUES).unwrap();
    let witness_backing = backing(INPUT_VALUES).unwrap();
    let check = |public: &Vec<Val>, witness: &Vec<Val>| {
        check_compiled_inputs(
            shape,
            &program,
            public,
            witness,
            public_backing,
            witness_backing,
        )
    };
    assert_eq!(check(&public, &witness).unwrap(), program.height());
    assert!(check(&public, &vec![Val::ZERO; maximum]).is_err());
    assert!(check(&public, &vec![Val::ZERO; program.witness_values() - 1]).is_err());
    assert!(check(&vec![Val::ZERO; PUBLIC_VALUES - 1], &witness).is_err());
    assert!(check_compiled_inputs(shape, &program, &public, &witness, 0, witness_backing).is_err());
    assert!(check_compiled_inputs(shape, &program, &public, &witness, public_backing, 0).is_err());
    // This remains a pure resource-layout comparison. Captured execution,
    // complete row-plan inspection and physical fit are deliberately absent.
    let bound = shape.bounds(program.height(), limits()).unwrap();
    let actual = Bounds::for_program_with_tree_storage(&program, true, limits().trees).unwrap();
    assert!(covers(&bound, &actual, shape.witness_values));
}
