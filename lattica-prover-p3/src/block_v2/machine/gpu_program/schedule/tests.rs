use super::*;
use crate::block_v2::machine::{gpu_program::Layout, ProgramBuilder};
use crate::spill_alloc::allocation_requests::measure;

fn compiled(inputs: usize) -> WitnessProgram {
    let mut builder = ProgramBuilder::new(0).unwrap();
    for _ in 0..inputs {
        builder.input();
    }
    WitnessProgram::compile(&builder.finish(None).unwrap(), 64 << 20).unwrap()
}

#[test]
fn schedule_admission_precedes_allocation_and_ignores_source_spare_capacity() {
    let mut program = compiled(1000);
    assert_eq!(program.waves.len(), 1);
    program.waves.reserve_exact(4096);
    let exact = WitnessSchedule::storage_bound(program.waves.len()).unwrap();
    let (rejected, requests) = measure(|| WitnessSchedule::try_new(&program, exact - 1));
    assert!(matches!(rejected, Err(ExecutionError::TooLarge)));
    assert_eq!(requests.calls, 0);
    let (schedule, requests) = measure(|| WitnessSchedule::try_new(&program, exact));
    let schedule = schedule.unwrap();
    assert_eq!(
        (requests.calls, requests.bytes),
        (1, size_of::<Range<usize>>())
    );
    assert_eq!(schedule.storage_bytes(), exact);
    assert_eq!(&*schedule.waves, &*program.waves);
    assert_ne!(schedule.waves.as_ptr(), program.waves.as_ptr());
    drop(program);
    assert_eq!(&*schedule.waves, &[0..1000]);
    assert_eq!(schedule.witnesses, 1000);
    eprintln!("witness_schedule_exact retained_bytes={exact} allocation_bytes={} calls=1 short_rejected_before_allocation=true source_spare_omitted=true survives_source_drop=true", requests.bytes);
}

#[test]
fn layout_bounds_every_possible_wave_without_allocating_dependency_scratch() {
    for inputs in [0, 1, 1000] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        for _ in 0..inputs {
            builder.input();
        }
        let source = builder.finish(None).unwrap();
        let (layout, requests) = measure(|| Layout::new(&source));
        let layout = layout.unwrap();
        assert_eq!(requests.calls, 0);
        let program = WitnessProgram::compile(&source, layout.host_peak_bytes).unwrap();
        assert_eq!(
            layout.schedule_host_bytes,
            WitnessSchedule::storage_bound(source.operations.len()).unwrap()
        );
        assert_eq!(program.schedule_host_bytes, layout.schedule_host_bytes);
        assert!(program.waves.len() <= source.operations.len());
        assert!(program.schedule_host_bytes < program.host_peak_bytes - program.words.len() * 8);
        let (schedule, requests) =
            measure(|| WitnessSchedule::try_new(&program, program.schedule_host_bytes));
        let schedule = schedule.unwrap();
        assert!(schedule.storage_bytes() <= program.schedule_host_bytes);
        assert_eq!(
            requests.bytes,
            program.waves.len() * size_of::<Range<usize>>()
        );
        assert_eq!(requests.calls, usize::from(inputs != 0));
    }
    // A public-input hash chain reaches the upper bound: every operation
    // needs its own wave. Parallel-input fixtures alone cannot exercise this.
    let mut builder = ProgramBuilder::new(8).unwrap();
    let mut state = core::array::from_fn(|i| builder.public(i).unwrap());
    for _ in 0..64 {
        state = builder.poseidon(state);
    }
    let source = builder.finish(None).unwrap();
    let program = WitnessProgram::compile(&source, 64 << 20).unwrap();
    assert_eq!(source.operations.len(), 64);
    assert_eq!(program.waves.len(), 64);
    let (schedule, requests) =
        measure(|| WitnessSchedule::try_new(&program, program.schedule_host_bytes));
    let schedule = schedule.unwrap();
    assert_eq!(schedule.storage_bytes(), program.schedule_host_bytes);
    assert_eq!(
        (requests.calls, requests.bytes),
        (1, 64 * size_of::<Range<usize>>())
    );
    let maximum = (usize::MAX - size_of::<WitnessSchedule>()) / size_of::<Range<usize>>();
    assert!(WitnessSchedule::storage_bound(maximum).is_ok());
    assert!(WitnessSchedule::storage_bound(maximum + 1).is_err());
    assert!(WitnessSchedule::storage_bound(usize::MAX).is_err());
    eprintln!("witness_schedule_upper templates=4 allocation_free=true one_wave_per_operation=true maximum_chain_waves=64 empty_copy_allocation_free=true overflow_rejected=true");
}

#[test]
fn compiler_peak_covers_original_metadata_and_the_new_schedule_during_handoff() {
    for inputs in [0, 1, 1000] {
        let program = compiled(inputs);
        let schedule = WitnessSchedule::try_new(&program, program.schedule_host_bytes).unwrap();
        let simultaneous = program.words.capacity() * size_of::<u64>()
            + program.waves.capacity() * size_of::<Range<usize>>()
            + size_of::<WitnessProgram>()
            + 2 * size_of::<usize>()
            + schedule.storage_bytes();
        assert!(simultaneous <= program.host_peak_bytes);
    }
    eprintln!(
        "witness_schedule_handoff templates=3 compiled_metadata_and_schedule_overlap_admitted=true"
    );
}
