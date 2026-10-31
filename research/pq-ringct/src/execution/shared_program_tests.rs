//! Public admission checks only; these tests never register or prove a program.
use super::*;
use lattica_prover_p3::block_v2::machine::ProgramBuilder;
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;

#[test]
fn remaining_host_allowance_refuses_before_registration_or_callback() {
    let context = ProvingContext::cpu(1 << 30).unwrap();
    let program = Arc::new(ProgramBuilder::new(1).unwrap().finish(None).unwrap());
    let called = Cell::new(false);
    for allowance in [0, (1 << 30) + 1, u64::MAX] {
        let result = context.with_registered_shared_with_host_budget(
            Arc::clone(&program),
            allowance,
            |_| {
                called.set(true);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), "registered remaining-host allowance must be nonzero and within context allowance");
        assert!(!called.get());
        assert_eq!(context.report()["registrations"], 0);
        assert_eq!(context.report()["prepared_entries"], 0);
        assert_eq!(Arc::strong_count(&program), 1);
    }
    let result = context.with_registered_shared_with_host_budget(
        Arc::clone(&program),
        1 << 29,
        |_| {
            called.set(true);
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err(), "registered remaining-host allowance requires GPU-required execution");
    assert!(!called.get());
    assert_eq!(context.report()["registrations"], 0);
    context.finish().unwrap();
}

#[test]
fn shared_air_retains_original_program_and_manifest() {
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.public(0).unwrap();
    let expected = builder.constant(Val::from_u64(7));
    builder.assert_equal(input, expected);
    let program = Arc::new(builder.finish(None).unwrap());
    let canonical = manifest(&program).unwrap();
    let air = MachineAir::from_shared_program(Arc::clone(&program));
    assert!(std::ptr::eq(air.program(), program.as_ref()));
    assert_eq!(manifest(air.program()).unwrap(), canonical);
    assert_eq!(Arc::strong_count(&program), 2);
    drop(air);
    assert_eq!(Arc::strong_count(&program), 1);
}
