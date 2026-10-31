use super::super::{
    budget, compile_once, compile_with_diagnostics, compile_with_profile_diagnostics,
};
use super::*;
use crate::{ring, Context};
use lattica_prover_p3::block_v2::machine::{
    program::{Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;

const PROFILES: [(CompilerMemoryProfile, &str, u64); 4] = [
    (CompilerMemoryProfile::Program256MiB, "256m", 400 << 20),
    (CompilerMemoryProfile::Program2GiB, "2g", 2192 << 20),
    (CompilerMemoryProfile::Program8GiB, "8g", 8336 << 20),
    (CompilerMemoryProfile::Program24GiB, "24g", 24720 << 20),
];

#[test]
fn closed_profiles_keep_default_geometry_and_exact_host_boundaries() {
    assert_eq!(CompilerMemoryProfile::default(), PROFILES[0].0);
    for (profile, name, required) in PROFILES {
        assert_eq!(name.parse::<CompilerMemoryProfile>().unwrap(), profile);
        let limits = profile.limits();
        assert_eq!(limits.required_host_bytes, required);
        assert_eq!(limits.witness_byte_limit, 128 << 20);
        assert_eq!(limits.auxiliary_byte_limit, 16 << 20);
        assert_eq!(limits.wire_limit, 1 << 24);
        assert_eq!(limits.input_limit, (1 << 24) - 4);
        assert_eq!(limits.row_limit, 1 << 24);
        assert!(profile.admit((required - 1) as usize).is_err());
        let called = Cell::new(false);
        let refused: Result<(), _> = compile_once(profile.into(), (required - 1) as usize, |_| {
            called.set(true);
            let _builder = ProgramBuilder::new(1).unwrap();
            Ok(())
        });
        assert!(refused.is_err());
        assert!(
            !called.get(),
            "one-byte-short admission must precede the builder"
        );
        let admitted = profile.admit(required as usize).unwrap();
        assert_eq!(admitted.limits, limits);
        assert_eq!(admitted.host_allowance_bytes, required);
        assert_eq!(
            admitted.construction.max_requested_program_bytes as u64,
            limits.program_byte_limit
        );
        assert_eq!(admitted.construction.max_wires, limits.wire_limit);
        assert_eq!(admitted.construction.max_input_values, limits.input_limit);
        assert!(profile.admit(WORKER_HOST_BYTES as usize).is_ok());
        assert!(profile.admit((WORKER_HOST_BYTES + 1) as usize).is_err());
    }
    for unknown in ["", "0", "512m", "4g", "16g", "32g", "2048m", "2G"] {
        assert!(unknown.parse::<CompilerMemoryProfile>().is_err());
    }
}

#[test]
fn insufficient_host_and_early_semantic_refusals_report_selected_profile() {
    let context = Context([19; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    for (profile, name, required) in PROFILES {
        let short = compile_with_profile_diagnostics(
            &statement,
            &witness,
            context,
            profile,
            (required - 1) as usize,
        )
        .err()
        .expect("one byte short refuses before construction");
        assert!(matches!(short.error, Error::ResourceLimit));
        assert_eq!(short.phase, "whole_compiler_admission");
        assert_eq!(short.logical_limit, "compiler_host_allowance");
        assert_eq!(short.limits, profile.limits());
        assert_eq!(short.host_allowance_bytes, required - 1);
        assert_eq!(short.wires, None);
        assert_eq!(short.input_values, None);
        assert_eq!(short.witness_hint_values, None);
        assert_eq!(short.requested_program_bytes_peak, None);
        let semantic = compile_with_profile_diagnostics(
            &statement,
            &witness,
            Context([20; 32]),
            profile,
            required as usize,
        )
        .err()
        .expect("wrong expected context refuses before arithmetic");
        assert!(matches!(semantic.error, Error::Context));
        assert_eq!(semantic.limits, profile.limits());
        assert_eq!(semantic.wires, None);
        assert!(!semantic.cryptographic_proof_started);
        for failure in [&short, &semantic] {
            let json = serde_json::to_value(failure).unwrap();
            assert_eq!(json["memory_profile"], name);
            assert_eq!(
                json["program_byte_limit"],
                profile.limits().program_byte_limit
            );
            assert_eq!(json["required_host_bytes"], required);
            assert_eq!(json["row_limit"], 1 << 24);
        }
    }
    let default = compile_with_diagnostics(&statement, &witness, context, (400 << 20) - 1)
        .err()
        .expect("legacy API keeps the original footprint");
    assert_eq!(default.limits, CompilerMemoryProfile::default().limits());
}

fn tiny_program(profile: CompilerMemoryProfile) -> Program {
    let admitted = profile
        .admit(profile.limits().required_host_bytes as usize)
        .unwrap();
    let mut builder =
        ProgramBuilder::new_with_construction_limits(1, admitted.construction).unwrap();
    let secret = builder.input();
    let seven = builder.constant(Val::from_u64(7));
    let sum = builder.add(secret, seven);
    let public = builder.public(0).unwrap();
    builder.assert_equal(sum, public);
    assert!(!builder.construction_counters().resource_failed);
    builder.finish(None).unwrap()
}

#[test]
fn larger_allowances_do_not_change_a_program_or_retry_a_primitive_refusal() {
    let original = tiny_program(CompilerMemoryProfile::default());
    for (profile, _, required) in PROFILES {
        let program = tiny_program(profile);
        assert_eq!(program, original);
        let air = MachineAir::new(program);
        air.trace(&[Val::from_u64(10)], &[Val::from_u64(3)])
            .unwrap();
        assert!(air
            .trace(&[Val::from_u64(11)], &[Val::from_u64(3)])
            .is_err());

        // Inspect the same private failure-conversion path used by the outer
        // compiler catch without building a multi-GiB program in unit tests.
        let calls = Cell::new(0);
        let failure = compile_once::<()>(profile.into(), required as usize, |admitted| {
            calls.set(calls.get() + 1);
            assert_eq!(admitted.limits.memory_profile, profile);
            let mut builder = ProgramBuilder::new_with_construction_limits(
                0,
                ConstructionLimits {
                    max_requested_program_bytes: 1,
                    max_wires: MAX_WIRES,
                    max_input_values: MAX_INPUTS,
                },
            )
            .unwrap();
            builder.input();
            let counters = builder.construction_counters();
            assert!(counters.resource_failed);
            budget::refuse(
                "profile_failure_diagnostic",
                "program_heap_request_allowance",
                counters,
                0,
            )
        })
        .expect_err("a primitive refusal cannot retry at a higher profile");
        assert_eq!(calls.get(), 1);
        assert_eq!(failure.limits.memory_profile, profile);
        assert_eq!(
            failure.limits.program_byte_limit,
            profile.limits().program_byte_limit
        );
        assert!(failure.wires.is_some());
        assert!(!failure.cryptographic_proof_started);
    }
}

#[test]
fn supported_core_wire_ceiling_requires_explicit_selection_and_is_reported() {
    use super::super::compile_with_capacity_diagnostics;
    assert_eq!(
        CompilerWireProfile::default(),
        CompilerWireProfile::Research16M
    );
    assert_eq!(
        "64m".parse::<CompilerWireProfile>().unwrap(),
        CompilerWireProfile::Core64M
    );
    for invalid in ["", "32m", "128m", "67108864", "64M"] {
        assert!(invalid.parse::<CompilerWireProfile>().is_err());
    }
    for memory in [
        CompilerMemoryProfile::Program8GiB,
        CompilerMemoryProfile::Program24GiB,
    ] {
        let capacity = CompilerCapacityProfile::new(memory, CompilerWireProfile::Core64M);
        let limits = capacity.limits();
        assert_eq!(limits.wire_limit, CORE_MAX_WIRES);
        assert_eq!(limits.wire_limit, 1 << 26);
        assert_eq!(memory.limits().wire_limit, 1 << 24);
        assert_eq!(
            CompilerCapacityProfile::from(memory).limits(),
            memory.limits()
        );
        assert_eq!(
            limits.required_host_bytes,
            memory.limits().required_host_bytes
        );
        assert_eq!(limits.witness_byte_limit, 128 << 20);
        assert_eq!(limits.input_limit, (1 << 24) - 4);
        assert_eq!(limits.row_limit, 1 << 24);
        let admitted = capacity.admit(limits.required_host_bytes as usize).unwrap();
        let builder =
            ProgramBuilder::new_with_construction_limits(1, admitted.construction).unwrap();
        // Counters expose the actual configured wire limit without allocating a
        // large circuit. This asserts builder wiring, not only the profile label.
        assert_eq!(
            builder.construction_counters().wire_limit,
            limits.wire_limit
        );
        assert_eq!(builder.construction_counters().input_limit, MAX_INPUTS);
        drop(builder);
        let (statement, witness) = ring::fixture(Context([19; 32])).unwrap();
        let failure = compile_with_capacity_diagnostics(
            &statement,
            &witness,
            Context([20; 32]),
            capacity,
            limits.required_host_bytes as usize,
        )
        .err()
        .expect("semantic refusal retains explicit capacity profile");
        assert!(matches!(failure.error, Error::Context));
        let json = serde_json::to_value(failure).unwrap();
        assert_eq!(
            json["memory_profile"],
            serde_json::to_value(memory).unwrap()
        );
        assert_eq!(json["wire_profile"], "64m");
        assert_eq!(json["wire_limit"], 1 << 26);
        assert_eq!(json["input_limit"], (1 << 24) - 4);
        assert_eq!(json["row_limit"], 1 << 24);

        let attempts = Cell::new(0);
        let failure =
            compile_once::<()>(capacity, limits.required_host_bytes as usize, |admitted| {
                attempts.set(attempts.get() + 1);
                let builder =
                    ProgramBuilder::new_with_construction_limits(1, admitted.construction).unwrap();
                let counters = builder.construction_counters();
                budget::refuse("wire_profile_diagnostic", "program_wire_count", counters, 0)
            })
            .expect_err("an explicit capacity choice still runs only once");
        assert_eq!(attempts.get(), 1);
        assert_eq!(failure.logical_limit, "program_wire_count");
        assert_eq!(failure.limits.wire_limit, 1 << 26);
        assert_eq!(failure.limits.wire_profile, CompilerWireProfile::Core64M);
        assert!(!failure.cryptographic_proof_started);
    }
}
