use super::super::MachineAir;
use super::*;
use p3_field::PrimeCharacteristicRing;

fn fixture(branches: usize, hash_depth: usize, publics: usize) -> Program {
    let mut b = ProgramBuilder::new(publics).unwrap();
    let one = b.constant(Val::ONE);
    let mut hash = core::array::from_fn(|_| b.input());
    let bit = b.input();
    b.assert_bool(bit);
    for _ in 0..branches {
        let a = core::array::from_fn(|_| b.input());
        let z = core::array::from_fn(|_| b.input());
        let sum = b.add(a[0], z[0]);
        let product = b.mul(sum, z[1]);
        let inverse = b.inverse(product);
        let identity = b.mul(product, inverse);
        b.assert_equal(identity, one);
        let selected = b.select(bit, a[0], product);
        let high = b.bit_hint(selected, 63);
        let low = b.bit_hint(inverse, 0);
        b.assert_bool(high);
        b.assert_bool(low);
        // Entries include computed values: their real dependencies must not be
        // confused with the intentionally absent AIR bus reads for this hint.
        let hint = b.select_hint(vec![a[0], selected, product, inverse], &[low, high]);
        let _ = b.add(hint, selected);
        let product = b.cubic_mul(a, z);
        let inverse = b.cubic_inverse(product);
        let identity = b.cubic_mul(product, inverse);
        b.assert_equal(identity[0], one);
        let zero = b.constant(Val::ZERO);
        b.assert_equal(identity[1], zero);
        b.assert_equal(identity[2], zero);
    }
    for _ in 0..hash_depth {
        hash = b.poseidon(hash);
    }
    if publics > 0 {
        let p = b.public(0).unwrap();
        let _ = b.add(hash[0], p);
    }
    b.finish(None).unwrap()
}

#[test]
fn witness_schedule_preserves_hint_dependencies_and_compiler_budget() {
    let program = fixture(2, 3, 64);
    let unchanged = program.clone();
    let compiled = WitnessProgram::compile(&program, 8 << 20).unwrap();
    assert_eq!(program, unchanged);
    assert!(compiled.waves.len() < program.operations.len());
    let mut ready = vec![None; compiled.wires];
    ready[..program.publics].fill(Some(0));
    let mut hints = 0;
    for (wave, range) in compiled.waves.iter().enumerate() {
        for i in range.clone() {
            let c = &compiled.words
                [HEADER_WORDS + i * INSTRUCTION_WORDS..HEADER_WORDS + (i + 1) * INSTRUCTION_WORDS];
            #[cfg(feature = "gpu")]
            assert_eq!(
                c[17],
                if i == range.start {
                    range.len() as u64
                } else {
                    0
                }
            );
            let (reads, writes): (Vec<usize>, Vec<usize>) = match c[0] {
                0 | 1 => (vec![], vec![c[1] as usize]),
                2 | 3 => (vec![c[2] as usize, c[3] as usize], vec![c[1] as usize]),
                4 => (vec![c[1] as usize, c[2] as usize], vec![]),
                5 => (vec![c[1] as usize], vec![]),
                6 | 11 => (vec![c[2] as usize], vec![c[1] as usize]),
                7 => (
                    c[2..5].iter().map(|&n| n as usize).collect(),
                    vec![c[1] as usize],
                ),
                8 => (
                    c[1..9].iter().map(|&n| n as usize).collect(),
                    c[9..17].iter().map(|&n| n as usize).collect(),
                ),
                9 => (
                    c[4..10].iter().map(|&n| n as usize).collect(),
                    c[1..4].iter().map(|&n| n as usize).collect(),
                ),
                10 => (
                    c[4..7].iter().map(|&n| n as usize).collect(),
                    c[1..4].iter().map(|&n| n as usize).collect(),
                ),
                12 => {
                    hints += 1;
                    let first = c[2] as usize;
                    let bits = c[3] as usize;
                    (
                        compiled.words[first..first + bits + (1 << bits)]
                            .iter()
                            .map(|&n| n as usize)
                            .collect(),
                        vec![c[1] as usize],
                    )
                }
                _ => panic!("unknown instruction"),
            };
            for read in reads {
                assert!(ready[read].is_some_and(|time| time <= wave));
            }
            for write in writes {
                assert!(ready[write].is_none());
                ready[write] = Some(wave + 1);
            }
        }
    }
    assert_eq!(hints, 2);
    assert!(ready.iter().all(Option::is_some));
    assert_eq!(
        WitnessProgram::compile(&program, compiled.host_peak_bytes - 1).err(),
        Some(ExecutionError::TooLarge)
    );
    assert!(WitnessProgram::compile(&program, compiled.host_peak_bytes).is_ok());
}

#[test]
fn witness_compiler_rejects_bad_sources_outputs_hints_and_shapes() {
    let valid = fixture(1, 1, 1);
    for malformed in 0..9 {
        let mut program = valid.clone();
        match malformed {
            0 => program.operations.insert(
                0,
                Op::Add {
                    a: Wire(100000),
                    b: Wire(0),
                    out: Wire(1),
                },
            ),
            1 => program.operations.push(Op::Constant {
                value: Val::ONE,
                out: Wire(0),
            }),
            2 => program.operations.push(Op::Bit {
                source: Wire(0),
                bit: 64,
                out: Wire(1),
            }),
            3 => program.operations.push(Op::SelectHint {
                entries: vec![Wire(0); 3],
                bits: vec![Wire(0)],
                out: Wire(1),
            }),
            4 => program.operations.insert(
                0,
                Op::Bit {
                    source: Wire(1),
                    bit: 1,
                    out: Wire(2),
                },
            ),
            5 => program.operations.push(Op::Input {
                index: program.witnesses,
                out: Wire(1),
            }),
            6 => program.height = 3,
            7 => program.rows.push(Row::Public(2)),
            _ => program.rows.push(Row::Alu(vec![0; LANES + 1])),
        }
        assert!(
            WitnessProgram::compile(&program, 8 << 20).is_err(),
            "case {malformed}"
        );
    }
}

#[test]
#[cfg(feature = "stream")]
fn row_indices_and_families_reject_before_compiler_allocation() {
    let valid = fixture(1, 1, 1);
    let input = valid
        .operations
        .iter()
        .position(|op| matches!(op, Op::Input { .. }))
        .unwrap() as u32;
    let hash = valid
        .operations
        .iter()
        .position(|op| matches!(op, Op::Poseidon { .. }))
        .unwrap() as u32;
    for row in [
        Row::Alu(vec![u32::MAX]),
        Row::Cubic(vec![u32::MAX]),
        Row::Poseidon(u32::MAX),
        Row::Cubic(vec![input]),
        Row::Alu(vec![hash]),
        Row::Poseidon(input),
    ] {
        let mut bad = valid.clone();
        bad.rows[0] = row;
        let (result, allocation) =
            crate::spill_alloc::allocation_requests::measure(|| Layout::new(&bad));
        assert!(result.is_err());
        assert_eq!(allocation.calls, 0);
    }
}

#[test]
#[ignore = "requires OpenCL GPU; serial <=3 GiB zero-swap service"]
fn gpu_witness_and_preprocessing_match_cpu_across_programs_and_fresh_sessions() {
    use crate::block_v2::gpu_hash::{self as engine, device::DeviceSession, Limits};
    use p3_air::BaseAir;
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_quotient_test_engine(Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let initial = engine::report("before witness conformance").unwrap();
    let mut programs = vec![
        ProgramBuilder::new(0).unwrap().finish(None).unwrap(),
        ProgramBuilder::new(64).unwrap().finish(Some(256)).unwrap(),
    ];
    for shape in [(1, 1, 1), (7, 4, 33), (23, 9, 64), (257, 65, 64)] {
        programs.push(fixture(shape.0, shape.1, shape.2));
    }
    // Cross the 64-level launch boundary and the 128-lane fusion limit with
    // genuine read-after-write chains. The CPU AIR trace is the oracle.
    for (width, depth) in [(1, 129), (127, 65), (128, 65), (129, 65)] {
        let mut builder = ProgramBuilder::new(0).unwrap();
        let mut wires: Vec<_> = (0..width).map(|_| builder.input()).collect();
        for _ in 0..depth {
            for wire in &mut wires {
                *wire = builder.add(*wire, *wire);
            }
        }
        programs.push(builder.finish(None).unwrap());
    }
    for program in programs {
        let setup = DeviceSession::new().unwrap();
        let compiled = std::sync::Arc::new(WitnessProgram::compile(&program, 64 << 20).unwrap());
        let upload = compiled.words.len() * 8;
        let waves = compiled.waves.len();
        let host_instructions = std::sync::Arc::downgrade(&compiled);
        let before = setup.stats();
        let prepared = setup.prepare_witness(compiled).unwrap();
        assert!(
            host_instructions.upgrade().is_none(),
            "uploaded host instructions retained"
        );
        assert_eq!(
            setup.stats().uploaded_bytes - before.uploaded_bytes,
            upload as u64
        );
        assert_eq!(setup.stats().downloaded_bytes, before.downloaded_bytes);
        let air = MachineAir::new(program.clone());
        let expected = air.preprocessed_trace().unwrap();
        let before = setup.stats();
        let pre = prepared.preprocessing(&setup).unwrap();
        assert_eq!(setup.stats().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(setup.stats().downloaded_bytes, before.downloaded_bytes);
        assert_eq!(
            setup.read(&pre, pre.spec().bytes()).unwrap(),
            expected
                .values
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        let public_pre = pre.into_public_preprocessing();
        let baseline = engine::report("witness public metadata baseline").unwrap();
        for offset in [7u64, 31, 101] {
            let session = DeviceSession::new().unwrap();
            let public: Vec<_> = (0..program.publics)
                .map(|i| u64::MAX.wrapping_sub((1 << 32) + i as u64))
                .collect();
            let mut witness: Vec<_> = (0..program.witnesses)
                .map(|i| ((i as u64 * 7 + offset) % 117) + 1)
                .collect();
            if !witness.is_empty() {
                if witness.len() > 8 {
                    witness[8] = (offset & 1) as u64;
                }
                witness[0] = 0xffff_ffff_0000_0000;
                if witness.len() > 1 {
                    witness[1] = 0;
                }
            }
            let expected = air
                .trace(
                    &public
                        .iter()
                        .copied()
                        .map(Val::from_u64)
                        .collect::<Vec<_>>(),
                    &witness
                        .iter()
                        .copied()
                        .map(Val::from_u64)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            let before = session.stats();
            let trace = prepared
                .trace(&session, &public, &witness, 64 << 20)
                .unwrap();
            let after = session.stats();
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                ((public.len() + witness.len()) * 8) as u64
            );
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
            assert_eq!(after.witness_waves - before.witness_waves, waves as u64);
            assert_eq!(
                after.witness_rows - before.witness_rows,
                program.height as u64
            );
            assert_eq!(
                session.read(&trace, trace.spec().bytes()).unwrap(),
                expected
                    .values
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
            );
            assert!(setup.alias_private(&trace).is_err());
            let imported = session.import_preprocessing(&public_pre).unwrap();
            drop((imported, trace));
            let after = engine::report("witness private scratch released").unwrap();
            assert_eq!(
                after.device_matrix_live_bytes,
                baseline.device_matrix_live_bytes
            );
            assert_eq!(after.device_matrices, baseline.device_matrices);
        }
    }
    let after = engine::report("witness conformance released").unwrap();
    assert_eq!(
        after.device_matrix_live_bytes,
        initial.device_matrix_live_bytes
    );
    assert_eq!(after.device_matrices, initial.device_matrices);
}

#[test]
#[ignore = "requires OpenCL GPU; serial <=3 GiB zero-swap service"]
fn gpu_witness_failures_are_explicit_bounded_and_do_not_poison_reuse() {
    use crate::block_v2::gpu_hash::{
        self as engine,
        device::{DeviceSession, WitnessError},
        Limits,
    };
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    for kind in 0..5 {
        let mut b = ProgramBuilder::new(0).unwrap();
        let a = b.input();
        let one = b.constant(Val::ONE);
        match kind {
            0 => b.assert_equal(a, one),
            1 => b.assert_bool(a),
            2 => {
                b.inverse(a);
            }
            3 => {
                let z = b.constant(Val::ZERO);
                b.cubic_inverse([a, z, z]);
            }
            _ => {
                b.select_hint(vec![one, a], &[a]);
            }
        }
        let program = b.finish(None).unwrap();
        let session = DeviceSession::new().unwrap();
        let prepared = session
            .prepare_witness(std::sync::Arc::new(
                WitnessProgram::compile(&program, 1 << 20).unwrap(),
            ))
            .unwrap();
        let bad = if kind == 2 || kind == 3 { 0 } else { 2 };
        let cpu = program.evaluate(&[], &[Val::from_u64(bad)]).err().unwrap();
        let before = engine::report("before witness rejection").unwrap();
        assert_eq!(
            prepared
                .trace(&session, &[], &[bad], 1 << 20)
                .err()
                .unwrap(),
            WitnessError::Execution(cpu)
        );
        let after = engine::report("after witness rejection").unwrap();
        assert_eq!(
            before.device_matrix_live_bytes,
            after.device_matrix_live_bytes
        );
        let untouched = session.stats();
        assert!(prepared.trace(&session, &[], &[1], 0).is_err());
        assert_eq!(
            prepared.trace(&session, &[1], &[1], 1 << 20).err().unwrap(),
            WitnessError::Execution(ExecutionError::PublicInputCount)
        );
        assert_eq!(
            prepared.trace(&session, &[], &[], 1 << 20).err().unwrap(),
            WitnessError::Execution(ExecutionError::WitnessCount)
        );
        assert_eq!(
            prepared
                .trace(&session, &[], &[0xffff_ffff_0000_0001], 1 << 20)
                .err()
                .unwrap(),
            WitnessError::Execution(ExecutionError::NonCanonicalField)
        );
        assert_eq!(session.stats(), untouched);
        let valid = prepared.trace(&session, &[], &[1], 1 << 20).unwrap();
        drop(valid);
    }
    // Metadata is tiny, but no full trace can fit the admitted 64 MiB service
    // context. Both operations reject before any transfer or allocation.
    let session = DeviceSession::new().unwrap();
    let huge = ProgramBuilder::new(0)
        .unwrap()
        .finish(Some(1 << 20))
        .unwrap();
    let prepared = session
        .prepare_witness(std::sync::Arc::new(
            WitnessProgram::compile(&huge, 1 << 20).unwrap(),
        ))
        .unwrap();
    let stats = session.stats();
    let before = engine::report("witness oversized before").unwrap();
    assert!(prepared.trace(&session, &[], &[], 8).is_err());
    assert!(prepared.preprocessing(&session).is_err());
    assert_eq!(session.stats(), stats);
    let after = engine::report("witness oversized after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(
        after.device_matrix_live_bytes,
        before.device_matrix_live_bytes
    );
}
