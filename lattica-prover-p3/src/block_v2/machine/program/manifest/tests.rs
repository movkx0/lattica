use super::*;

#[test]
fn compact_poseidon_keeps_canonical_u64_wire_encoding() {
    let input = [
        0,
        1,
        255,
        65535,
        65536,
        MAX_WIRES as u32 - 2,
        MAX_WIRES as u32 - 1,
        13,
    ];
    let output = [8, 9, 10, 11, 12, 13, 14, 15];
    let mut encoded = Vec::new();
    operation(&Op::Poseidon { input, output }, &mut |word| {
        encoded.push(word);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        encoded,
        vec![
            8, 8, 0, 1, 255, 65535, 65536, 67_108_862, 67_108_863, 13, 8, 8, 9, 10, 11, 12, 13, 14,
            15
        ]
    );
}

// Frozen pre-stream encoder: preserve its row cloning and address vectors as
// an independent compatibility oracle, including input/hint discriminants.
fn legacy(program: &Program) -> Vec<u64> {
    let mut out = vec![
        if cfg!(feature = "block-v2-wide-lanes") {
            6
        } else {
            3
        },
        program.publics as u64,
        program.witnesses as u64,
        program.height as u64,
        program.references.len() as u64,
        program.rows.len() as u64,
    ];
    #[cfg(feature = "block-v2-wide-lanes")]
    out.extend([
        LANES as u64,
        EXT_LANES as u64,
        PUBLICS_PER_ROW as u64,
        crate::block_v2::profile::NODE_CODEC_REVISION,
    ]);
    for row in &program.rows {
        let ops = match row {
            Row::Public(bank) => {
                out.push(3);
                out.push(*bank as u64);
                vec![]
            }
            Row::Alu(ops) => {
                out.push(0);
                ops.iter()
                    .map(|index| program.operation(*index).unwrap().clone())
                    .collect()
            }
            Row::Cubic(ops) => {
                out.push(2);
                ops.iter()
                    .map(|index| program.operation(*index).unwrap().clone())
                    .collect()
            }
            Row::Poseidon(index) => {
                out.push(1);
                vec![program.operation(*index).unwrap().clone()]
            }
        };
        out.push(ops.len() as u64);
        for op in ops {
            out.push(op.code() as u64);
            match &op {
                Op::Input { index, .. } => {
                    out.push(0);
                    out.push(*index as u64);
                }
                Op::Bit { source, bit, .. } => {
                    out.push(1);
                    out.push(source.0 as u64);
                    out.push(*bit as u64);
                }
                Op::SelectHint { entries, bits, .. } => {
                    out.push(2);
                    out.push(entries.len() as u64);
                    out.extend(entries.iter().map(|w| w.0 as u64));
                    out.push(bits.len() as u64);
                    out.extend(bits.iter().map(|w| w.0 as u64));
                }
                Op::Constant { value, .. } => out.push(value.as_canonical_u64()),
                _ => (),
            }
            let reads = op.reads();
            let writes = op.writes();
            out.push(reads.len() as u64);
            out.extend(reads.iter().map(|w| w.0 as u64));
            out.push(writes.len() as u64);
            out.extend(writes.iter().map(|w| w.0 as u64));
        }
    }
    out.extend(program.references.iter().map(|&r| u64::from(r)));
    out
}

fn all_operations() -> Program {
    let w = Wire;
    let ops = vec![
        Op::Input {
            index: 7,
            out: w(20),
        },
        Op::Bit {
            source: w(20),
            bit: 63,
            out: w(21),
        },
        Op::SelectHint {
            entries: (30..94).map(w).collect(),
            bits: (94..100).map(w).collect(),
            out: w(100),
        },
        Op::SelectHint {
            entries: vec![],
            bits: vec![],
            out: w(101),
        },
        Op::Constant {
            value: Val::NEG_ONE,
            out: w(22),
        },
        Op::Add {
            a: w(20),
            b: w(22),
            out: w(23),
        },
        Op::Mul {
            a: w(23),
            b: w(22),
            out: w(24),
        },
        Op::Equal { a: w(23), b: w(24) },
        Op::Boolean { a: w(21) },
        Op::Inverse {
            a: w(24),
            out: w(25),
        },
        Op::Select {
            bit: w(21),
            a: w(24),
            b: w(25),
            out: w(26),
        },
    ];
    let cubic = vec![
        Op::CubicMul {
            a: [w(3), w(4), w(5)],
            b: [w(6), w(7), w(8)],
            out: [w(9), w(10), w(11)],
        },
        Op::CubicInverse {
            a: [w(9), w(10), w(11)],
            out: [w(12), w(13), w(14)],
        },
    ];
    let alu_ids = (0..ops.len() as u32).collect();
    let cubic_ids = (ops.len() as u32..(ops.len() + cubic.len()) as u32).collect();
    let mut operations = ops;
    operations.extend(cubic);
    let hash_id = operations.len() as u32;
    operations.push(Op::Poseidon {
        input: std::array::from_fn(|i| i as u32),
        output: std::array::from_fn(|i| (i + 8) as u32),
    });
    Program {
        operations,
        rows: vec![
            Row::Public(0),
            Row::Public(1),
            Row::Alu(alu_ids),
            Row::Alu(vec![]),
            Row::Cubic(cubic_ids),
            Row::Poseidon(hash_id),
        ],
        references: vec![0, 1, u32::MAX, 3],
        publics: 40,
        witnesses: 8,
        height: 16,
        construction_host_bytes: usize::MAX,
    }
}

#[test]
fn borrowed_manifest_matches_frozen_encoding_for_all_operations() {
    let program = all_operations();
    let expected = legacy(&program);
    assert_eq!(program.manifest_fields(), expected);
    let mut actual = vec![];
    program
        .emit_manifest(&mut |v| {
            actual.push(v);
            Ok(())
        })
        .unwrap();
    assert_eq!(actual, expected);
    let mut other = program.clone();
    other.construction_host_bytes = 0;
    assert_eq!(other.manifest_fields(), expected);
}

#[test]
fn manifest_rejects_invalid_shared_operation_indices_and_hash_families() {
    for row in [
        Row::Alu(vec![u32::MAX]),
        Row::Cubic(vec![u32::MAX]),
        Row::Poseidon(u32::MAX),
        Row::Poseidon(0),
    ] {
        let mut program = all_operations();
        program.rows[0] = row;
        assert!(program.emit_manifest(&mut |_| Ok(())).is_err());
    }
}

#[test]
fn borrowed_manifest_stops_immediately_when_consumer_rejects() {
    let program = all_operations();
    let expected = legacy(&program);
    for end in 0..expected.len() {
        let mut seen = 0;
        let result = program.emit_manifest(&mut |field| {
            assert_eq!(field, expected[seen]);
            if seen == end {
                return Err("stop".into());
            }
            seen += 1;
            Ok(())
        });
        assert_eq!(result.err().as_deref(), Some("stop"));
        assert_eq!(seen, end);
    }
}
