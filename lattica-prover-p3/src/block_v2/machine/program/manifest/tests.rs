use super::*;

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
                ops.clone()
            }
            Row::Cubic(ops) => {
                out.push(2);
                ops.clone()
            }
            Row::Poseidon { input, output } => {
                out.push(1);
                vec![Op::Poseidon {
                    input: *input,
                    output: *output,
                }]
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
    Program {
        operations: vec![],
        rows: vec![
            Row::Public(0),
            Row::Public(1),
            Row::Alu(ops),
            Row::Alu(vec![]),
            Row::Cubic(cubic),
            Row::Poseidon {
                input: std::array::from_fn(w),
                output: std::array::from_fn(|i| w(i + 8)),
            },
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
