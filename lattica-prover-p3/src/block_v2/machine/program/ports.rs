//! Operation bus ports are bounded by the eight-word Poseidon state. Keep these
//! short-lived lists inline while compiling, validating and materializing rows.
//! Hints' execution dependencies are checked separately from their bus ports.

use super::Wire;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WirePorts {
    wires: [Wire; 8],
    len: usize,
}

impl<const N: usize> From<[Wire; N]> for WirePorts {
    fn from(source: [Wire; N]) -> Self {
        assert!(N <= 8, "operation exceeds the bus port bound");
        let mut wires = [Wire(0); 8];
        wires[..N].copy_from_slice(&source);
        Self { wires, len: N }
    }
}

impl core::ops::Deref for WirePorts {
    type Target = [Wire];

    fn deref(&self) -> &Self::Target {
        &self.wires[..self.len]
    }
}

impl IntoIterator for WirePorts {
    type Item = Wire;
    type IntoIter = core::iter::Take<core::array::IntoIter<Wire, 8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.wires.into_iter().take(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Op, Val};
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn operation_ports_preserve_order_multiplicity_and_hint_semantics() {
        let a = Wire(0);
        let b = Wire(7);
        let c = Wire(19);
        let out = Wire(33);
        let cases: [(Op, &[Wire], &[Wire]); 13] = [
            (Op::Input { index: 5, out }, &[], &[out]),
            (
                Op::Constant {
                    value: Val::ONE,
                    out,
                },
                &[],
                &[out],
            ),
            (
                Op::Bit {
                    source: b,
                    bit: 63,
                    out,
                },
                &[],
                &[out],
            ),
            // Hints must not gain AIR reads; their true execution dependencies
            // remain part of witness scheduling and construction validation.
            (
                Op::SelectHint {
                    entries: vec![a, b],
                    bits: vec![c],
                    out,
                },
                &[],
                &[out],
            ),
            (Op::Add { a, b, out }, &[a, b], &[out]),
            (Op::Mul { a: b, b, out }, &[b, b], &[out]),
            (Op::Equal { a: c, b: a }, &[c, a], &[]),
            (Op::Boolean { a: b }, &[b], &[]),
            (Op::Inverse { a: c, out }, &[c], &[out]),
            (Op::Select { bit: c, a, b, out }, &[a, b, c], &[out]),
            (
                Op::CubicMul {
                    a: [a, b, c],
                    b: [c, b, a],
                    out: [out, c, b],
                },
                &[a, b, c, c, b, a],
                &[out, c, b],
            ),
            (
                Op::CubicInverse {
                    a: [c, a, b],
                    out: [b, out, a],
                },
                &[c, a, b],
                &[b, out, a],
            ),
            (
                Op::Poseidon {
                    input: [0, 7, 19, 7, 0, 33, 7, u32::MAX],
                    output: [u32::MAX, 33, 19, 7, 0, 19, 33, 7],
                },
                &[a, b, c, b, a, out, b, Wire(u32::MAX as usize)],
                &[Wire(u32::MAX as usize), out, c, b, a, c, out, b],
            ),
        ];
        for (operation, expected_reads, expected_writes) in cases {
            for (ports, expected) in [
                (operation.reads(), expected_reads),
                (operation.writes(), expected_writes),
            ] {
                assert_eq!(&*ports, expected, "{operation:?}");
                let mut actual = ports.into_iter();
                assert_eq!(actual.len(), expected.len());
                for &wire in expected {
                    assert_eq!(actual.next(), Some(wire), "{operation:?}");
                }
                assert_eq!(actual.len(), 0);
                assert_eq!(actual.next(), None);
                assert_eq!(actual.next(), None);
            }
        }
    }
}
