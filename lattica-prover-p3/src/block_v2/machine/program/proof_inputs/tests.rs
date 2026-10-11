use super::super::{ExecutionError, Program};
use super::*;
use p3_field::PrimeCharacteristicRing;
use p3_merkle_tree::MerkleCap;

#[test]
fn value_growth_is_clipped_to_the_declared_input_limit() {
    for limit in [0, 1, 2, 3, 4, 5, 9, 10, 17] {
        let mut b = ProgramBuilder::new(3).unwrap();
        b.memory.input_limit = limit;
        let mut inputs = ProofInputs::default();
        assert!(inputs.bases(&mut b, &[]).unwrap().is_empty());
        for i in 0..limit {
            let old = inputs.values.capacity();
            assert_eq!(inputs.base(&mut b, Val::from_u64(i as u64)), Wire(3 + i));
            let new = inputs.values.capacity();
            assert!(new >= i + 1 && new <= limit);
            if new != old {
                assert!(old + new <= 2 * limit);
            }
        }
        assert_eq!(inputs.values.len(), limit);
        assert_eq!(inputs.values.capacity(), limit);
        let before = (inputs.values.clone(), b.witnesses, b.wires);
        inputs.base(&mut b, Val::ONE);
        assert_eq!(before, (inputs.values, b.witnesses, b.wires));
        assert_eq!(b.resource_failure(), Some(ExecutionError::TooLarge));
    }
}

#[test]
fn whole_input_groups_reject_before_callbacks_or_builder_mutation() {
    for (count, fields, input_limit, wire_limit) in [
        (5, 1, 4, 100),
        (2, 3, 5, 100),
        (2, 4, 7, 100),
        (3, 1, 100, 2),
    ] {
        let mut b = ProgramBuilder::new(0).unwrap();
        b.memory.input_limit = input_limit;
        b.memory.wire_limit = wire_limit;
        let mut inputs = ProofInputs::default();
        let mut calls = 0;
        let result = inputs.collect(&mut b, count, fields, |_, _, _| {
            calls += 1;
            Wire(0)
        });
        assert!(result.is_err());
        assert_eq!(calls, 0);
        assert_eq!(
            (
                b.witnesses,
                b.wires,
                b.operations.len(),
                inputs.values.capacity()
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(b.finish(None).unwrap_err(), ExecutionError::TooLarge);
    }
    let mut b = ProgramBuilder::new(0).unwrap();
    b.memory.input_limit = 5;
    let mut inputs = ProofInputs::default();
    assert!(inputs.extensions(&mut b, &[Challenge::ONE; 2]).is_err());
    assert_eq!(b.witnesses, 0);
    let mut b = ProgramBuilder::new(0).unwrap();
    b.memory.input_limit = 7;
    let mut inputs = ProofInputs::default();
    let cap = MerkleCap::new(vec![[Val::ONE; 4]; 2]);
    assert!(inputs.cap(&mut b, &cap, 1).is_err());
    assert_eq!(b.witnesses, 0);
}

#[test]
fn input_storage_stops_when_program_construction_exhausts_its_quota() {
    let mut b = ProgramBuilder::new(0).unwrap();
    b.memory.limit = Some(0);
    b.memory.input_limit = 4;
    let mut inputs = ProofInputs::default();
    assert!(inputs.bases(&mut b, &[Val::ONE; 4]).is_err());
    assert_eq!(inputs.values.capacity(), 0);
    assert_eq!(b.witnesses, 1); // The first instruction is rejected before its value buffer grows.
    let before = (b.wires, b.witnesses, b.memory.live, b.memory.peak);
    assert!(inputs.bases(&mut b, &[]).is_err());
    inputs.extension(&mut b, Challenge::ONE);
    inputs.digest(&mut b, &[Val::ONE; 4]);
    assert_eq!((b.wires, b.witnesses, b.memory.live, b.memory.peak), before);
    assert_eq!(inputs.values.capacity(), 0);
}

#[test]
fn oversized_existing_capacity_and_field_count_overflow_fail_closed() {
    let mut b = ProgramBuilder::new(0).unwrap();
    b.memory.input_limit = 16;
    let mut inputs = ProofInputs {
        values: Vec::with_capacity(17),
    };
    assert!(inputs.bases(&mut b, &[]).is_err());
    assert_eq!(b.witnesses, 0);
    let mut b = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    assert!(inputs
        .collect(&mut b, usize::MAX, 3, |_, _, _| -> Wire {
            panic!("overflow callback")
        })
        .is_err());
    assert_eq!(inputs.values.capacity(), 0);
    assert_eq!(b.witnesses, 0);
}

fn compile(reference: bool) -> (Program, Vec<Val>) {
    let mut b = ProgramBuilder::new(0).unwrap();
    let bases: Vec<_> = (1..18).map(Val::from_u64).collect();
    let ext =
        Challenge::from_basis_coefficients_slice(&[Val::ONE, Val::TWO, Val::NEG_ONE]).unwrap();
    let extensions = [ext, Challenge::ONE];
    let digest = [Val::ONE, Val::TWO, Val::NEG_ONE, Val::ZERO];
    let cap = MerkleCap::new(vec![digest; 2]);
    let values = if reference {
        let mut inputs = legacy::ProofInputs::default();
        let wires = inputs.bases(&mut b, &bases);
        let exts = inputs.extensions(&mut b, &extensions);
        let hash = inputs.digest(&mut b, &digest);
        let cap_wires = inputs.cap(&mut b, &cap, 1).unwrap();
        assert_eq!(
            cap_wires,
            vec![
                [Wire(27), Wire(28), Wire(29), Wire(30)],
                [Wire(31), Wire(32), Wire(33), Wire(34)]
            ]
        );
        assert_eq!(wires, (0..17).map(Wire).collect::<Vec<_>>());
        assert_eq!(
            exts,
            [
                [Wire(17), Wire(18), Wire(19)],
                [Wire(20), Wire(21), Wire(22)]
            ]
        );
        assert_eq!(hash, [Wire(23), Wire(24), Wire(25), Wire(26)]);
        inputs.values
    } else {
        let mut inputs = ProofInputs::default();
        let wires = inputs.bases(&mut b, &bases).unwrap();
        let exts = inputs.extensions(&mut b, &extensions).unwrap();
        let hash = inputs.digest(&mut b, &digest);
        let cap_wires = inputs.cap(&mut b, &cap, 1).unwrap();
        assert_eq!(
            cap_wires,
            vec![
                [Wire(27), Wire(28), Wire(29), Wire(30)],
                [Wire(31), Wire(32), Wire(33), Wire(34)]
            ]
        );
        assert_eq!(wires, (0..17).map(Wire).collect::<Vec<_>>());
        assert_eq!(
            exts,
            [
                [Wire(17), Wire(18), Wire(19)],
                [Wire(20), Wire(21), Wire(22)]
            ]
        );
        assert_eq!(hash, [Wire(23), Wire(24), Wire(25), Wire(26)]);
        inputs.values
    };
    (b.finish(None).unwrap(), values)
}

#[test]
fn input_groups_preserve_legacy_input_order_and_program_identity() {
    let (expected, values) = compile(true);
    let (actual, actual_values) = compile(false);
    assert_eq!(actual_values, values);
    assert_eq!(actual, expected);
    assert_eq!(actual.manifest_fields(), expected.manifest_fields());
    assert_eq!(actual.evaluate(&[], &actual_values).unwrap(), values);
}

// Frozen input collector from the preceding checkpoint.
mod legacy {
    use super::*;
    #[derive(Default)]
    pub struct ProofInputs {
        pub values: Vec<Val>,
    }
    impl ProofInputs {
        pub fn base(&mut self, b: &mut ProgramBuilder, value: Val) -> Wire {
            let wire = b.input();
            if b.resource_failure().is_none() {
                self.values.push(value);
            }
            wire
        }
        pub fn bases(&mut self, b: &mut ProgramBuilder, values: &[Val]) -> Vec<Wire> {
            values.iter().map(|&v| self.base(b, v)).collect()
        }
        pub fn extension(&mut self, b: &mut ProgramBuilder, value: Challenge) -> Extension {
            let values: &[Val] = value.as_basis_coefficients_slice();
            core::array::from_fn(|i| self.base(b, values[i]))
        }
        pub fn extensions(
            &mut self,
            b: &mut ProgramBuilder,
            values: &[Challenge],
        ) -> Vec<Extension> {
            values.iter().map(|&v| self.extension(b, v)).collect()
        }
        pub fn digest(&mut self, b: &mut ProgramBuilder, value: &[Val; 4]) -> Digest {
            value.map(|v| self.base(b, v))
        }
        pub fn cap(
            &mut self,
            b: &mut ProgramBuilder,
            value: &p3_batch_stark::Commitment<Config>,
            log_height: usize,
        ) -> Result<Vec<Digest>, CompileError> {
            if value.roots().len() != 1 << log_height.min(crate::block_v2::profile::CAP_HEIGHT) {
                return Err(CompileError::Shape("Merkle cap length"));
            }
            Ok(value.roots().iter().map(|d| self.digest(b, d)).collect())
        }
    }
}
