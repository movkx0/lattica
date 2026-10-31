//! Independent range audit: compare the candidate with the prior constrained
//! relation and an integer oracle. These are host trace diagnostics, not proofs.

use super::{assert_at_most, canonical_from_bits_q, canonical_q, input_q, ConstraintContext, Q};
use crate::{Error, GOLDILOCKS_MODULUS};
use lattica_pq_ringct_research::rust_verify::constraints_crypto::CryptoObligations;
use lattica_prover_p3::block_v2::machine::{
    pq_modular,
    program::{ConstructionLimits, Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::PrimeCharacteristicRing;

fn builder(publics: usize) -> ProgramBuilder {
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: 1 << 20,
            max_wires: 1 << 15,
            max_input_values: 1 << 10,
        },
    )
    .unwrap()
}

fn range_program(bound: Option<u64>, candidate: bool) -> MachineAir {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let source = c.input(0);
        let output = match bound {
            Some(bound) => {
                if candidate {
                    assert_at_most(&mut c, source, bound, "audit_range").unwrap();
                } else {
                    pq_modular::assert_at_most(c.builder, source, bound).unwrap();
                }
                source
            }
            None => {
                let residue = if candidate {
                    canonical_q(&mut c, source, "audit_canonical").unwrap()
                } else {
                    let modulus = pq_modular::Modulus::new(Q as u32).unwrap();
                    pq_modular::canonical(c.builder, source, modulus)
                };
                assert_eq!(u64::from(residue.modulus().value()), Q);
                residue.wire()
            }
        };
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(output, public);
    }
    assert_eq!(witness.len(), 1);
    assert!(crypto.ntt.is_empty() && crypto.mul.is_empty());
    assert!(crypto.shake.is_empty() && crypto.aes.is_empty());
    MachineAir::new(b.finish(None).unwrap())
}

fn accepts(air: &MachineAir, public: Val, witness: Val) -> bool {
    air.trace(&[public], &[witness]).map(drop).is_ok()
}

#[test]
fn small_bounds_exhaustively_match_reference_and_integer_interval() {
    for bound in 0..=33 {
        let candidate = range_program(Some(bound), true);
        let reference = range_program(Some(bound), false);
        for value in 0..=65 {
            let field = Val::from_u64(value);
            let expected = value <= bound;
            assert_eq!(
                accepts(&candidate, field, field),
                expected,
                "{value} <= {bound}"
            );
            assert_eq!(
                accepts(&reference, field, field),
                expected,
                "reference {value} <= {bound}"
            );
        }
        assert!(!accepts(&candidate, -Val::ONE, -Val::ONE));
        assert!(!accepts(&reference, -Val::ONE, -Val::ONE));
    }
}

#[test]
fn every_u32_width_and_real_quotient_boundary_matches_reference() {
    let mut bounds = vec![Q - 1, 127, 20 * (Q - 1) + 2];
    for width in 1..=32 {
        let power = 1_u64 << width;
        bounds.extend([power - 2, power - 1]);
        if power < u64::from(u32::MAX) {
            bounds.extend([power, power + 1]);
        }
    }
    bounds.sort_unstable();
    bounds.dedup();
    for bound in bounds {
        let candidate = range_program(Some(bound), true);
        let reference = range_program(Some(bound), false);
        for value in [
            0,
            1,
            bound / 2,
            bound.saturating_sub(1),
            bound,
            bound + 1,
            1_u64 << 32,
        ] {
            let field = Val::from_u64(value);
            let expected = value <= bound;
            assert_eq!(
                accepts(&candidate, field, field),
                expected,
                "{value} <= {bound}"
            );
            assert_eq!(
                accepts(&reference, field, field),
                expected,
                "reference {value} <= {bound}"
            );
        }
        for value in [-Val::ONE, -Val::from_u64(Q), -Val::from_u64(1_u64 << 32)] {
            assert!(!accepts(&candidate, value, value));
            assert!(!accepts(&reference, value, value));
        }
    }
}

#[test]
fn sealed_q_values_bind_source_and_match_legacy_canonicality() {
    let candidate = range_program(None, true);
    let reference = range_program(None, false);
    let mut values = vec![0, 1, Q - 1, Q, Q + 1, (1 << 28) - 1, 1 << 28, 1 << 32];
    for width in 1..=28 {
        let power = 1_u64 << width;
        values.extend([power - 1, power, power + 1]);
    }
    for value in values {
        let field = Val::from_u64(value);
        let expected = value < Q;
        assert_eq!(accepts(&candidate, field, field), expected, "{value} < Q");
        assert_eq!(
            accepts(&reference, field, field),
            expected,
            "reference {value} < Q"
        );
        assert!(!accepts(&candidate, field + Val::ONE, field));
        assert!(!accepts(&reference, field + Val::ONE, field));
    }
    for field in [-Val::ONE, -Val::from_u64(Q), -Val::from_u64(1 << 28)] {
        assert!(!accepts(&candidate, field, field));
        assert!(!accepts(&reference, field, field));
    }
}

fn bits_program(width: usize) -> MachineAir {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let bits = (0..width).map(|_| c.input(0)).collect::<Vec<_>>();
        let residue = canonical_from_bits_q(&mut c, &bits, "audit_bits").unwrap();
        assert_eq!(u64::from(residue.modulus().value()), Q);
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(residue.wire(), public);
    }
    assert_eq!(witness.len(), width);
    MachineAir::new(b.finish(None).unwrap())
}

#[test]
fn short_and_full_bit_encodings_reject_boolean_and_output_mutations() {
    for width in [0, 1, 7, 27, 28] {
        let air = bits_program(width);
        let maximum = ((1_u64 << width) - 1).min(Q - 1);
        for value in [0, maximum / 2, maximum] {
            let public = Val::from_u64(value);
            let witness = (0..width)
                .map(|i| Val::from_u64((value >> i) & 1))
                .collect::<Vec<_>>();
            air.trace(&[public], &witness).unwrap();
            assert!(air.trace(&[public + Val::ONE], &witness).is_err());
            for i in 0..width {
                for mutation in [Val::ONE - witness[i], Val::from_u64(2), -Val::ONE] {
                    let mut wrong = witness.clone();
                    wrong[i] = mutation;
                    assert!(
                        air.trace(&[public], &wrong).is_err(),
                        "width {width}, bit {i}"
                    );
                }
            }
        }
        if width == 28 {
            for value in [Q, Q + 1, (1 << 28) - 1] {
                let witness = (0..width)
                    .map(|i| Val::from_u64((value >> i) & 1))
                    .collect::<Vec<_>>();
                assert!(air.trace(&[Val::from_u64(value)], &witness).is_err());
            }
        }
    }
}

#[test]
fn invalid_geometry_and_native_values_are_refused_before_builder_changes() {
    let mut b = builder(0);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut b,
        witness: &mut witness,
        crypto: &mut crypto,
    };
    let wire = c.input(0);
    let counters = |c: &ConstraintContext<'_, '_>| {
        let count = c.builder.construction_counters();
        (
            count.wires,
            count.witnesses,
            count.operations,
            count.requested_bytes_peak,
            c.witness.len(),
        )
    };
    let before = counters(&c);
    for bound in [u64::from(u32::MAX) + 1, GOLDILOCKS_MODULUS, u64::MAX] {
        assert!(matches!(
            assert_at_most(&mut c, wire, bound, "audit_invalid"),
            Err(Error::Range)
        ));
        assert_eq!(counters(&c), before);
    }
    assert!(matches!(
        canonical_from_bits_q(&mut c, &[wire; 29], "audit_invalid"),
        Err(Error::Geometry)
    ));
    assert_eq!(counters(&c), before);
    for value in [
        Q,
        Q + 1,
        1 << 28,
        GOLDILOCKS_MODULUS,
        GOLDILOCKS_MODULUS + 1,
        u64::MAX,
    ] {
        assert!(matches!(
            input_q(&mut c, value, "audit_invalid"),
            Err(Error::NonCanonical)
        ));
        assert_eq!(counters(&c), before);
    }
}

fn input_program(value: u64) -> (Program, Vec<Val>) {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let residue = input_q(&mut c, value, "audit_private_hint").unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(residue.constrained.wire(), public);
    }
    (b.finish(None).unwrap(), witness)
}

#[test]
fn native_hint_values_do_not_change_program_or_permit_noncanonical_reuse() {
    let (zero, _) = input_program(0);
    for value in [0, 1, Q / 2, Q - 1] {
        let (program, witness) = input_program(value);
        assert!(program == zero, "a private hint changed the public program");
        let air = MachineAir::new(program);
        air.trace(&[Val::from_u64(value)], &witness).unwrap();
        for fresh in [0, 1, Q - 1] {
            let field = Val::from_u64(fresh);
            assert!(accepts(&air, field, field));
        }
        for invalid in [Val::from_u64(Q), Val::from_u64(Q + 1), -Val::ONE] {
            assert!(!accepts(&air, invalid, invalid));
        }
        air.trace(&[Val::from_u64(value)], &witness).unwrap();
    }
}
