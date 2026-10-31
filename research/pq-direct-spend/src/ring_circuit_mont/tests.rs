use super::super::public_constant;
use super::*;
use crate::{ring, ring_native as native, Context};
use lattica_pq_ringct_research::rust_verify::{
    constraints_crypto::CryptoObligations,
    generic::{self, Backend},
};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder, Val},
    MachineAir,
};
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy, Debug)]
struct Metrics {
    wires: usize,
    active_rows: usize,
    padded_rows: usize,
    requested_bytes_peak: usize,
    hints: usize,
}

fn builder(publics: usize) -> ProgramBuilder {
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: super::super::PROGRAM_BYTES,
            max_wires: super::super::MAX_WIRES,
            max_input_values: super::super::MAX_INPUTS,
        },
    )
    .unwrap()
}

fn one_case(
    optimized: bool,
    q: u64,
    a: u64,
    b: u64,
    known_a: bool,
    known_b: bool,
) -> (Program, Vec<Val>, Metrics) {
    let mut builder = builder(1);
    let mut witness = Vec::with_capacity(8);
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let a = if known_a {
            public_constant(&mut c, a, q).unwrap()
        } else {
            c.residue(a, q)
        };
        let b = if known_b {
            public_constant(&mut c, b, q).unwrap()
        } else {
            c.residue(b, q)
        };
        let out = if optimized {
            mont(&mut c, a, b, q, "test_montgomery")
        } else {
            c.mont(a, b, q)
        };
        let expected = c.builder.public(0).unwrap();
        c.builder.assert_equal(out.constrained.wire(), expected);
    }
    let counters = builder.construction_counters();
    assert!(!counters.resource_failed);
    let program = builder.finish(None).unwrap();
    let metrics = Metrics {
        wires: program.wire_count(),
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        requested_bytes_peak: counters.requested_bytes_peak,
        hints: witness.len(),
    };
    (program, witness, metrics)
}

#[test]
fn exact_montgomery_matches_existing_and_native_reference() {
    for q in [Q, QHAT] {
        let r = (1_u64 << 32) % q;
        for (a, b) in [(0, 0), (1, 1), (q - 1, q - 1), (q / 2, r), (q - 1, 0)] {
            let expected = Val::from_u64(native::Native.mont(a, b, q));
            for (known_a, known_b) in [(false, false), (false, true), (true, false), (true, true)] {
                for optimized in [false, true] {
                    let (program, witness, _) = one_case(optimized, q, a, b, known_a, known_b);
                    let air = MachineAir::new(program);
                    air.trace(&[expected], &witness).unwrap();
                    assert!(air.trace(&[expected + Val::ONE], &witness).is_err());
                }
            }
        }
    }
}

#[test]
fn canonical_inputs_and_private_reduction_hints_remain_constrained() {
    for q in [Q, QHAT] {
        let r = (1_u64 << 32) % q;
        for factor in [0, r, 1, q - 1] {
            let (program, witness, _) = one_case(true, q, 5, factor, false, true);
            assert_eq!(
                witness.len(),
                if factor == 0 || factor == r { 1 } else { 3 }
            );
            let air = MachineAir::new(program);
            let expected = [Val::from_u64(native::Native.mont(5, factor, q))];
            air.trace(&expected, &witness).unwrap();
            // Canonical input checking survives public-zero/identity folding.
            let mut bad = witness.clone();
            bad[0] = Val::from_u64(q);
            assert!(air.trace(&expected, &bad).is_err());
            for index in 1..witness.len() {
                for replacement in [witness[index] + Val::ONE, Val::from_u64(q)] {
                    let mut bad = witness.clone();
                    bad[index] = replacement;
                    assert!(air.trace(&expected, &bad).is_err());
                }
            }
        }
        // Neither private zero nor a private identity may select a folded
        // program. Both modular reductions keep all four constrained hints.
        for (a, b) in [(0, r), (5, 7)] {
            let (program, witness, _) = one_case(true, q, a, b, false, false);
            assert_eq!(witness.len(), 6);
            let air = MachineAir::new(program);
            let expected = [Val::from_u64(native::Native.mont(a, b, q))];
            air.trace(&expected, &witness).unwrap();
            for index in 2..6 {
                let mut bad = witness.clone();
                bad[index] += Val::ONE;
                assert!(air.trace(&expected, &bad).is_err());
            }
        }
    }
}

#[test]
fn public_factor_representation_saves_rows_without_witness_specialization() {
    for q in [Q, QHAT] {
        for factor in [0, (1_u64 << 32) % q, 1, q - 1] {
            let (_, _, old) = one_case(false, q, 7, factor, false, true);
            let (program, _, new) = one_case(true, q, 7, factor, false, true);
            eprintln!("direct_montgomery_representation q={q} public_factor={factor} old_wires={} new_wires={} old_active_rows={} new_active_rows={} old_padded_rows={} new_padded_rows={} old_builder_requested_peak={} new_builder_requested_peak={} old_hints={} new_hints={} proof_started=false",
                old.wires,new.wires,old.active_rows,new.active_rows,old.padded_rows,new.padded_rows,
                old.requested_bytes_peak,new.requested_bytes_peak,old.hints,new.hints);
            assert!(new.wires < old.wires, "{old:?} -> {new:?}");
            assert!(new.active_rows < old.active_rows, "{old:?} -> {new:?}");
            // Bounded maps and operation Vecs grow in steps and overlap their
            // old/new backing. Fewer wires do not imply a lower requested peak
            // in each small case: report both, retaining the actual bound.
            assert!(old.requested_bytes_peak <= super::super::PROGRAM_BYTES);
            assert!(new.requested_bytes_peak <= super::super::PROGRAM_BYTES);
            let (other_witness_program, _, _) = one_case(true, q, q - 1, factor, false, true);
            assert_eq!(program, other_witness_program);
        }
    }
    let (zero_private, _, _) = one_case(true, Q, 0, 0, false, false);
    let (other_private, _, _) = one_case(true, Q, 13, 17, false, false);
    assert_eq!(zero_private, other_private);
}

fn ownership_matrix_block(changed_serial: bool) -> (Program, Vec<Val>, [Val; 4]) {
    // A differential diagnostic for the exact first four coefficients of one
    // ownership equation. NTT states are private canonical test inputs here;
    // this is not a decomposition, proof API, or complete ownership circuit.
    let (statement, witness) = ring::fixture(Context([19; 32])).unwrap();
    let params = native::parameters(&statement.setup_seed).unwrap();
    let transformed = witness.spending[0]
        .each_ref()
        .map(|p| native::ntt(&mut native::Native, p));
    let mut serial = statement.serials[0];
    if changed_serial {
        serial[0] ^= 1;
    }
    let g = native::serial_image(&serial).unwrap();
    let expected = std::array::from_fn(|i| {
        Val::from_u64(statement.ring[witness.selected_pair][0].public_key[0][i])
    });
    // Public coefficients are derived by the existing native ring-product
    // oracle on Montgomery basis vectors, so all wrap signs/twiddles and the
    // original partial-NTT order are exercised without copying private tables.
    let mut weights = [[[0_u64; 4]; 4]; 4];
    for group in 0..4 {
        for input in 0..4 {
            let mut basis = [0; ring::D];
            basis[input] = (1_u64 << 32) % Q;
            let product =
                generic::mul_residues(&mut native::Native, &params.mat1[group][0], &basis, Q);
            weights[group][input].copy_from_slice(&product[..4]);
        }
    }
    let mut builder = builder(4);
    let mut hints = Vec::with_capacity(512);
    let mut crypto = CryptoObligations::new(statement.setup_seed);
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut hints,
            crypto: &mut crypto,
        };
        let base: [_; 4] = std::array::from_fn(|i| c.residue(transformed[0][i], Q));
        let terms: [[_; 4]; 4] = std::array::from_fn(|group| {
            std::array::from_fn(|i| c.residue(transformed[4 + group][i], Q))
        });
        for output in 0..4 {
            let mut result = base[output];
            for group in 0..4 {
                for input in 0..4 {
                    let factor = public_constant(&mut c, weights[group][input][output], Q).unwrap();
                    let product = budget::Limited(&mut c, "test_ownership_matrix").mont(
                        factor,
                        terms[group][input],
                        Q,
                    );
                    result =
                        budget::Limited(&mut c, "test_ownership_matrix").add(result, product, Q);
                }
            }
            let serial_value = public_constant(&mut c, g[0][output], Q).unwrap();
            result = budget::Limited(&mut c, "test_ownership_matrix").add(result, serial_value, Q);
            let public = c.builder.public(output).unwrap();
            c.builder.assert_equal(result.constrained.wire(), public);
        }
    }
    (builder.finish(None).unwrap(), hints, expected)
}

#[test]
fn ownership_matrix_block_matches_reference_and_rejects_mutations() {
    let (program, hints, expected) = ownership_matrix_block(false);
    let air = MachineAir::new(program);
    air.trace(&expected, &hints).unwrap();
    let mut bad = hints.clone();
    bad[0] += Val::ONE;
    assert!(air.trace(&expected, &bad).is_err());
    bad[0] = Val::from_u64(Q);
    assert!(air.trace(&expected, &bad).is_err());
    let mut wrong_owner = expected;
    wrong_owner[0] += Val::ONE;
    assert!(air.trace(&wrong_owner, &hints).is_err());
    let (changed_serial, hints, expected) = ownership_matrix_block(true);
    assert!(MachineAir::new(changed_serial)
        .trace(&expected, &hints)
        .is_err());
}
