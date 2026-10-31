use super::super::{
    bits, bits_ranges, compile_with_representation_diagnostics, linear, ntt::PublicTransform,
    ternary, CompilerCapacityProfile, CompilerMemoryProfile, CompilerRepresentation,
};
use super::*;
use crate::{ring, ring_native as native, Context, Profile};
use lattica_pq_ringct_research::rust_verify::{constraints_crypto::CryptoObligations, D};
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder},
    MachineAir,
};
use std::time::Instant;

fn builder(publics: usize) -> ProgramBuilder {
    // An existing explicit profile for a whole nine-NTT commitment component.
    // No fallback or production capacity/default change is made by this test.
    let limits = CompilerMemoryProfile::Program2GiB.limits();
    ProgramBuilder::new_with_construction_limits(
        publics,
        ConstructionLimits {
            max_requested_program_bytes: limits.program_byte_limit as usize,
            max_wires: limits.wire_limit,
            max_input_values: limits.input_limit.min(limits.wire_limit - publics),
        },
    )
    .unwrap()
}

#[test]
fn exact_q_range_rejects_noncanonical_and_field_alias_values() {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let input = c.input(0);
        let output = canonical_q(&mut c, input, "range_boundaries").unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(output.wire(), public);
    }
    let air = MachineAir::new(b.finish(None).unwrap());
    for value in [0, 1, Q / 2, Q - 2, Q - 1] {
        let value = Val::from_u64(value);
        air.trace(&[value], &[value]).unwrap();
        assert!(air.trace(&[value + Val::ONE], &[value]).is_err());
    }
    for invalid in [
        Val::from_u64(Q),
        Val::from_u64(Q + 1),
        Val::from_u64(1 << Q_BITS),
        -Val::ONE,
    ] {
        assert!(air.trace(&[invalid], &[invalid]).is_err());
    }
}

#[test]
fn public_bound_checks_cover_zero_all_ones_u32_limit_and_refusal() {
    for bound in [
        0,
        1,
        127,
        Q - 1,
        20 * (Q - 1) + 2,
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
    ] {
        let mut b = builder(0);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let input = c.input(0);
        assert_at_most(&mut c, input, bound, "range_u32_bound").unwrap();
        let air = MachineAir::new(b.finish(None).unwrap());
        for value in [0, bound / 2, bound] {
            air.trace(&[], &[Val::from_u64(value)]).unwrap();
        }
        for value in [Val::from_u64(bound + 1), -Val::ONE] {
            assert!(air.trace(&[], &[value]).is_err());
        }
    }
    let mut b = builder(0);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let mut c = ConstraintContext {
        builder: &mut b,
        witness: &mut witness,
        crypto: &mut crypto,
    };
    let input = c.input(0);
    let before = c.builder.construction_counters().wires;
    for bound in [u64::from(u32::MAX) + 1, u64::MAX] {
        assert!(matches!(
            assert_at_most(&mut c, input, bound, "range_invalid_bound"),
            Err(Error::Range)
        ));
        assert_eq!(c.builder.construction_counters().wires, before);
    }
}

#[test]
fn reused_bit_encoding_binds_every_bit_booleanity_and_strict_comparison() {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let bits: [Wire; Q_BITS as usize] = std::array::from_fn(|_| c.input(0));
        let output = canonical_from_bits_q(&mut c, &bits, "range_explicit_bits").unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(output.wire(), public);
    }
    let air = MachineAir::new(b.finish(None).unwrap());
    let encode = |value: u64| {
        std::array::from_fn::<_, { Q_BITS as usize }, _>(|i| Val::from_u64((value >> i) & 1))
    };
    for value in [0, 1, Q - 1] {
        let valid = encode(value);
        air.trace(&[Val::from_u64(value)], &valid).unwrap();
        for i in 0..Q_BITS as usize {
            let mut wrong = valid;
            wrong[i] = Val::ONE - wrong[i];
            assert!(air.trace(&[Val::from_u64(value)], &wrong).is_err());
            wrong[i] = Val::from_u64(2);
            assert!(air.trace(&[Val::from_u64(value)], &wrong).is_err());
        }
    }
    assert!(air.trace(&[Val::from_u64(Q)], &encode(Q)).is_err());
}

#[test]
fn amount_bits_keep_exact_52_bit_range_and_zero_high_padding() {
    let mut b = builder(1);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let (amount, encoded) = bits_ranges(&mut c, 0).unwrap();
        let public = c.builder.public(0).unwrap();
        c.builder.assert_equal(amount, public);
        let mut sum = c.builder.constant(Val::ZERO);
        for (i, bit) in encoded.iter().enumerate() {
            let coefficient = c.builder.constant(Val::from_u64(1_u64 << i));
            let term = c.builder.mul(bit.constrained.wire(), coefficient);
            sum = c.builder.add(sum, term);
        }
        c.builder.assert_equal(amount, sum);
    }
    assert_eq!(
        witness.len(),
        1,
        "amount bits must reuse the original amount hint"
    );
    let air = MachineAir::new(b.finish(None).unwrap());
    for value in [0, 1, (1 << 51) + 3, (1 << 52) - 1] {
        let field = Val::from_u64(value);
        air.trace(&[field], &[field]).unwrap();
    }
    for value in [Val::from_u64(1 << 52), -Val::ONE] {
        assert!(air.trace(&[value], &[value]).is_err());
    }
}

#[test]
fn selected_account_range_keeps_private_choice_out_of_program_shape() {
    fn compile(s: &ring::Statement, choice: usize) -> (Program, Vec<Val>, [Val; 64]) {
        let mut b = builder(64);
        let mut witness = Vec::new();
        let mut crypto = CryptoObligations::new([0; 32]);
        {
            let mut c = ConstraintContext {
                builder: &mut b,
                witness: &mut witness,
                crypto: &mut crypto,
            };
            let selectors: [Wire; 10] = std::array::from_fn(|i| {
                let wire = c.input(u64::from(i == choice));
                c.builder.assert_bool(wire);
                wire
            });
            let mut sum = c.builder.constant(Val::ZERO);
            for wire in selectors {
                sum = c.builder.add(sum, wire);
            }
            let one = c.builder.constant(Val::ONE);
            c.builder.assert_equal(sum, one);
            let output =
                super::super::selected_ranges(&mut c, s, &selectors, 0, true, 0, choice).unwrap();
            for i in 0..64 {
                let public = c.builder.public(i).unwrap();
                c.builder
                    .assert_equal(output[D - 64 + i].constrained.wire(), public);
            }
        }
        let public =
            std::array::from_fn(|i| Val::from_u64(s.ring[choice][0].public_key[0][D - 64 + i]));
        (b.finish(None).unwrap(), witness, public)
    }
    let (statement, _) = ring::fixture(Context([39; 32])).unwrap();
    let (p, witness, public) = compile(&statement, 0);
    let (other, other_witness, other_public) = compile(&statement, 9);
    assert!(p == other, "private selection changed the range program");
    let air = MachineAir::new(p);
    air.trace(&public, &witness).unwrap();
    air.trace(&other_public, &other_witness).unwrap();
    for index in [0, 9, 10, witness.len() - 1] {
        let mut wrong = witness.clone();
        wrong[index] += Val::ONE;
        assert!(air.trace(&public, &wrong).is_err());
    }
}

struct Fixture {
    opening: [native::Signed; 9],
    mat1: Vec<[native::Poly; 4]>,
    mat2: Vec<[native::Poly; 3]>,
    value: u64,
    ntt_expected: native::Poly,
    commitment_expected: [native::Poly; 5],
}

fn fixture() -> Fixture {
    let (statement, witness) = ring::fixture(Context([39; 32])).unwrap();
    let params = native::parameters(&statement.setup_seed).unwrap();
    let opening = witness.input_openings[0];
    let value = witness.input_values[0];
    let encoded = std::array::from_fn(|i| (value >> i) & 1);
    let ntt_expected = native::ntt(&mut native::Native, &opening[0]);
    let commitment_expected = native::commitment(
        &mut native::Native,
        &opening,
        &encoded,
        &params.mat1,
        &params.mat2,
    );
    Fixture {
        opening,
        mat1: params.mat1,
        mat2: params.mat2,
        value,
        ntt_expected,
        commitment_expected,
    }
}

#[derive(Clone, Copy, Debug)]
enum Component {
    Ntt,
    Commitment,
}

#[derive(Debug)]
struct Metrics {
    wires: usize,
    active_rows: usize,
    padded_rows: usize,
    hints: usize,
    requested_before_finish: usize,
    packed_peak: usize,
    public_table_seconds: f64,
}

/// A whole NTT or complete nine-NTT/five-polynomial commitment. Native oracles
/// and public parameter derivation stay outside timing. Each construction
/// includes one public transform derivation and binds all output coefficients:
/// the last 64 publicly and the rest to diagnostic-only oracle constants.
fn component(
    f: &Fixture,
    kind: Component,
    reuse: bool,
    bind_all: bool,
) -> (Program, Vec<Val>, [Val; 64], Metrics) {
    let start = Instant::now();
    let transform = PublicTransform::derive();
    let public_table_seconds = start.elapsed().as_secs_f64();
    let expected: Vec<u64> = match kind {
        Component::Ntt => f.ntt_expected.to_vec(),
        Component::Commitment => f.commitment_expected.iter().flatten().copied().collect(),
    };
    let mut b = builder(64);
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    {
        let mut c = ConstraintContext {
            builder: &mut b,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let output: Vec<ResidueValue> = match kind {
            Component::Ntt => {
                let input = f.opening[0].map(|value| c.signed(value, 1));
                if reuse {
                    ternary::ntt_ranges(&mut c, &input, &transform, "ranges_ntt_component").unwrap()
                } else {
                    ternary::ntt(&mut c, &input, &transform, "ranges_ntt_component").unwrap()
                }
                .to_vec()
            }
            Component::Commitment => {
                let input = f.opening.map(|p| p.map(|value| c.signed(value, 1)));
                let (_, bits) = if reuse {
                    bits_ranges(&mut c, f.value)
                } else {
                    bits(&mut c, f.value)
                }
                .unwrap();
                let result = if reuse {
                    let r = ternary::ntt_many_ranges(
                        &mut c,
                        &input,
                        &transform,
                        "ranges_commitment_component",
                    )
                    .unwrap();
                    linear::commitment_from_ntt_ranges(
                        &mut c,
                        &r,
                        &bits,
                        &f.mat1,
                        &f.mat2,
                        "ranges_commitment_component",
                    )
                    .unwrap()
                } else {
                    let r = ternary::ntt_many(
                        &mut c,
                        &input,
                        &transform,
                        "ranges_commitment_component",
                    )
                    .unwrap();
                    linear::commitment_from_ntt(
                        &mut c,
                        &r,
                        &bits,
                        &f.mat1,
                        &f.mat2,
                        "ranges_commitment_component",
                    )
                    .unwrap()
                };
                result.into_iter().flatten().collect()
            }
        };
        for (i, result) in output.iter().enumerate() {
            assert_eq!(result.value, expected[i]);
            let oracle = if i >= output.len() - 64 {
                Some(c.builder.public(i - (output.len() - 64)).unwrap())
            } else if bind_all {
                Some(c.builder.constant(Val::from_u64(expected[i])))
            } else {
                None
            };
            if let Some(oracle) = oracle {
                c.builder.assert_equal(result.constrained.wire(), oracle);
            }
        }
    }
    assert!(
        crypto.ntt.is_empty()
            && crypto.mul.is_empty()
            && crypto.aes.is_empty()
            && crypto.shake.is_empty()
    );
    let before = b.construction_counters();
    assert!(!before.resource_failed);
    let p = b.finish(None).unwrap();
    let metrics = Metrics {
        wires: p.wire_count(),
        active_rows: p.active_rows(),
        padded_rows: p.height(),
        hints: witness.len(),
        requested_before_finish: before.requested_bytes_peak,
        packed_peak: p.construction_host_bytes(),
        public_table_seconds,
    };
    let public = std::array::from_fn(|i| Val::from_u64(expected[expected.len() - 64 + i]));
    (p, witness, public, metrics)
}

#[test]
fn whole_components_match_prior_representation_and_native_oracle() {
    let f = fixture();
    for kind in [Component::Ntt, Component::Commitment] {
        for reuse in [false, true] {
            let (p, witness, public, _) = component(&f, kind, reuse, true);
            let air = MachineAir::new(p);
            air.trace(&public, &witness).unwrap();
            for i in [0, witness.len() - 2, witness.len() - 1] {
                let mut wrong = witness.clone();
                wrong[i] += Val::ONE;
                assert!(air.trace(&public, &wrong).is_err());
            }
            let mut wrong = public;
            wrong[63] += Val::ONE;
            assert!(air.trace(&wrong, &witness).is_err());
        }
    }
}

#[test]
fn range_ntt_shape_is_independent_of_private_values() {
    let mut f = fixture();
    let (p, witness, public, _) = component(&f, Component::Ntt, true, false);
    for input in [f.opening[0].map(|v| -v), [0; D], [-1; D], [1; D]] {
        f.opening[0] = input;
        f.ntt_expected = native::ntt(&mut native::Native, &input);
        let (other, other_witness, other_public, _) = component(&f, Component::Ntt, true, false);
        assert!(p == other, "private values changed the range NTT program");
        let air = MachineAir::new(other);
        air.trace(&public, &witness).unwrap();
        air.trace(&other_public, &other_witness).unwrap();
    }
}

#[test]
fn range_selector_preserves_defaults_and_pre_arithmetic_refusals() {
    let selected = CompilerRepresentation::FusedTernaryRangesV1;
    assert_eq!(
        selected.name().parse::<CompilerRepresentation>().unwrap(),
        selected
    );
    assert_eq!(
        serde_json::to_string(&selected).unwrap(),
        "\"fused-ternary-ranges-v1\""
    );
    assert_eq!(
        CompilerRepresentation::default(),
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2
    );
    for invalid in [
        "ranges",
        "fused-ternary-ranges-v2",
        "auto",
        "fused-ternary-ranges-v1 ",
    ] {
        assert!(invalid.parse::<CompilerRepresentation>().is_err());
    }
    let context = Context([39; 32]);
    let (mut statement, witness) = ring::fixture(context).unwrap();
    let profile = CompilerCapacityProfile::default();
    let allowance = profile.limits().required_host_bytes as usize;
    for (expected, allowance) in [(context, allowance - 1), (Context([40; 32]), allowance)] {
        let failure = compile_with_representation_diagnostics(
            &statement, &witness, expected, profile, selected, allowance,
        )
        .err()
        .unwrap();
        assert_eq!(failure.representation, selected.name());
        assert_eq!(failure.wires, None);
        assert!(!failure.cryptographic_proof_started);
    }
    statement.profile = Profile::PrivateNoteDirectV1;
    let failure = compile_with_representation_diagnostics(
        &statement, &witness, context, profile, selected, allowance,
    )
    .err()
    .unwrap();
    assert_eq!(failure.error, Error::Profile);
}

#[test]
#[ignore = "serialized complete NTT and commitment component pairs; no proof/workflow claim"]
fn alternating_range_components_screen() {
    let f = fixture();
    for kind in [Component::Ntt, Component::Commitment] {
        for pair in 0..3 {
            let order = if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for reuse in order {
                let start = Instant::now();
                let (p, witness, public, m) = component(&f, kind, reuse, true);
                let compile_seconds = start.elapsed().as_secs_f64();
                let start = Instant::now();
                let air = MachineAir::new(p);
                let trace = air.trace(&public, &witness).unwrap();
                let evaluate_seconds = start.elapsed().as_secs_f64();
                eprintln!("range_component kind={kind:?} pair={pair} representation={} wires={} active_rows={} padded_rows={} hints={} builder_requested_peak_before_finish={} packed_admitted_peak={} public_table_seconds={:.9} compile_seconds={compile_seconds:.9} host_evaluation_seconds={evaluate_seconds:.9} proof_started=false complete_workflow=false",
                    if reuse { "fused-ternary-ranges-v1" } else { "fused-ternary-ntt-v1" }, m.wires, m.active_rows, m.padded_rows, m.hints, m.requested_before_finish, m.packed_peak, m.public_table_seconds);
                drop(trace);
                drop(air);
                drop(witness);
            }
        }
    }
}
