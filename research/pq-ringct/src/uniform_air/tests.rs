use super::*;
use crate::rust_verify::{
    constraints_ntt::{commit_values, POLYNOMIAL_DOMAIN},
    primitives,
};
use p3_air::check_all_constraints;
fn accepts(air: &UniformAir, w: &UniformWitness) -> bool {
    check_all_constraints(air, &w.trace, &w.public_values, Some(2))
        .failures
        .is_empty()
}
fn bytes(kind: Kind, seed: [u8; 32]) -> Vec<u8> {
    primitives::AesStream::new(&seed, if kind == Kind::SampleG4 { 0 } else { 0x4368 })
        .bytes(kind.draws() * 4)
}
fn roots(w: &UniformWitness) -> Vec<[Val; 4]> {
    w.polynomials
        .iter()
        .map(|p| commit_values(POLYNOMIAL_DOMAIN, Q, p))
        .collect()
}
#[test]
fn uniform_matches_native_aes_samplers_and_ordered_roots() {
    for kind in [Kind::SampleG4, Kind::ExpandAlpha2] {
        for seed in [[0; 32], [27; 32]] {
            let air = UniformAir::new(kind);
            let raw = bytes(kind, seed);
            let w = air.generate(&raw).unwrap();
            let expected = if kind == Kind::SampleG4 {
                primitives::sample_g(&seed).unwrap()
            } else {
                primitives::expand_alpha(&seed).unwrap().0
            };
            assert_eq!(w.polynomials, expected);
            assert!(accepts(&air, &w));
            assert_eq!(
                &w.public_values[..4],
                &crate::shake_air::commit_bytes(
                    crate::rust_verify::constraints_crypto::AES_OUTPUT_DOMAIN,
                    &raw
                )
            );
            assert_eq!(&w.public_values[4..], &air.bundle(&roots(&w)).unwrap());
        }
    }
}
#[test]
fn uniform_threshold_rejection_canonical_reduction_exhaustion_and_tail() {
    for kind in [Kind::SampleG4, Kind::ExpandAlpha2] {
        let air = UniformAir::new(kind);
        let mut candidates = vec![0u32; kind.draws()];
        candidates[..7].copy_from_slice(&[
            ACCEPT_LIMIT as u32,
            u32::MAX,
            (Q + 19) as u32,
            0,
            (Q - 1) as u32,
            ACCEPT_LIMIT as u32 - 1,
            17,
        ]);
        let raw: Vec<_> = candidates.iter().flat_map(|v| v.to_le_bytes()).collect();
        let w = air.generate(&raw).unwrap();
        assert!(accepts(&air, &w));
        assert_eq!(&w.polynomials[0][..5], &[19, 0, Q - 1, Q - 1, 17]);
        let mut tail = raw.clone();
        *tail.last_mut().unwrap() = 255;
        let changed = air.generate(&tail).unwrap();
        assert!(accepts(&air, &changed));
        assert_eq!(w.polynomials, changed.polynomials);
        assert_ne!(&w.public_values[..4], &changed.public_values[..4]);
        assert!(!accepts(
            &air,
            &air.generate(&vec![255; raw.len()]).unwrap()
        ));
        assert!(air.generate(&raw[..raw.len() - 1]).is_err());
    }
}
#[test]
fn uniform_trace_and_bundle_mutations_fail() {
    let kind = Kind::ExpandAlpha2;
    let air = UniformAir::new(kind);
    let mut w = air.generate(&bytes(kind, [51; 32])).unwrap();
    assert!(accepts(&air, &w));
    for (r, c) in [
        (0, RAW),
        (1, RAW_BITS),
        (2, ACCEPT),
        (3, COMPARE_BITS),
        (4, REMAINDER),
        (5, REMAINDER_BITS),
        (6, SLACK_BITS),
        (7, QUOTIENT_BITS),
        (8, COUNT),
        (9, COUNT_BITS),
        (10, TAKE),
        (11, END_FOUR),
        (12, LOW_FULL),
        (13, HIGH_FULL),
        (14, END_POLY),
        (15, PREVIOUS),
        (16, BUFFER),
        (17, BYTE_ACC),
        (18, POLY_ACC),
        (19, BUNDLE_ACC),
        (20, BYTE_POSEIDON),
        (21, POLY_POSEIDON),
        (22, BUNDLE_POSEIDON),
    ] {
        w.trace.values[r * WIDTH + c] += Val::ONE;
        assert!(!accepts(&air, &w), "row={r} column={c}");
        w.trace.values[r * WIDTH + c] -= Val::ONE;
    }
    let mut ordered = roots(&w);
    ordered.swap(0, 1);
    assert_ne!(&w.public_values[4..], &air.bundle(&ordered).unwrap());
    for i in 0..8 {
        w.public_values[i] += Val::ONE;
        assert!(!accepts(&air, &w));
        w.public_values[i] -= Val::ONE;
    }
}
#[test]
#[ignore = "actual uniform STARK and recursive trace; memory guard required"]
fn uniform_actual_stark_and_typed_recursive_join() {
    use lattica_prover_p3::block_v2::{
        machine::{program::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    for kind in [Kind::SampleG4, Kind::ExpandAlpha2] {
        let air = UniformAir::new(kind);
        let w = air.generate(&bytes(kind, [73; 32])).unwrap();
        let roots = roots(&w);
        let config = profile::make_config();
        let proof = p3_uni_stark::prove(&config, &air, w.trace, &w.public_values);
        p3_uni_stark::verify(&config, &air, &proof, &w.public_values).unwrap();
        let mut artifact = join::UniformArtifact {
            public_values: w.public_values,
            proof,
        };
        join::verify_native(kind, &artifact).unwrap();
        let wrong_kind = if kind == Kind::SampleG4 {
            Kind::ExpandAlpha2
        } else {
            Kind::SampleG4
        };
        assert!(join::verify_native(wrong_kind, &artifact).is_err());
        artifact.proof.degree_bits += 1;
        assert!(join::verify_native(kind, &artifact).is_err());
        artifact.proof.degree_bits -= 1;
        let mut b = ProgramBuilder::new(4 + 4 * roots.len()).unwrap();
        let mut inputs = ProofInputs::default();
        let input = core::array::from_fn(|i| b.public(i).unwrap());
        let output: Vec<_> = (0..roots.len())
            .map(|p| core::array::from_fn(|i| b.public(4 + 4 * p + i).unwrap()))
            .collect();
        join::verify_sampler(&mut b, &mut inputs, kind, &input, &output, &artifact).unwrap();
        let program = b.finish(None).unwrap();
        eprintln!("uniform {kind:?}: width={WIDTH} height={}; recursive active_rows={} height={} wires={}",air.height(),program.active_rows(),program.height(),program.wire_count());
        let mut public = w.public_values[..4].to_vec();
        public.extend(roots.into_iter().flatten());
        let machine = MachineAir::new(program);
        machine.trace(&public, &inputs.values).unwrap();
        public[4] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
        public[4] -= Val::ONE;
        public[0] += Val::ONE;
        assert!(machine.trace(&public, &inputs.values).is_err());
    }
}
