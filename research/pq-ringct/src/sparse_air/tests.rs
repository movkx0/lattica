use super::*;
use crate::rust_verify::{constraints_ntt::commit_signed_values, primitives, D};
use p3_air::check_all_constraints;

fn accepts(air: &SparseAir, w: &SparseWitness) -> bool {
    check_all_constraints(air, &w.trace, &w.public_values, Some(2))
        .failures
        .is_empty()
}
fn input(kind: Kind, salt: u8) -> Vec<u8> {
    primitives::shake(&[salt; 32], kind.input_len())
}
fn oracle(kind: Kind, bytes: &[u8]) -> Option<[i64; D]> {
    let mut output = [0; D];
    let signs = bytes[..kind.sign_bytes()]
        .iter()
        .enumerate()
        .fold(0u64, |a, (i, &v)| a + (u64::from(v) << (8 * i)));
    let mut cursor = kind.sign_bytes();
    for count in 0..kind.weight() {
        loop {
            let raw = *bytes.get(cursor)?;
            cursor += 1;
            let index = match kind {
                Kind::AlphaPrime39 => usize::from(raw),
                Kind::ChallengeX44 => {
                    4 * usize::from(raw & 63) + if count < 4 { count } else { (count - 4) / 10 }
                }
            };
            if output[index] == 0 {
                output[index] = 1 - 2 * ((signs >> count) & 1) as i64;
                break;
            }
        }
    }
    Some(output)
}
#[test]
fn sparse_samplers_match_native_challenges_and_commit_every_byte() {
    for salt in [0, 31, 255] {
        let seed = [salt; 32];
        let mut aes = primitives::AesStream::new(&seed, 0x4368);
        let _ = aes.bytes(643 * 4);
        let bytes = aes.bytes(127);
        let air = SparseAir::new(Kind::AlphaPrime39);
        let w = air.generate(&bytes).unwrap();
        assert_eq!(w.polynomial, primitives::expand_alpha(&seed).unwrap().1);
        assert!(accepts(&air, &w));
        assert_eq!(
            &w.public_values[..4],
            &crate::shake_air::commit_bytes(air.kind.input_domain(), &bytes)
        );
        assert_eq!(&w.public_values[4..], &commit_signed_values(&w.polynomial));

        let zero = [0u64; D];
        let mut transcript = seed.to_vec();
        transcript.extend_from_slice(&vec![0u8; 2 * D * 4]);
        let bytes = primitives::shake(&transcript, 137);
        let air = SparseAir::new(Kind::ChallengeX44);
        let w = air.generate(&bytes).unwrap();
        assert_eq!(
            w.polynomial,
            primitives::hash_x(&seed, &zero, &zero, &[], &[], &[]).unwrap()
        );
        assert!(accepts(&air, &w));
        assert_eq!(
            &w.public_values[..4],
            &crate::shake_air::commit_bytes(air.kind.input_domain(), &bytes)
        );
        assert_eq!(&w.public_values[4..], &commit_signed_values(&w.polynomial));
        for group in 0..4 {
            assert_eq!(
                w.polynomial
                    .iter()
                    .skip(group)
                    .step_by(4)
                    .filter(|&&v| v != 0)
                    .count(),
                11
            );
        }
    }
}
#[test]
fn sparse_sampler_duplicate_exhaustion_order_signs_and_tail_are_bound() {
    for kind in [Kind::AlphaPrime39, Kind::ChallengeX44] {
        let air = SparseAir::new(kind);
        let mut bytes = input(kind, 17);
        // A repeated byte is an explicit rejected draw in the ordinary phase.
        let first = kind.sign_bytes() + 4;
        bytes[first + 1] = bytes[first];
        let w = air.generate(&bytes).unwrap();
        assert_eq!(Some(w.polynomial), oracle(kind, &bytes));
        assert!(accepts(&air, &w));
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 128;
        let tail = air.generate(&changed).unwrap();
        assert!(accepts(&air, &tail));
        assert_eq!(w.polynomial, tail.polynomial);
        assert_ne!(&w.public_values[..4], &tail.public_values[..4]);
        changed = bytes.clone();
        changed[0] ^= 1;
        let sign = air.generate(&changed).unwrap();
        assert!(accepts(&air, &sign));
        assert_ne!(w.polynomial, sign.polynomial);
        let exhausted = air.generate(&vec![0; kind.input_len()]).unwrap();
        assert!(oracle(kind, &vec![0; kind.input_len()]).is_none());
        assert!(!accepts(&air, &exhausted));
        assert!(air.generate(&bytes[..bytes.len() - 1]).is_err());
    }
}
#[test]
fn sparse_sampler_rejects_trace_and_public_root_mutations() {
    for kind in [Kind::AlphaPrime39, Kind::ChallengeX44] {
        let air = SparseAir::new(kind);
        let mut w = air.generate(&input(kind, 19)).unwrap();
        assert!(accepts(&air, &w));
        for (r, c) in [
            (0, OUTPUT),
            (1, SIGNS),
            (7, BYTE),
            (8, BYTE_BITS),
            (9, LOW),
            (10, HIGH),
            (11, COUNT),
            (12, COUNT_BITS),
            (13, COUNT_LOW),
            (14, COUNT_HIGH),
            (15, GROUP),
            (16, REMAINING),
            (17, READ),
            (18, SIGN),
            (19, TAKE),
            (20, BUFFER),
            (31, BYTE_ACC),
            (220, POLY_ACC),
            (255, POSEIDON),
        ] {
            w.trace.values[r * WIDTH + c] += Val::ONE;
            assert!(!accepts(&air, &w), "kind={kind:?} row={r} column={c}");
            w.trace.values[r * WIDTH + c] -= Val::ONE;
        }
        for i in 0..PUBLIC_VALUES {
            w.public_values[i] += Val::ONE;
            assert!(!accepts(&air, &w));
            w.public_values[i] -= Val::ONE;
        }
    }
}
#[test]
#[ignore = "actual sampler STARK and typed recursive trace; run under a memory guard"]
fn sparse_actual_stark_and_typed_recursive_join() {
    use lattica_prover_p3::block_v2::{
        machine::{program::ProofInputs, MachineAir, ProgramBuilder},
        profile,
    };
    for kind in [Kind::AlphaPrime39, Kind::ChallengeX44] {
        let air = SparseAir::new(kind);
        let w = air.generate(&input(kind, 23)).unwrap();
        let config = profile::make_config();
        let proof = p3_uni_stark::prove(&config, &air, w.trace, &w.public_values);
        p3_uni_stark::verify(&config, &air, &proof, &w.public_values).unwrap();
        let mut bad = w.public_values;
        bad[4] += Val::ONE;
        assert!(p3_uni_stark::verify(&config, &air, &proof, &bad).is_err());
        let mut artifact = join::SparseArtifact {
            public_values: w.public_values,
            proof,
        };
        join::verify_native(kind, &artifact).unwrap();
        let wrong_kind = if kind == Kind::AlphaPrime39 {
            Kind::ChallengeX44
        } else {
            Kind::AlphaPrime39
        };
        assert!(join::verify_native(wrong_kind, &artifact).is_err());
        artifact.proof.degree_bits += 1;
        assert!(join::verify_native(kind, &artifact).is_err());
        artifact.proof.degree_bits -= 1;
        let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
        let mut inputs = ProofInputs::default();
        let roots: [_; PUBLIC_VALUES] = core::array::from_fn(|i| b.public(i).unwrap());
        join::verify_sampler(
            &mut b,
            &mut inputs,
            kind,
            &roots[..4].try_into().unwrap(),
            &roots[4..].try_into().unwrap(),
            &artifact,
        )
        .unwrap();
        let program = b.finish(None).unwrap();
        eprintln!("sparse {kind:?}: width={WIDTH} height={HEIGHT}; recursive active_rows={} height={} wires={}",program.active_rows(),program.height(),program.wire_count());
        let machine = MachineAir::new(program);
        machine.trace(&w.public_values, &inputs.values).unwrap();
        assert!(machine.trace(&bad, &inputs.values).is_err());
        bad = w.public_values;
        bad[0] += Val::ONE;
        assert!(machine.trace(&bad, &inputs.values).is_err());
    }
}
