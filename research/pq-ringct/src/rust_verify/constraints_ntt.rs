//! Explicit NTT proof obligations and a separately provable exact component.
//!
//! The caller must verify every registered component proof and equate both
//! commitments inside its consuming proof. A pending request is never evidence
//! that the transform is correct. Polynomial coefficients are canonical field
//! elements, with modulus and exact coefficient count in each commitment.
use super::{
    arithmetic,
    constraints::{ConstraintContext, ResidueValue, SignedValue},
    constraints_crypto::CryptoObligations,
    generic::{self, Backend, Polynomial},
    D, Q, QHAT,
};
use lattica_prover_p3::block_v2::machine::{
    program::{Val, Wire},
    Program, ProgramBuilder,
};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

/// One framed canonical-polynomial root is reusable across typed predicates.
/// Operation, input/output role, modulus and exact batch ordering are pinned by
/// the registered AIR and its consuming join, not selected by a proof artifact.
pub const POLYNOMIAL_DOMAIN: u64 = 0x504f_4c59_5f50_5131;
/// Signed integer polynomial root: initial [domain, 0, 256, 0], then the
/// canonical Goldilocks representatives of four coefficients per absorption.
/// Individual source/operation predicates enforce integer bounds; bounds are
/// deliberately excluded from the root so identical signed values can reuse it.
pub const SIGNED_POLYNOMIAL_DOMAIN: u64 = 0x5349_474e_5051_3031;
pub const INPUT_DOMAIN: u64 = POLYNOMIAL_DOMAIN;
pub const OUTPUT_DOMAIN: u64 = POLYNOMIAL_DOMAIN;
pub const PUBLIC_VALUES: usize = 8;

#[derive(Clone, Debug)]
pub struct PendingNtt {
    pub modulus: u64,
    pub input: Polynomial<ResidueValue>,
    pub output: Polynomial<ResidueValue>,
    pub input_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

pub(crate) fn commit(
    c: &mut ConstraintContext<'_, '_>,
    q: u64,
    values: &Polynomial<ResidueValue>,
) -> [Wire; 4] {
    let key = (q, values.map(|value| value.constrained.wire()));
    if let Some(root) = c.crypto.polynomial_commitments.get(&key) {
        return *root;
    }
    let zero = c.builder.constant(Val::ZERO);
    let mut state = [
        c.builder.constant(Val::from_u64(POLYNOMIAL_DOMAIN)),
        c.builder.constant(Val::from_u64(q)),
        c.builder.constant(Val::from_usize(D)),
        zero,
    ];
    for chunk in values.chunks_exact(4) {
        let mut input = [zero; 8];
        input[..4].copy_from_slice(&state);
        for i in 0..4 {
            input[4 + i] = chunk[i].constrained.wire();
        }
        state.copy_from_slice(&c.builder.poseidon(input)[..4]);
    }
    c.crypto.polynomial_commitments.insert(key, state);
    state
}
pub fn commit_values(domain: u64, q: u64, values: &[u64; D]) -> [Val; 4] {
    assert!(q == Q || q == QHAT);
    assert!(values.iter().all(|&value| value < q));
    let mut state = [
        Val::from_u64(domain),
        Val::from_u64(q),
        Val::from_usize(D),
        Val::ZERO,
    ];
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    for chunk in values.chunks_exact(4) {
        let mut input = [Val::ZERO; 8];
        input[..4].copy_from_slice(&state);
        for i in 0..4 {
            input[4 + i] = Val::from_u64(chunk[i]);
        }
        permutation.permute_mut(&mut input);
        state.copy_from_slice(&input[..4]);
    }
    state
}

pub fn commit_signed_values(values: &[i64; D]) -> [Val; 4] {
    assert!(values
        .iter()
        .all(|value| value.unsigned_abs() <= i32::MAX as u64));
    let mut state = [
        Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
        Val::ZERO,
        Val::from_usize(D),
        Val::ZERO,
    ];
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    for chunk in values.chunks_exact(4) {
        let mut input = [Val::ZERO; 8];
        input[..4].copy_from_slice(&state);
        for (lane, &value) in chunk.iter().enumerate() {
            input[4 + lane] = if value < 0 {
                -Val::from_u64(value.unsigned_abs())
            } else {
                Val::from_u64(value as u64)
            };
        }
        permutation.permute_mut(&mut input);
        state.copy_from_slice(&input[..4]);
    }
    state
}

pub fn request_ntt(
    c: &mut ConstraintContext<'_, '_>,
    input: &Polynomial<SignedValue>,
    q: u64,
) -> Polynomial<ResidueValue> {
    let residues = input.map(|value| c.to_residue(value, q));
    let expected = arithmetic::ntt(&input.map(|value| value.value), q);
    let output = expected.map(|value| c.residue(value, q));
    let input_commitment = commit(c, q, &residues);
    let output_commitment = commit(c, q, &output);
    c.crypto.ntt.push(PendingNtt {
        modulus: q,
        input: residues,
        output,
        input_commitment,
        output_commitment,
    });
    output
}

pub struct CompiledNtt {
    pub program: Program,
    pub witness: Vec<Val>,
    pub public_values: [Val; PUBLIC_VALUES],
    pub output: [u64; D],
}

/// Compile a reusable modulus-specific program. Input values only populate
/// witness hints; the program manifest is identical for every canonical input.
pub fn compile(q: u64, input: &[u64; D]) -> Result<CompiledNtt, String> {
    if !matches!(q, Q | QHAT) || input.iter().any(|&value| value >= q) {
        return Err("noncanonical NTT component input".into());
    }
    let mut builder = ProgramBuilder::new(PUBLIC_VALUES).map_err(|e| format!("{e:?}"))?;
    let mut witness = Vec::new();
    let mut crypto = CryptoObligations::new([0; 32]);
    let output;
    {
        let mut c = ConstraintContext {
            builder: &mut builder,
            witness: &mut witness,
            crypto: &mut crypto,
        };
        let input = input.map(|value| c.residue(value, q));
        // Direct inline residue transform bypasses the delegation hook.
        let result = generic::ntt_residues(&mut c, &input, q);
        output = result.map(|value| value.value);
        let before = commit(&mut c, q, &input);
        let after = commit(&mut c, q, &result);
        for (index, wire) in before.into_iter().chain(after).enumerate() {
            let public = c.builder.public(index).map_err(|e| format!("{e:?}"))?;
            c.builder.assert_equal(wire, public);
        }
    }
    assert!(
        crypto.shake.is_empty()
            && crypto.aes.is_empty()
            && crypto.ntt.is_empty()
            && crypto.mul.is_empty()
    );
    let mut public_values = [Val::ZERO; PUBLIC_VALUES];
    public_values[..4].copy_from_slice(&commit_values(INPUT_DOMAIN, q, input));
    public_values[4..].copy_from_slice(&commit_values(OUTPUT_DOMAIN, q, &output));
    let program = builder.finish(None).map_err(|e| format!("{e:?}"))?;
    Ok(CompiledNtt {
        program,
        witness,
        public_values,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::{analysis, MachineAir};

    #[test]
    fn committed_ntt_component_matches_oracle_and_rejects_hints() {
        let signed = core::array::from_fn(|i| (i as i64 * 37) % 1013 - 506);
        for q in [Q, QHAT] {
            let input = signed.map(|v| v.rem_euclid(q as i64) as u64);
            let compiled = compile(q, &input).unwrap();
            assert_eq!(compiled.output, arithmetic::ntt(&signed, q));
            let zero = compile(q, &[0; D]).unwrap();
            assert_eq!(
                compiled.program.manifest_fields(),
                zero.program.manifest_fields(),
                "witness must not specialize NTT program"
            );
            let air = MachineAir::new(compiled.program);
            let geometry = analysis::analyze(&air).unwrap();
            eprintln!(
                "NTT component q={q} wires={} height={} retained_lde_bytes={}",
                air.program().wire_count(),
                air.program().height(),
                geometry.retained_lde_bytes
            );
            air.trace(&compiled.public_values, &compiled.witness)
                .unwrap();
            for index in [
                0,
                255,
                256,
                compiled.witness.len() / 2,
                compiled.witness.len() - 1,
            ] {
                let mut changed = compiled.witness.clone();
                changed[index] += Val::ONE;
                assert!(
                    air.trace(&compiled.public_values, &changed).is_err(),
                    "unbound NTT witness index={index}"
                );
            }
            let mut changed = compiled.public_values;
            changed[4] += Val::ONE;
            assert!(air.trace(&changed, &compiled.witness).is_err());
        }
    }
}
