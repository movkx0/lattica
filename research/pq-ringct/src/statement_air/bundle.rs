//! Bridge from the exact public statement digest to ordered polynomial roots.
//! This interface never creates unchecked modular values. Arithmetic components
//! consume the same canonical polynomial commitments and prove their relations.

use super::{StatementAir, BUNDLE_DOMAIN, HEIGHT, POLYNOMIALS, PUBLIC_VALUES};
use crate::{
    native_packet::STATEMENT_BYTES,
    rust_verify::{constraints_ntt, D, Q},
};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::Config,
};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

pub(crate) fn absorb(state: &mut [Val; 4], chunk: [Val; 4]) -> [Val; 8] {
    let mut input = [Val::ZERO; 8];
    input[..4].copy_from_slice(state);
    input[4..].copy_from_slice(&chunk);
    let mut output = input;
    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut output);
    state.copy_from_slice(&output[..4]);
    input
}

pub(crate) fn initial(setup: &[u8; 32]) -> [Val; 4] {
    let mut state = [
        Val::from_u64(BUNDLE_DOMAIN),
        Val::from_u64(Q),
        Val::from_usize(D),
        Val::from_usize(POLYNOMIALS),
    ];
    for bytes in setup.chunks_exact(16) {
        let _ = absorb(
            &mut state,
            core::array::from_fn(|i| {
                Val::from_u32(u32::from_le_bytes(
                    bytes[4 * i..4 * i + 4].try_into().unwrap(),
                ))
            }),
        );
    }
    state
}

#[derive(Clone, Debug)]
pub struct StatementBundle {
    pub setup_seed: [u8; 32],
    pub polynomial_roots: [[Val; 4]; POLYNOMIALS],
    pub serial_words: [u32; 16],
}

impl StatementBundle {
    /// Native witness helper only. The AIR proves canonicality and serial
    /// distinctness independently; this helper's return is not acceptance.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != STATEMENT_BYTES {
            return Err("statement length");
        }
        let setup_seed = bytes[..32].try_into().unwrap();
        let mut polynomial_roots = [[Val::ZERO; 4]; POLYNOMIALS];
        for (root, encoded) in polynomial_roots
            .iter_mut()
            .zip(bytes[32..STATEMENT_BYTES - 64].chunks_exact(1024))
        {
            let values: [u64; D] = core::array::from_fn(|i| {
                u64::from(u32::from_le_bytes(
                    encoded[4 * i..4 * i + 4].try_into().unwrap(),
                ))
            });
            if values.iter().any(|&x| x >= Q) {
                return Err("noncanonical coefficient");
            }
            *root = constraints_ntt::commit_values(constraints_ntt::POLYNOMIAL_DOMAIN, Q, &values);
        }
        let serial_words = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[STATEMENT_BYTES - 64 + 4 * i..STATEMENT_BYTES - 60 + 4 * i]
                    .try_into()
                    .unwrap(),
            )
        });
        Ok(Self {
            setup_seed,
            polynomial_roots,
            serial_words,
        })
    }

    pub fn commitment(&self) -> [Val; 4] {
        let mut state = initial(&self.setup_seed);
        for &root in &self.polynomial_roots {
            let _ = absorb(&mut state, root);
        }
        for words in self.serial_words.chunks_exact(4) {
            let _ = absorb(
                &mut state,
                core::array::from_fn(|i| Val::from_u32(words[i])),
            );
        }
        state
    }
}

pub struct StatementProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}

/// Emit both the complete child STARK verifier and the exact ordered bundle
/// binding. These are witness wires, never host-side equality/acceptance flags.
/// A successful compile is only a component of a complete MatRiCT proof.
pub fn verify_bundle(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    setup_seed: [u8; 32],
    expected_statement: [Wire; 4],
    polynomial_roots: &[[Wire; 4]; POLYNOMIALS],
    serial_words: &[Wire; 16],
    artifact: &StatementProof,
) -> Result<(), CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    verifier::uni::verify(
        b,
        inputs,
        &StatementAir { setup_seed },
        HEIGHT,
        &public,
        &artifact.proof,
    )?;
    for i in 0..4 {
        b.assert_equal(public[i], expected_statement[i]);
    }
    let mut state = initial(&setup_seed).map(|x| b.constant(x));
    for chunk in polynomial_roots.iter().copied().chain(
        serial_words
            .chunks_exact(4)
            .map(|chunk| chunk.try_into().unwrap()),
    ) {
        let mut input = [state[0]; 8];
        input[..4].copy_from_slice(&state);
        input[4..].copy_from_slice(&chunk);
        state.copy_from_slice(&b.poseidon(input)[..4]);
    }
    for i in 0..4 {
        b.assert_equal(state[i], public[4 + i]);
    }
    Ok(())
}
