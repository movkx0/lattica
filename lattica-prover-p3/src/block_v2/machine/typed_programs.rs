//! Separate five-key research registry. These compilers do not establish
//! recursive proof feasibility, host authorization, or production acceptance.
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;

use super::program::Val;
use super::programs::{
    self, assert_constant, finish, public, registry, Compiled, COUNT, LEVEL, MODE, PUBLIC_VALUES,
    ROOT,
};
use super::verifier::{self, CompileError, ProofInputs};
use super::ProgramBuilder;
use crate::block_v2::{
    commitment::{self, Context, Kind},
    profile::{self, Config},
    typed_leaf::ContextAir,
};
use crate::{htlc_air as htlc, joinsplit_air as js};

pub type Caps = programs::Caps<5>;
pub const HTLC: u64 = 4;
pub const ISSUANCE: u64 = 5;

/// The mint amount and HTLC height are bound inside the typed statement digest.
/// The host must separately check them against its own policy and chain state.
pub fn wrapper(
    height: usize,
    caps: &Caps,
    mode: u64,
    wallet_public: &[Val],
    proof: &Proof<Config>,
) -> Result<Compiled, CompileError> {
    if mode == programs::WRAPPER {
        return programs::wrapper(height, caps, wallet_public, proof);
    }
    let (count, kind) = match mode {
        HTLC => (htlc::N_PUBLIC, Kind::Htlc),
        ISSUANCE => (js::N_PUBLIC, Kind::Coinbase),
        _ => return Err(CompileError::Shape("typed wrapper mode")),
    };
    if wallet_public.len() != count {
        return Err(CompileError::Shape("typed wallet statement"));
    }
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], mode);
    assert_constant(&mut b, public[LEVEL], 0);
    assert_constant(&mut b, public[COUNT], 1);
    let wallet = inputs.bases(&mut b, wallet_public);
    let mut inner = wallet.clone();
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0; 32],
    }
    .to_fields();
    inner.extend(context[..8].iter().map(|&v| b.constant(Val::from_u64(v))));
    inner.extend_from_slice(&public[8..16]);
    if mode == HTLC {
        b.assert_zero(wallet[htlc::PI_MINT]);
        verifier::uni::verify(
            &mut b,
            &mut inputs,
            &ContextAir(htlc::HtlcAir),
            htlc::HEIGHT,
            &inner,
            proof,
        )?;
    } else {
        let inverse = b.inverse(wallet[js::PI_MINT]);
        let product = b.mul(wallet[js::PI_MINT], inverse);
        assert_constant(&mut b, product, 1);
        verifier::uni::verify(
            &mut b,
            &mut inputs,
            &ContextAir(js::JoinSplitAir),
            js::HEIGHT,
            &inner,
            proof,
        )?;
    }
    let tag = kind as u64;
    let digest = b.hash_fields(commitment::STATEMENT + tag, &wallet);
    let mut fields = public[..16].to_vec();
    fields.push(b.constant(Val::from_u64(tag)));
    fields.extend(digest);
    let root = b.hash_fields(commitment::LEAF, &fields);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::typed_leaf;
    use p3_field::PrimeField64;

    fn check(mode: u64, values: Vec<Val>, bytes: Vec<u8>, chain: [u8; 32]) {
        let caps: Caps = core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        let height = 1 << 19;
        let proof: Proof<Config> = postcard::from_bytes(&bytes[72..]).unwrap();
        let context = Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: chain,
        };
        let kind = if mode == HTLC {
            Kind::Htlc
        } else {
            Kind::Coinbase
        };
        let fields: Vec<_> = values.iter().map(|v| v.as_canonical_u64()).collect();
        let entry = commitment::Entry {
            kind,
            statement_digest: commitment::statement_digest(kind as u8, &fields).unwrap(),
        };
        let node = commitment::leaf(context, entry).unwrap();
        let public = programs::statement(node, mode);
        let compiled = wrapper(height, &caps, mode, &values, &proof).unwrap();
        compiled
            .program
            .evaluate(&public, &compiled.witness)
            .unwrap();
        eprintln!(
            "typed wrapper mode={mode} rows={} height={} wires={}",
            compiled.program.active_rows(),
            compiled.program.height(),
            compiled.program.wire_count()
        );
        for index in [0, 8, MODE, LEVEL, COUNT, ROOT] {
            let mut wrong = public;
            wrong[index] += Val::ONE;
            assert!(compiled
                .program
                .evaluate(&wrong, &compiled.witness)
                .is_err());
        }
        let mut wrong = values;
        wrong[0] += Val::ONE;
        let changed = wrapper(height, &caps, mode, &wrong, &proof).unwrap();
        assert_eq!(compiled.program, changed.program);
        assert!(changed.program.evaluate(&public, &changed.witness).is_err());
        let legacy: programs::Caps =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        assert_ne!(
            programs::profile_id(height, &legacy).unwrap(),
            context.profile_id
        );
        let mut caps = caps;
        caps[(mode - 1) as usize][0][0] += Val::ONE;
        assert_ne!(
            programs::profile_id(height, &caps).unwrap(),
            context.profile_id
        );
    }

    #[test]
    fn typed_compilers_enforce_real_leaf_proofs_and_kind() {
        let context = Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [41; 32],
        };
        let mut htlc = htlc::demo_htlc_witness();
        for refund in [false, true] {
            if refund {
                htlc.inputs[0].nk = [9, 90];
                htlc.inputs[0].div = Val::from_u64(2);
                htlc.inputs[0].mode = Val::ZERO;
                htlc.current_height = htlc.inputs[0].timeout;
            }
            check(
                HTLC,
                htlc::public_values(&htlc),
                typed_leaf::prove_htlc_research(&htlc, &context).unwrap(),
                context.chain_id,
            );
        }
        let mut issuance = js::demo_witness();
        issuance.mint = 7;
        issuance.outputs[0].value += 7;
        check(
            ISSUANCE,
            js::public_values(&issuance),
            typed_leaf::prove_issuance_research(&issuance, &context, 7).unwrap(),
            context.chain_id,
        );
    }

    #[test]
    fn every_typed_key_is_bound_by_empty_program() {
        let mut caps: Caps =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        let height = 1 << 19;
        let context = Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: [41; 32],
        };
        let public = programs::statement(
            commitment::empty_subtree(context, 6).unwrap(),
            programs::EMPTY,
        );
        let compiled = programs::empty(height, &caps).unwrap();
        compiled
            .program
            .evaluate(&public, &compiled.witness)
            .unwrap();
        for i in 0..5 {
            caps[i][0][0] += Val::ONE;
            let changed = programs::empty(height, &caps).unwrap();
            assert!(changed.program.evaluate(&public, &changed.witness).is_err());
            caps[i][0][0] -= Val::ONE;
        }
    }
}
