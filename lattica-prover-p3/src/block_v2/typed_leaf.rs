//! Context-bound typed leaves for local qualification, with no production ABI.
//!
//! These are leaf proofs, not recursive wrapper registration or block acceptance.
//! Coinbase authorization and HTLC height come from the caller's independently
//! expected host statement. Proving balance alone never authorizes issuance.
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_uni_stark::{prove, verify, Proof};

use super::{
    commitment::Context,
    leaf::LeafError,
    profile::{self, Config},
};
use crate::{htlc_air as htlc, joinsplit_air as js};

const HTLC_MAGIC: &[u8; 8] = b"LBV2HT01";
const ISSUANCE_MAGIC: &[u8; 8] = b"LBV2CB01";
const HEADER: usize = 72;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Leaf(LeafError),
    UnauthorizedIssuance,
    HeightMismatch,
}

impl From<LeafError> for Error {
    fn from(value: LeafError) -> Self {
        Self::Leaf(value)
    }
}

/// Context is absorbed as public input by the STARK transcript, as in the
/// existing context-bound JoinSplit leaf. The underlying audited constraints
/// and candidate hiding/cubic-extension parameters are unchanged.
pub(crate) struct ContextAir<A>(pub A);

impl<A: BaseAir<Val>> BaseAir<Val> for ContextAir<A> {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values() + 16
    }
    fn num_periodic_columns(&self) -> usize {
        self.0.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.0.periodic_columns()
    }
}

impl<AB: AirBuilder<F = Val>, A: Air<AB>> Air<AB> for ContextAir<A> {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

fn public(context: &Context, statement: &[Val], count: usize) -> Result<Vec<Val>, Error> {
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile.into());
    }
    if statement.len() != count {
        return Err(LeafError::WrongPublicValueCount.into());
    }
    let mut values = statement.to_vec();
    values.extend(context.to_fields().map(Val::from_u64));
    Ok(values)
}

fn encode(proof: &Proof<Config>, magic: &[u8; 8], context: &Context) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_allocvec(proof).map_err(|_| LeafError::InvalidEncoding)?;
    if payload.len() > profile::MAX_PROOF_BYTES - HEADER {
        return Err(LeafError::SizeLimit.into());
    }
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&context.profile_id);
    bytes.extend_from_slice(&context.chain_id);
    bytes.extend(payload);
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
    magic: &[u8; 8],
    context: &Context,
    height: usize,
) -> Result<Proof<Config>, Error> {
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err(LeafError::SizeLimit.into());
    }
    if bytes.len() <= HEADER || &bytes[..8] != magic {
        return Err(LeafError::InvalidEncoding.into());
    }
    if bytes[8..40] != context.profile_id {
        return Err(LeafError::WrongProfile.into());
    }
    if bytes[40..HEADER] != context.chain_id {
        return Err(LeafError::WrongContext.into());
    }
    let payload = &bytes[HEADER..];
    let (proof, rest): (Proof<Config>, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|_| LeafError::InvalidEncoding)?;
    if !rest.is_empty()
        || postcard::to_allocvec(&proof).map_err(|_| LeafError::InvalidEncoding)? != payload
    {
        return Err(LeafError::InvalidEncoding.into());
    }
    if proof.degree_bits != height.trailing_zeros() as usize + 1
        || proof.opening_proof.1.query_proofs.len() != profile::NUM_QUERIES
        || proof.commitments.random.is_none()
        || proof.opening_proof.1.query_proofs.iter().any(|query| {
            query
                .commit_phase_openings
                .iter()
                .any(|opening| opening.log_arity != 1)
        })
    {
        return Err(LeafError::InvalidShape.into());
    }
    Ok(proof)
}

/// Research prover for trusted local witnesses. Witness construction can panic.
pub fn prove_htlc_research(witness: &htlc::Witness, context: &Context) -> Result<Vec<u8>, Error> {
    if witness.mint != 0 {
        return Err(Error::UnauthorizedIssuance);
    }
    let values = public(context, &htlc::public_values(witness), htlc::N_PUBLIC)?;
    let proof = prove(
        &profile::make_config(),
        &ContextAir(htlc::HtlcAir),
        htlc::build_trace(witness),
        &values,
    );
    encode(&proof, HTLC_MAGIC, context)
}

pub fn verify_htlc_research(
    bytes: &[u8],
    context: &Context,
    statement: &[Val],
    expected_height: u64,
) -> Result<(), Error> {
    let values = public(context, statement, htlc::N_PUBLIC)?;
    if expected_height >= 1u64 << htlc::BITS
        || statement[htlc::PI_HEIGHT] != Val::from_u64(expected_height)
    {
        return Err(Error::HeightMismatch);
    }
    if statement[htlc::PI_MINT] != Val::ZERO {
        return Err(Error::UnauthorizedIssuance);
    }
    let proof = decode(bytes, HTLC_MAGIC, context, htlc::HEIGHT)?;
    verify(
        &profile::make_config(),
        &ContextAir(htlc::HtlcAir),
        &proof,
        &values,
    )
    .map_err(|_| LeafError::VerificationFailed.into())
}

fn authorized(statement: &[Val], authorized_mint: u64) -> Result<(), Error> {
    if authorized_mint == 0
        || authorized_mint >= 1u64 << js::BITS
        || statement[js::PI_MINT] != Val::from_u64(authorized_mint)
    {
        return Err(Error::UnauthorizedIssuance);
    }
    Ok(())
}

/// The external host must determine authorized_mint and enforce issuance count.
pub fn prove_issuance_research(
    witness: &js::Witness,
    context: &Context,
    authorized_mint: u64,
) -> Result<Vec<u8>, Error> {
    if witness.mint != authorized_mint
        || authorized_mint == 0
        || authorized_mint >= 1u64 << js::BITS
    {
        return Err(Error::UnauthorizedIssuance);
    }
    let values = public(context, &js::public_values(witness), js::N_PUBLIC)?;
    let proof = prove(
        &profile::make_config(),
        &ContextAir(js::JoinSplitAir),
        js::build_trace(witness),
        &values,
    );
    encode(&proof, ISSUANCE_MAGIC, context)
}

pub fn verify_issuance_research(
    bytes: &[u8],
    context: &Context,
    statement: &[Val],
    authorized_mint: u64,
) -> Result<(), Error> {
    let values = public(context, statement, js::N_PUBLIC)?;
    authorized(statement, authorized_mint)?;
    let proof = decode(bytes, ISSUANCE_MAGIC, context, js::HEIGHT)?;
    verify(
        &profile::make_config(),
        &ContextAir(js::JoinSplitAir),
        &proof,
        &values,
    )
    .map_err(|_| LeafError::VerificationFailed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> Context {
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [0x5a; 32],
        }
    }

    #[test]
    fn typed_leaf_security_is_computed_independently() {
        for security in [
            profile::base_air_security(&ContextAir(htlc::HtlcAir), htlc::HEIGHT).unwrap(),
            profile::base_air_security(&ContextAir(js::JoinSplitAir), js::HEIGHT).unwrap(),
        ] {
            eprintln!("typed leaf security: {security:?}");
            assert!(
                profile::composition_bits(security.proven_bits, profile::MAX_TREE_PROOF_STATEMENTS)
                    .unwrap()
                    >= profile::MIN_TREE_SECURITY_BITS
            );
        }
    }

    #[test]
    fn typed_policy_rejects_before_proving() {
        let ctx = context();
        let mut witness = js::demo_witness();
        assert_eq!(
            prove_issuance_research(&witness, &ctx, 0),
            Err(Error::UnauthorizedIssuance)
        );
        witness.mint = 2;
        assert_eq!(
            prove_issuance_research(&witness, &ctx, 1),
            Err(Error::UnauthorizedIssuance)
        );
        let witness = htlc::demo_htlc_witness();
        let public = htlc::public_values(&witness);
        assert_eq!(
            verify_htlc_research(&[], &ctx, &public, witness.current_height + 1),
            Err(Error::HeightMismatch)
        );
    }

    #[test]
    fn typed_issuance_roundtrip_is_bound_to_policy_context_and_kind() {
        let ctx = context();
        let mut witness = js::demo_witness();
        witness.mint = 7;
        witness.outputs[0].value += 7;
        let statement = js::public_values(&witness);
        let bytes = prove_issuance_research(&witness, &ctx, 7).unwrap();
        verify_issuance_research(&bytes, &ctx, &statement, 7).unwrap();
        assert_eq!(
            verify_issuance_research(&bytes, &ctx, &statement, 8),
            Err(Error::UnauthorizedIssuance)
        );
        assert!(super::super::leaf::verify_joinsplit_research(&bytes, &ctx, &statement).is_err());
        let mut chain = ctx;
        chain.chain_id[0] ^= 1;
        let mut relabeled = bytes.clone();
        relabeled[40..72].copy_from_slice(&chain.chain_id);
        assert!(verify_issuance_research(&relabeled, &chain, &statement, 7).is_err());
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(verify_issuance_research(&appended, &ctx, &statement, 7).is_err());
        for i in 0..statement.len() {
            let mut wrong = statement.clone();
            wrong[i] += Val::ONE;
            assert!(verify_issuance_research(&bytes, &ctx, &wrong, 7).is_err());
        }
    }

    #[test]
    fn typed_htlc_redeem_refund_and_height_binding() {
        let ctx = context();
        let mut witness = htlc::demo_htlc_witness();
        for refund in [false, true] {
            if refund {
                witness.inputs[0].nk = [9, 90];
                witness.inputs[0].div = Val::from_u64(2);
                witness.inputs[0].mode = Val::ZERO;
                witness.current_height = witness.inputs[0].timeout;
            }
            let statement = htlc::public_values(&witness);
            let bytes = prove_htlc_research(&witness, &ctx).unwrap();
            verify_htlc_research(&bytes, &ctx, &statement, witness.current_height).unwrap();
            assert!(
                verify_htlc_research(&bytes, &ctx, &statement, witness.current_height + 1).is_err()
            );
            for i in 0..statement.len() {
                let mut wrong = statement.clone();
                wrong[i] += Val::ONE;
                assert!(
                    verify_htlc_research(&bytes, &ctx, &wrong, witness.current_height).is_err()
                );
            }
            let mut relabeled = bytes.clone();
            let mut chain = ctx;
            chain.chain_id[0] ^= 1;
            relabeled[40..72].copy_from_slice(&chain.chain_id);
            assert!(
                verify_htlc_research(&relabeled, &chain, &statement, witness.current_height)
                    .is_err()
            );
        }
    }
}
