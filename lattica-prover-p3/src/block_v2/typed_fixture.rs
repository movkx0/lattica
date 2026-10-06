//! Public mixed-wallet fixtures for local research qualification.
//! The deterministic witnesses are synthetic, contain no real funds, and are
//! never emitted. Host application and throughput need separate qualification.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;

use super::{
    codec,
    commitment::Context,
    leaf, profile,
    recursive::{Error, WalletProof},
    typed_leaf,
    typed_recursive::{self, Policy},
};
use crate::{htlc_air as htlc, joinsplit_air as js, spend_common};

pub const CHAIN: [u8; 32] = [0x6d; 32];
pub const HEIGHT: u64 = 10;
pub const MINT: u64 = 7;

enum Witness {
    JoinSplit(js::Witness),
    Htlc(htlc::Witness),
}

/// One shared anchor, distinct nullifiers and outputs, and a single block
/// height. The order repeats JoinSplit, HTLC redeem, HTLC refund, issuance.
/// Prefixes of the 64-wallet fixture cover the contract's smaller counts.
fn witnesses() -> Vec<Witness> {
    let mut witnesses = Vec::with_capacity(64);
    let mut commitments = Vec::with_capacity(128);
    for index in 0..64 {
        let offset = Val::from_usize(1000 * (index + 1));
        if index % 4 == 1 || index % 4 == 2 {
            let mut w = htlc::demo_htlc_witness();
            w.current_height = HEIGHT;
            if index % 4 == 1 {
                w.inputs[0].timeout = HEIGHT + 10;
            } else {
                w.inputs[0].nk = [9, 90];
                w.inputs[0].div = Val::from_u64(2);
                w.inputs[0].mode = Val::ZERO;
            }
            for input in &mut w.inputs {
                input.rho[0] += offset;
                input.rcm[1] += offset;
                let owner = if input.note_type == Val::ZERO {
                    htlc::recipient_of(
                        Val::from_u64(input.nk[0]),
                        Val::from_u64(input.nk[1]),
                        input.div,
                    )
                } else {
                    htlc::htlc_root(
                        input.redeem_tag,
                        input.refund_tag,
                        input.hashlock,
                        Val::from_u64(input.timeout),
                    )
                };
                commitments.push(htlc::commit(
                    owner,
                    Val::from_u64(input.value),
                    input.rho,
                    input.rcm,
                    input.asset,
                    input.note_type,
                ));
            }
            for output in &mut w.outputs {
                output.rho[0] += offset;
            }
            w.tx_binding[0] += offset;
            witnesses.push(Witness::Htlc(w));
        } else {
            let mut w = js::demo_witness();
            if index % 4 == 3 {
                w.mint = MINT;
                w.outputs[0].value += MINT;
            }
            for input in &mut w.inputs {
                input.rho[0] += offset;
                input.rcm[1] += offset;
                commitments.push(js::commit(
                    js::recipient_of(
                        Val::from_u64(input.nk[0]),
                        Val::from_u64(input.nk[1]),
                        input.div,
                    ),
                    Val::from_u64(input.value),
                    input.rho,
                    input.rcm,
                    input.asset,
                ));
            }
            for output in &mut w.outputs {
                output.rho[0] += offset;
            }
            w.tx_binding[0] += offset;
            witnesses.push(Witness::JoinSplit(w));
        }
    }
    let (_, paths) = spend_common::build_paths(&commitments);
    for (index, witness) in witnesses.iter_mut().enumerate() {
        match witness {
            Witness::JoinSplit(w) => {
                for (slot, input) in w.inputs.iter_mut().enumerate() {
                    (input.sib, input.bits) = paths[index * js::N_IN + slot];
                }
            }
            Witness::Htlc(w) => {
                for (slot, input) in w.inputs.iter_mut().enumerate() {
                    (input.sib, input.bits) = paths[index * js::N_IN + slot];
                }
            }
        }
    }
    witnesses
}

/// Generate one public leaf. The native witness set always has 64 entries so
/// every call uses the same anchor, regardless of the selected prefix count.
/// Proving randomness remains fresh; only the public statement is repeatable.
pub fn wallet(index: usize) -> Result<(WalletProof, Policy), Error> {
    if index >= 64 {
        return Err("mixed fixture index must be below 64".into());
    }
    let witness = witnesses().swap_remove(index);
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: CHAIN,
    };
    let (public, bytes, policy) = match witness {
        Witness::JoinSplit(w) if w.mint == 0 => (
            js::public_values(&w),
            leaf::prove_joinsplit_research(&w, &context).map_err(|e| format!("{e:?}"))?,
            Policy::JoinSplit,
        ),
        Witness::JoinSplit(w) => (
            js::public_values(&w),
            typed_leaf::prove_issuance_research(&w, &context, MINT)
                .map_err(|e| format!("{e:?}"))?,
            Policy::Issuance {
                authorized_mint: MINT,
            },
        ),
        Witness::Htlc(w) => (
            htlc::public_values(&w),
            typed_leaf::prove_htlc_research(&w, &context).map_err(|e| format!("{e:?}"))?,
            Policy::Htlc {
                expected_height: HEIGHT,
            },
        ),
    };
    let wallet = WalletProof {
        chain: CHAIN,
        public,
        // This envelope was just generated locally. Still use the bounded,
        // canonical decoder used by retained research artifacts.
        proof: codec::decode(bytes.get(72..).ok_or("short generated leaf")?)?,
    };
    typed_recursive::verify_wallet(&wallet, policy)?;
    Ok((wallet, policy))
}

/// Public statements, without leaf proving or any preprocessing allocation.
pub fn statements() -> Vec<Vec<u64>> {
    witnesses()
        .iter()
        .map(|w| match w {
            Witness::JoinSplit(w) => js::public_values(w),
            Witness::Htlc(w) => htlc::public_values(w),
        })
        .map(|v| v.iter().map(|x| x.as_canonical_u64()).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn all_fixture_statements_share_anchor_and_have_unique_spends_and_outputs() {
        let statements = statements();
        let anchor = &statements[0][..4];
        let mut nullifiers = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        for (i, public) in statements.iter().enumerate() {
            assert_eq!(&public[..4], anchor);
            for nf in public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
                assert!(nullifiers.insert(nf.to_vec()));
            }
            for cm in public[js::PI_OUTCM..js::PI_FEE].chunks_exact(4) {
                assert!(outputs.insert(cm.to_vec()));
            }
            assert_eq!(public[js::PI_MINT], if i % 4 == 3 { MINT } else { 0 });
            if i % 4 == 1 || i % 4 == 2 {
                assert_eq!(public[htlc::PI_HEIGHT], HEIGHT);
                let hashlock = &public[htlc::PI_HASHLOCK..];
                assert_eq!(hashlock.iter().all(|v| *v == 0), i % 4 == 2);
            }
        }
        assert_eq!(nullifiers.len(), 128);
        assert_eq!(outputs.len(), 128);
    }

    #[test]
    fn each_fixture_type_has_a_valid_context_bound_proof() {
        for index in 0..4 {
            let (wallet, policy) = wallet(index).unwrap();
            typed_recursive::verify_wallet(&wallet, policy).unwrap();
            assert_eq!(
                wallet
                    .public
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>(),
                statements()[index]
            );
        }
        assert!(wallet(64).is_err());
    }
}
