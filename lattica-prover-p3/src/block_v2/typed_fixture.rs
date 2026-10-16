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
    #[cfg(test)]
    tests::record_preparation();
    let mut witnesses = Vec::with_capacity(super::profile::MAX_TRANSACTIONS);
    let mut commitments = Vec::with_capacity(128);
    for index in 0..super::profile::MAX_TRANSACTIONS {
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
/// Synthetic input construction and independent verification use CPU arithmetic;
/// the statement exported here comes from the admitted leaf prover.
pub fn wallet(index: usize) -> Result<(WalletProof, Policy), Error> {
    let request = crate::proving::Request::from_env()?;
    let _admission = leaf::admit_wallet_request(request)?;
    if index >= super::profile::MAX_TRANSACTIONS {
        return Err("mixed fixture index exceeds the selected block capacity".into());
    }
    let witness = witnesses().swap_remove(index);
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: CHAIN,
    };
    let (proved, policy) = match witness {
        Witness::JoinSplit(w) if w.mint == 0 => (
            leaf::prove_joinsplit_with_public(&w, &context, request)
                .map_err(|e| format!("{e:?}"))?,
            Policy::JoinSplit,
        ),
        Witness::JoinSplit(w) => (
            typed_leaf::prove_issuance_with_public(&w, &context, MINT, request)
                .map_err(|e| format!("{e:?}"))?,
            Policy::Issuance {
                authorized_mint: MINT,
            },
        ),
        Witness::Htlc(w) => (
            typed_leaf::prove_htlc_with_public(&w, &context, request)
                .map_err(|e| format!("{e:?}"))?,
            Policy::Htlc {
                expected_height: HEIGHT,
            },
        ),
    };
    let wallet = WalletProof {
        chain: CHAIN,
        public: proved.public,
        // This envelope was just generated locally. Still use the bounded,
        // canonical decoder used by retained research artifacts.
        proof: codec::decode(proved.envelope.get(72..).ok_or("short generated leaf")?)?,
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
#[path = "typed_fixture_tests.rs"]
mod tests;
