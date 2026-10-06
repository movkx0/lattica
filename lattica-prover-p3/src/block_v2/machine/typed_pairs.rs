//! Research programs for pairs of typed wallets in a separate twelve-key registry.
//!
//! Both wallet verifiers always run. COUNT=1 selects canonical right-hand padding;
//! callers can repeat the first valid wallet in the unused slot. The public count
//! and ordered commitment describe actual entries, never the verifier invocation count.

use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;

use super::program::{Val, Wire};
use super::programs::{
    self, assert_constant, finish, parent_root, public, registry, selectors, Compiled, COUNT,
    LEVEL, MODE, PUBLIC_VALUES, ROOT,
};
use super::typed_finalizer;
use super::typed_programs::{HTLC, ISSUANCE};
use super::verifier::{self, CompileError, ProofInputs};
use super::ProgramBuilder;
use crate::block_v2::{
    commitment::{self, Context, Kind},
    leaf::ContextJoinSplitAir,
    profile::{self, Config},
    recursive::WalletProof,
    typed_leaf::ContextAir,
};
use crate::{htlc_air as htlc, joinsplit_air as js};

pub const KEY_COUNT: usize = 12;
pub type Caps = programs::Caps<KEY_COUNT>;
pub const FINALIZE: u64 = KEY_COUNT as u64;

/// Empty and merge retain slots 2 and 3. Every other nonterminal slot verifies
/// a fixed, ordered pair of wallet types; HTLC redeem/refund share the same AIR.
pub const PAIRS: [(u64, [u64; 2]); 9] = [
    (1, [programs::WRAPPER, programs::WRAPPER]),
    (4, [programs::WRAPPER, HTLC]),
    (5, [programs::WRAPPER, ISSUANCE]),
    (6, [HTLC, programs::WRAPPER]),
    (7, [HTLC, HTLC]),
    (8, [HTLC, ISSUANCE]),
    (9, [ISSUANCE, programs::WRAPPER]),
    (10, [ISSUANCE, HTLC]),
    (11, [ISSUANCE, ISSUANCE]),
];

pub fn mode_for(leaves: [u64; 2]) -> Result<u64, CompileError> {
    PAIRS
        .iter()
        .find_map(|(mode, kinds)| (*kinds == leaves).then_some(*mode))
        .ok_or(CompileError::Shape("typed pair leaf modes"))
}

pub fn leaf_modes(mode: u64) -> Result<[u64; 2], CompileError> {
    PAIRS
        .iter()
        .find_map(|(key, kinds)| (*key == mode).then_some(*kinds))
        .ok_or(CompileError::Shape("typed pair registry mode"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofPlan {
    pub subtree_level: u8,
    pub single_wrapper_proofs: u16,
    pub subtree_proofs: u16,
    pub finalizer_proofs: u16,
    pub proposed_proofs: u16,
}

pub fn proof_plan(count: u8) -> Result<ProofPlan, CompileError> {
    let single = typed_finalizer::proof_plan(count)?;
    fn nodes(level: u8, count: u8) -> u16 {
        if count == 0 || level == 1 {
            return 1;
        }
        let half = 1 << (level - 1);
        1 + nodes(level - 1, count.min(half)) + nodes(level - 1, count.saturating_sub(half))
    }
    let subtree_level = single.subtree_level.max(1);
    let subtree_proofs = nodes(subtree_level, count);
    let finalizer_proofs = u16::from(subtree_level < commitment::DEPTH);
    Ok(ProofPlan {
        subtree_level,
        single_wrapper_proofs: single.proposed_proofs,
        subtree_proofs,
        finalizer_proofs,
        proposed_proofs: subtree_proofs + finalizer_proofs,
    })
}

fn wallet_leaf(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    public: &[Wire; PUBLIC_VALUES],
    mode: u64,
    values: &[Val],
    proof: &Proof<Config>,
) -> Result<[Wire; 4], CompileError> {
    let (count, kind) = match mode {
        programs::WRAPPER => (js::N_PUBLIC, Kind::JoinSplit),
        HTLC => (htlc::N_PUBLIC, Kind::Htlc),
        ISSUANCE => (js::N_PUBLIC, Kind::Coinbase),
        _ => return Err(CompileError::Shape("typed pair wallet type")),
    };
    if values.len() != count {
        return Err(CompileError::Shape("typed pair wallet statement"));
    }
    let wallet = inputs.bases(b, values);
    let mut inner = wallet.clone();
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0; 32],
    }
    .to_fields();
    inner.extend(context[..8].iter().map(|&v| b.constant(Val::from_u64(v))));
    inner.extend_from_slice(&public[8..16]);
    match mode {
        programs::WRAPPER => {
            b.assert_zero(wallet[js::PI_MINT]);
            verifier::uni::verify(b, inputs, &ContextJoinSplitAir, js::HEIGHT, &inner, proof)?;
        }
        HTLC => {
            b.assert_zero(wallet[htlc::PI_MINT]);
            verifier::uni::verify(
                b,
                inputs,
                &ContextAir(htlc::HtlcAir),
                htlc::HEIGHT,
                &inner,
                proof,
            )?;
        }
        ISSUANCE => {
            let inverse = b.inverse(wallet[js::PI_MINT]);
            let product = b.mul(wallet[js::PI_MINT], inverse);
            assert_constant(b, product, 1);
            verifier::uni::verify(
                b,
                inputs,
                &ContextAir(js::JoinSplitAir),
                js::HEIGHT,
                &inner,
                proof,
            )?;
        }
        _ => unreachable!(),
    }
    let tag = kind as u64;
    let digest = b.hash_fields(commitment::STATEMENT + tag, &wallet);
    let mut fields = public[..16].to_vec();
    fields.push(b.constant(Val::from_u64(tag)));
    fields.extend(digest);
    Ok(b.hash_fields(commitment::LEAF, &fields))
}

pub fn wrapper_pair(
    height: usize,
    caps: &Caps,
    mode: u64,
    wallet_public: [&[Val]; 2],
    proofs: [&Proof<Config>; 2],
) -> Result<Compiled, CompileError> {
    let kinds = leaf_modes(mode)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], mode);
    assert_constant(&mut b, public[LEVEL], 1);
    let _counts = selectors(&mut b, public[COUNT], 1, 2);
    let one = b.constant(Val::ONE);
    let right_count = b.sub(public[COUNT], one);
    let left = wallet_leaf(
        &mut b,
        &mut inputs,
        &public,
        kinds[0],
        wallet_public[0],
        proofs[0],
    )?;
    let right = wallet_leaf(
        &mut b,
        &mut inputs,
        &public,
        kinds[1],
        wallet_public[1],
        proofs[1],
    )?;
    let empty = b.hash_fields(commitment::EMPTY, &public[..16]);
    let right: [Wire; 4] = core::array::from_fn(|i| {
        let delta = b.sub(right[i], empty[i]);
        let active = b.mul(right_count, delta);
        b.add(empty[i], active)
    });
    let root = parent_root(&mut b, one, one, right_count, &left, &right);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

pub fn finalize(
    height: usize,
    caps: &Caps,
    child: &[Val; PUBLIC_VALUES],
    proof: &BatchProof<Config>,
) -> Result<Compiled, CompileError> {
    let child_air = programs::shape(height)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    let keys = registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], FINALIZE);
    assert_constant(&mut b, public[LEVEL], u64::from(commitment::DEPTH));
    let child = inputs.bases(&mut b, child);
    for i in 0..16 {
        b.assert_equal(child[i], public[i]);
    }
    b.assert_equal(child[COUNT], public[COUNT]);
    let masks = selectors(&mut b, child[MODE], programs::WRAPPER, FINALIZE - 1);
    let zero = b.constant(Val::ZERO);
    let mut key = vec![[zero; 4]; 1 << profile::CAP_HEIGHT];
    for (i, selected) in key.iter_mut().enumerate() {
        for j in 0..4 {
            for k in 0..KEY_COUNT - 1 {
                let term = b.mul(masks[k], keys[k][i][j]);
                selected[j] = b.add(selected[j], term);
            }
        }
    }
    verifier::batch::verify(&mut b, &mut inputs, &child_air, &child, &key, proof)?;
    let root = typed_finalizer::padded_root(&mut b, &child);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

pub fn compile_registration(
    height: usize,
    mode: u64,
    wallets: Option<[&WalletProof; 2]>,
) -> Result<Compiled, CompileError> {
    let caps: Caps = core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    if leaf_modes(mode).is_ok() {
        let wallets = wallets.ok_or(CompileError::Shape("typed pair registration templates"))?;
        return wrapper_pair(
            height,
            &caps,
            mode,
            [&wallets[0].public, &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof],
        );
    }
    match mode {
        programs::EMPTY => programs::empty(height, &caps),
        programs::MERGE | FINALIZE => {
            let proof = verifier::template::batch(&programs::shape(height)?)?;
            let public = [Val::ZERO; PUBLIC_VALUES];
            if mode == FINALIZE {
                finalize(height, &caps, &public, &proof)
            } else {
                programs::merge(height, &caps, [&public, &public], [&proof, &proof])
            }
        }
        _ => Err(CompileError::Shape("typed pair registration mode")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::{commitment::NodeSummary, typed_fixture};
    use p3_field::PrimeField64;
    use std::collections::BTreeMap;

    fn caps() -> Caps {
        core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
    }

    fn copy_proof(proof: &Proof<Config>) -> Proof<Config> {
        postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap()
    }

    fn leaf(context: Context, wallet: &WalletProof, mode: u64) -> NodeSummary {
        let kind = match mode {
            programs::WRAPPER => Kind::JoinSplit,
            HTLC => Kind::Htlc,
            ISSUANCE => Kind::Coinbase,
            _ => panic!("test leaf kind"),
        };
        let values: Vec<_> = wallet.public.iter().map(|v| v.as_canonical_u64()).collect();
        commitment::leaf(
            context,
            commitment::Entry {
                kind,
                statement_digest: commitment::statement_digest(kind as u8, &values).unwrap(),
            },
        )
        .unwrap()
    }

    #[test]
    fn twelve_key_registry_binds_every_key_and_stays_separate() {
        let height = 1 << 18;
        let caps = caps();
        let original = programs::profile_id(height, &caps).unwrap();
        for index in 0..KEY_COUNT {
            let mut changed = caps.clone();
            changed[index][0][0] += Val::ONE;
            assert_ne!(original, programs::profile_id(height, &changed).unwrap());
        }
        let legacy: programs::Caps<3> = core::array::from_fn(|_| caps[0].clone());
        let typed: programs::Caps<5> = core::array::from_fn(|_| caps[0].clone());
        let finalized: programs::Caps<6> = core::array::from_fn(|_| caps[0].clone());
        for other in [
            programs::profile_id(height, &legacy).unwrap(),
            programs::profile_id(height, &typed).unwrap(),
            programs::profile_id(height, &finalized).unwrap(),
        ] {
            assert_ne!(original, other);
        }
    }

    #[test]
    fn paired_finalizer_checks_a_real_child_proof_and_rejects_forged_statements() {
        use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
        let height = 2048;
        let mut caps = caps();
        let initial = programs::empty(height, &caps).unwrap();
        let registered =
            RegisteredProgram::new(MachineAir::new(initial.program.pad_to(height).unwrap()))
                .unwrap();
        caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
        let empty = programs::empty(height, &caps).unwrap();
        let context = Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: [61; 32],
        };
        let parent = programs::statement(
            commitment::empty_subtree(context, commitment::DEPTH).unwrap(),
            FINALIZE,
        );
        let template = compile_registration(height, FINALIZE, None).unwrap();
        for level in [1, 5, commitment::DEPTH] {
            let node = commitment::empty_subtree(context, level).unwrap();
            let child = programs::statement(node, programs::EMPTY);
            let proof = registered.prove(&child, &empty.witness).unwrap();
            registered.verify(&proof, &child).unwrap();
            let compiled = finalize(height, &caps, &child, &proof).unwrap();
            assert_eq!(compiled.program, template.program);
            if level == commitment::DEPTH {
                assert!(compiled
                    .program
                    .evaluate(&parent, &compiled.witness)
                    .is_err());
                continue;
            }
            compiled
                .program
                .evaluate(&parent, &compiled.witness)
                .unwrap();
            for index in [0, 8, MODE, LEVEL, COUNT, ROOT, ROOT + 3] {
                let mut wrong = parent;
                wrong[index] += Val::ONE;
                assert!(compiled
                    .program
                    .evaluate(&wrong, &compiled.witness)
                    .is_err());
            }
            for index in [0, 8, MODE, LEVEL, COUNT, ROOT, ROOT + 3] {
                let mut wrong_child = child;
                wrong_child[index] += Val::ONE;
                let bad = finalize(height, &caps, &wrong_child, &proof).unwrap();
                assert!(bad.program.evaluate(&parent, &bad.witness).is_err());
            }
            // Recompute the parent so a forged child is rejected by the inner
            // verifier even when its outer ordered commitment is consistent.
            let mut forged = NodeSummary {
                count: 1,
                root: [71, 72, 73, 74],
                ..node
            };
            let forged_child = programs::statement(forged, programs::EMPTY);
            while forged.level < commitment::DEPTH {
                let padding = commitment::empty_subtree(context, forged.level).unwrap();
                forged = commitment::merge_nodes(forged, padding).unwrap();
            }
            let bad = finalize(height, &caps, &forged_child, &proof).unwrap();
            assert!(bad
                .program
                .evaluate(&programs::statement(forged, FINALIZE), &bad.witness)
                .is_err());
        }
    }

    #[test]
    fn proof_counts_include_finalization_and_odd_padding() {
        for (count, single, paired) in [
            (1, 2, 2),
            (2, 4, 2),
            (3, 8, 4),
            (4, 8, 4),
            (8, 16, 8),
            (16, 32, 16),
            (32, 64, 32),
            (63, 127, 63),
            (64, 127, 63),
        ] {
            let plan = proof_plan(count).unwrap();
            assert_eq!(plan.single_wrapper_proofs, single);
            assert_eq!(plan.proposed_proofs, paired);
        }
        assert!(proof_plan(0).is_err());
        assert!(proof_plan(65).is_err());
    }

    #[test]
    fn every_ordered_typed_pair_binds_proofs_padding_and_registry_at_current_geometry() {
        let wallets: Vec<_> = (0..4)
            .map(|i| typed_fixture::wallet(i).unwrap().0)
            .collect();
        let kinds = [programs::WRAPPER, HTLC, HTLC, ISSUANCE];
        let height = if cfg!(feature = "block-v2-wide-lanes") {
            1 << 18
        } else {
            1 << 19
        };
        let caps = caps();
        let context = Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: typed_fixture::CHAIN,
        };
        let leaves: Vec<_> = wallets
            .iter()
            .zip(kinds)
            .map(|(w, mode)| leaf(context, w, mode))
            .collect();
        let mut registered_shapes = BTreeMap::new();
        for left in 0..4 {
            for right in 0..4 {
                let mode = mode_for([kinds[left], kinds[right]]).unwrap();
                let values = [
                    wallets[left].public.as_slice(),
                    wallets[right].public.as_slice(),
                ];
                let proofs = [&wallets[left].proof, &wallets[right].proof];
                let pair = programs::statement(
                    commitment::merge_nodes(leaves[left], leaves[right]).unwrap(),
                    mode,
                );
                let compiled = wrapper_pair(height, &caps, mode, values, proofs).unwrap();
                eprintln!("typed_pair mode={mode} left={left} right={right} rows={} height={} wires={} recursive_proof_produced=false",
                    compiled.program.active_rows(), compiled.program.height(), compiled.program.wire_count());
                assert!(
                    compiled.program.height() <= height,
                    "paired compiler increased the shared height"
                );
                if let Some(expected) = registered_shapes.get(&mode) {
                    assert_eq!(
                        &compiled.program, expected,
                        "wallet proof contents changed preprocessing"
                    );
                } else {
                    registered_shapes.insert(mode, compiled.program.clone());
                }
                compiled.program.evaluate(&pair, &compiled.witness).unwrap();
                if left != right {
                    let reversed = programs::statement(
                        commitment::merge_nodes(leaves[right], leaves[left]).unwrap(),
                        mode,
                    );
                    assert!(compiled
                        .program
                        .evaluate(&reversed, &compiled.witness)
                        .is_err());
                }
                if left == right {
                    let single = programs::statement(
                        commitment::merge_nodes(
                            leaves[left],
                            commitment::empty_subtree(context, 0).unwrap(),
                        )
                        .unwrap(),
                        mode,
                    );
                    compiled
                        .program
                        .evaluate(&single, &compiled.witness)
                        .unwrap();
                    // The unused slot must still execute its verifier. Changing only
                    // that proof leaves the single occupied leaf and root unchanged.
                    let mut forged = copy_proof(&wallets[right].proof);
                    forged.opened_values.trace_local[0] += profile::Challenge::ONE;
                    let bad =
                        wrapper_pair(height, &caps, mode, values, [proofs[0], &forged]).unwrap();
                    assert_eq!(compiled.program, bad.program);
                    assert!(bad.program.evaluate(&single, &bad.witness).is_err());
                }
                if left == 0 && right == 1 {
                    for index in [0, 8, MODE, LEVEL, ROOT] {
                        let mut wrong = pair;
                        wrong[index] += Val::ONE;
                        assert!(compiled
                            .program
                            .evaluate(&wrong, &compiled.witness)
                            .is_err());
                    }
                    for slot in 0..2 {
                        let mut forged = copy_proof(proofs[slot]);
                        forged.opened_values.trace_local[0] += profile::Challenge::ONE;
                        let mut changed = proofs;
                        changed[slot] = &forged;
                        let bad = wrapper_pair(height, &caps, mode, values, changed).unwrap();
                        assert!(bad.program.evaluate(&pair, &bad.witness).is_err());
                    }
                    for count in [0, 3] {
                        let right_count = Val::from_u64(count) - Val::ONE;
                        let empty = commitment::empty_subtree(context, 0).unwrap();
                        let mut fields = vec![1, 1, right_count.as_canonical_u64()];
                        fields.extend(leaves[left].root);
                        fields.extend((0..4).map(|i| {
                            let padding = Val::from_u64(empty.root[i]);
                            (padding
                                + right_count * (Val::from_u64(leaves[right].root[i]) - padding))
                                .as_canonical_u64()
                        }));
                        let mut wrong = pair;
                        wrong[COUNT] = Val::from_u64(count);
                        wrong[ROOT..].copy_from_slice(
                            &commitment::hash_fields(commitment::NODE, &fields)
                                .unwrap()
                                .map(Val::from_u64),
                        );
                        assert!(
                            compiled
                                .program
                                .evaluate(&wrong, &compiled.witness)
                                .is_err(),
                            "range checks must reject even a matching extrapolated root"
                        );
                    }
                    let mut changed_caps = caps.clone();
                    changed_caps[0][0][0] += Val::ONE;
                    let changed =
                        wrapper_pair(height, &changed_caps, mode, values, proofs).unwrap();
                    assert!(changed.program.evaluate(&pair, &changed.witness).is_err());
                }
            }
        }
        assert_eq!(registered_shapes.len(), 9);
        for mode in [programs::EMPTY, programs::MERGE, FINALIZE] {
            let compiled = compile_registration(height, mode, None).unwrap();
            eprintln!(
                "typed_pair registry mode={mode} rows={} height={} recursive_proof_produced=false",
                compiled.program.active_rows(),
                compiled.program.height()
            );
            assert!(
                compiled.program.height() <= height,
                "registry program increased the shared height"
            );
        }
        for mode in [0, programs::EMPTY, programs::MERGE, FINALIZE, FINALIZE + 1] {
            assert!(wrapper_pair(
                height,
                &caps,
                mode,
                [&wallets[0].public, &wallets[0].public],
                [&wallets[0].proof, &wallets[0].proof]
            )
            .is_err());
        }
        let legacy: programs::Caps<6> =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        assert_ne!(
            context.profile_id,
            programs::profile_id(height, &legacy).unwrap()
        );
    }
}
