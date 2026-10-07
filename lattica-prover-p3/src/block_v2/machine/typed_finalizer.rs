//! Research compiler for a separately registered depth-six finalizer.
//!
//! One authenticated subtree replaces the empty proofs and merges above it.
//! Its six-key registry has a distinct identity. The measured five-key driver
//! and production acceptance paths do not dispatch to this compiler. Compiler
//! checks and proof counts do not establish a proving-time improvement.

use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;

use super::program::{Val, Wire};
use super::programs::{
    self, assert_constant, finish, parent_root, public, registry, selectors, Compiled, COUNT,
    LEVEL, MODE, PUBLIC_VALUES, ROOT,
};
use super::typed_programs;
use super::verifier::{self, CompileError, ProofInputs};
use super::ProgramBuilder;
use crate::block_v2::{commitment, profile, recursive::WalletProof};

pub type Caps = programs::Caps<6>;
pub const FINALIZE: u64 = 6;

/// Counts for fresh recursive proofs, excluding wallet proofs and registration.
/// Counts above 32 already require depth six and bypass the finalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofPlan {
    pub subtree_level: u8,
    pub reference_proofs: u16,
    pub subtree_proofs: u16,
    pub finalizer_proofs: u16,
    pub proposed_proofs: u16,
}

pub fn proof_plan(count: u8) -> Result<ProofPlan, CompileError> {
    if count == 0 || count > 1 << commitment::DEPTH {
        return Err(CompileError::Shape("finalizer transaction count"));
    }
    fn nodes(level: u8, count: u8) -> u16 {
        if count == 0 || level == 0 {
            return 1;
        }
        let half = 1 << (level - 1);
        1 + nodes(level - 1, count.min(half)) + nodes(level - 1, count.saturating_sub(half))
    }
    let subtree_level = count.next_power_of_two().trailing_zeros() as u8;
    let subtree_proofs = nodes(subtree_level, count);
    let finalizer_proofs = u16::from(subtree_level < commitment::DEPTH);
    Ok(ProofPlan {
        subtree_level,
        reference_proofs: nodes(commitment::DEPTH, count),
        subtree_proofs,
        finalizer_proofs,
        proposed_proofs: subtree_proofs + finalizer_proofs,
    })
}

/// Constrain padding for an authenticated child. The inner registered program
/// establishes the child's count, root and canonical left-packed subtree.
pub(super) fn padded_root(b: &mut ProgramBuilder, child: &[Wire]) -> [Wire; 4] {
    let masks = selectors(b, child[LEVEL], 0, u64::from(commitment::DEPTH - 1));
    let zero = b.constant(Val::ZERO);
    let mut empty = b.hash_fields(commitment::EMPTY, &child[..16]);
    let mut root: [Wire; 4] = child[ROOT..ROOT + 4].try_into().unwrap();
    let mut active = zero;
    for (level, mask) in masks.into_iter().enumerate() {
        // The constrained level selectors make this 0 below the child's level
        // and 1 at and above it. Padding is always on the right.
        active = b.add(active, mask);
        let parent_level = b.constant(Val::from_usize(level + 1));
        let parent = parent_root(b, parent_level, child[COUNT], zero, &root, &empty);
        for i in 0..4 {
            let delta = b.sub(parent[i], root[i]);
            let selected = b.mul(active, delta);
            root[i] = b.add(root[i], selected);
        }
        if level + 1 < commitment::DEPTH as usize {
            empty = parent_root(b, parent_level, zero, zero, &empty, &empty);
        }
    }
    root
}

pub fn compile(
    height: usize,
    caps: &Caps,
    child: &[Val; PUBLIC_VALUES],
    proof: &BatchProof<profile::Config>,
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
    // A finalizer is terminal. Only the five subtree modes can be its child.
    let masks = selectors(
        &mut b,
        child[MODE],
        programs::WRAPPER,
        typed_programs::ISSUANCE,
    );
    let zero = b.constant(Val::ZERO);
    let mut key = vec![[zero; 4]; 1 << profile::CAP_HEIGHT];
    for (i, selected) in key.iter_mut().enumerate() {
        for j in 0..4 {
            for k in 0..5 {
                let term = b.mul(masks[k], keys[k][i][j]);
                selected[j] = b.add(selected[j], term);
            }
        }
    }
    verifier::batch::verify(&mut b, &mut inputs, &child_air, &child, &key, proof)?;
    let root = padded_root(&mut b, &child);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

/// All six keys must be registered from these compilers at one qualified
/// height. Key values and proof contents are witnesses, not program choices.
pub fn compile_registration(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
) -> Result<Compiled, CompileError> {
    let caps: Caps = core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    match mode {
        programs::WRAPPER | typed_programs::HTLC | typed_programs::ISSUANCE => {
            let wallet = wallet.ok_or(CompileError::Shape("typed wrapper template"))?;
            typed_programs::wrapper(height, &caps, mode, &wallet.public, &wallet.proof)
        }
        programs::EMPTY => programs::empty(height, &caps),
        programs::MERGE | FINALIZE => {
            let proof = verifier::template::batch(&programs::shape(height)?)?;
            let public = [Val::ZERO; PUBLIC_VALUES];
            if mode == FINALIZE {
                compile(height, &caps, &public, &proof)
            } else {
                programs::merge(height, &caps, [&public, &public], [&proof, &proof])
            }
        }
        _ => Err(CompileError::Shape("typed finalizer registry mode")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::commitment::{Context, Entry, Kind, NodeSummary};
    use crate::block_v2::machine::backend::RegisteredProgram;
    use crate::block_v2::machine::MachineAir;

    fn caps() -> Caps {
        core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
    }

    fn subtree(context: Context, entries: &[Entry], level: u8) -> NodeSummary {
        if entries.is_empty() {
            return commitment::empty_subtree(context, level).unwrap();
        }
        if level == 0 {
            assert_eq!(entries.len(), 1);
            return commitment::leaf(context, entries[0]).unwrap();
        }
        let split = entries.len().min(1 << (level - 1));
        commitment::merge_nodes(
            subtree(context, &entries[..split], level - 1),
            subtree(context, &entries[split..], level - 1),
        )
        .unwrap()
    }

    fn finalized(mut node: NodeSummary) -> NodeSummary {
        while node.level < commitment::DEPTH {
            let empty = commitment::empty_subtree(node.context, node.level).unwrap();
            node = commitment::merge_nodes(node, empty).unwrap();
        }
        node
    }

    #[test]
    fn planned_proof_counts_keep_full_capacity_and_reduce_only_padding() {
        for (count, reference, proposed) in [
            (1, 13, 2),
            (2, 13, 4),
            (3, 15, 8),
            (4, 15, 8),
            (8, 21, 16),
            (16, 35, 32),
            (32, 65, 64),
            (63, 127, 127),
            (64, 127, 127),
        ] {
            let plan = proof_plan(count).unwrap();
            assert_eq!(plan.reference_proofs, reference);
            assert_eq!(plan.proposed_proofs, proposed);
        }
        assert!(proof_plan(0).is_err());
        assert!(proof_plan(65).is_err());
        assert!(proof_plan(u8::MAX).is_err());
    }

    #[test]
    fn padding_constraints_match_ordered_commitments_for_every_small_count() {
        let mut b = ProgramBuilder::new(PUBLIC_VALUES + 4).unwrap();
        let child = public(&b);
        let root = padded_root(&mut b, &child);
        for (i, value) in root.into_iter().enumerate() {
            b.assert_equal(value, b.public(PUBLIC_VALUES + i).unwrap());
        }
        let program = b.finish(None).unwrap();
        let context = Context {
            profile_id: programs::profile_id(1 << 18, &caps()).unwrap(),
            chain_id: [73; 32],
        };
        let entries: Vec<_> = (0..32)
            .map(|i| Entry {
                kind: [Kind::JoinSplit, Kind::Htlc, Kind::Coinbase][i % 3],
                statement_digest: [i as u64 + 1, 2, 3, 4],
            })
            .collect();
        for count in 1..=32 {
            let expected = commitment::root(context, &entries[..count]).unwrap();
            for level in proof_plan(count as u8).unwrap().subtree_level..commitment::DEPTH {
                let node = subtree(context, &entries[..count], level);
                let mut values = programs::statement(node, programs::MERGE).to_vec();
                values.extend(expected.map(Val::from_u64));
                program.evaluate(&values, &[]).unwrap();
                for i in PUBLIC_VALUES..PUBLIC_VALUES + 4 {
                    let mut wrong = values.clone();
                    wrong[i] += Val::ONE;
                    assert!(program.evaluate(&wrong, &[]).is_err());
                }
                for bad_level in [6, 7, 64] {
                    let mut wrong = values.clone();
                    wrong[LEVEL] = Val::from_u64(bad_level);
                    assert!(program.evaluate(&wrong, &[]).is_err());
                }
            }
        }
    }

    #[test]
    fn six_key_registry_is_separate_and_binds_every_key() {
        let height = 1 << 18;
        let six = caps();
        let three: programs::Caps<3> = core::array::from_fn(|i| six[i].clone());
        let five: programs::Caps<5> = core::array::from_fn(|i| six[i].clone());
        let id = programs::profile_id(height, &six).unwrap();
        assert_ne!(id, programs::profile_id(height, &three).unwrap());
        assert_ne!(id, programs::profile_id(height, &five).unwrap());
        for i in 0..6 {
            let mut wrong = six.clone();
            wrong[i][0][0] += Val::ONE;
            assert_ne!(id, programs::profile_id(height, &wrong).unwrap());
        }
    }

    #[test]
    fn finalizer_checks_a_real_child_proof_and_rejects_forged_statements() {
        // A small genuine empty proof exercises the complete inner verifier.
        // This is an interpreter check, not a full-size finalizer proof run.
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
            chain_id: [47; 32],
        };
        let parent = programs::statement(
            commitment::empty_subtree(context, commitment::DEPTH).unwrap(),
            FINALIZE,
        );
        let template = compile_registration(height, FINALIZE, None).unwrap();
        for level in [0, 5, 6] {
            let child = programs::statement(
                commitment::empty_subtree(context, level).unwrap(),
                programs::EMPTY,
            );
            let proof = registered.prove(&child, &empty.witness).unwrap();
            registered.verify(&proof, &child).unwrap();
            let compiled = compile(height, &caps, &child, &proof).unwrap();
            assert_eq!(
                compiled.program.manifest_fields(),
                template.program.manifest_fields()
            );
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
            // Keep parent and forged child mutually consistent. These cases
            // must fail inside the proof verifier, not the outer padding check.
            let original = commitment::empty_subtree(context, level).unwrap();
            for forged in [
                commitment::empty_subtree(
                    Context {
                        chain_id: [48; 32],
                        ..context
                    },
                    level,
                )
                .unwrap(),
                NodeSummary {
                    count: 1,
                    ..original
                },
                NodeSummary {
                    count: 1,
                    root: [71, 72, 73, 74],
                    ..original
                },
            ] {
                let wrong_child = programs::statement(forged, programs::EMPTY);
                let wrong_parent = programs::statement(finalized(forged), FINALIZE);
                let bad = compile(height, &caps, &wrong_child, &proof).unwrap();
                assert!(bad.program.evaluate(&wrong_parent, &bad.witness).is_err());
            }
            for mode in [0, 1, 4, 5, FINALIZE, 7] {
                let mut wrong = child;
                wrong[MODE] = Val::from_u64(mode);
                let bad = compile(height, &caps, &wrong, &proof).unwrap();
                assert_eq!(
                    bad.program.manifest_fields(),
                    template.program.manifest_fields()
                );
                assert!(bad.program.evaluate(&parent, &bad.witness).is_err());
            }
            let mut wrong_caps = caps.clone();
            wrong_caps[1][0][0] += Val::ONE;
            let bad = compile(height, &wrong_caps, &child, &proof).unwrap();
            assert!(bad.program.evaluate(&parent, &bad.witness).is_err());
        }
    }

    #[test]
    #[cfg(feature = "block-v2-wide-lanes")]
    fn finalizer_fits_the_current_shared_height_without_preprocessing_allocation() {
        let height = 1 << 18;
        let compiled = compile_registration(height, FINALIZE, None).unwrap();
        eprintln!(
            "typed finalizer geometry: rows={} height={} shared_height={} wires={}",
            compiled.program.active_rows(),
            compiled.program.height(),
            height,
            compiled.program.wire_count()
        );
        compiled.program.pad_to(height).unwrap();
        assert!(compile_registration(height, 0, None).is_err());
        assert!(compile_registration(height, 7, None).is_err());
        assert!(compile_registration(height, typed_programs::HTLC, None).is_err());
    }
}
