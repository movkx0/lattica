//! Candidate recursive programs. Compilation/interpreter checks are not recursive proofs.
//! Keys are supplied as witness parameters, hashed into the public context, and selected
//! by constrained child mode. A root verifier MUST pin a registry built from these exact
//! programs; a prover-supplied registry/profile is never an authorization source.
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::{symbolic, BatchProof};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{LogUpGadget, Lookups};
use p3_uni_stark::Proof;

use super::program::Val;
use super::verifier::{self, CompileError, ProofInputs};
use super::{analysis, fingerprint, MachineAir, Program, ProgramBuilder, Wire};
use crate::block_v2::{
    commitment::{self, Context, NodeSummary},
    leaf::ContextJoinSplitAir,
    profile::{self, Config},
};
use crate::joinsplit_air as js;

pub const PUBLIC_VALUES: usize = 23;
pub const MODE: usize = 16;
pub const LEVEL: usize = 17;
pub const COUNT: usize = 18;
pub const ROOT: usize = 19;
pub const WRAPPER: u64 = 1;
pub const EMPTY: u64 = 2;
pub const MERGE: u64 = 3;
const REGISTRY_DOMAIN: u64 = 0x4c42563211;
const AIR_DOMAIN: u64 = 0x4c42563212;

/// Public key material only. Not evidence that these keys belong to approved programs.
pub type Caps = [Vec<[Val; 4]>; 3];

pub struct Compiled {
    pub program: Program,
    pub witness: Vec<Val>,
}

pub fn statement(node: NodeSummary, mode: u64) -> [Val; PUBLIC_VALUES] {
    let mut out = [Val::ZERO; PUBLIC_VALUES];
    out[..16].copy_from_slice(&node.context.to_fields().map(Val::from_u64));
    out[MODE] = Val::from_u64(mode);
    out[LEVEL] = Val::from_u8(node.level);
    out[COUNT] = Val::from_u8(node.count);
    out[ROOT..].copy_from_slice(&node.root.map(Val::from_u64));
    out
}

pub fn shape(height: usize) -> Result<MachineAir, CompileError> {
    let p = ProgramBuilder::new(PUBLIC_VALUES)
        .unwrap()
        .finish(Some(height))
        .map_err(|_| CompileError::Shape("registered height"))?;
    Ok(MachineAir::new(p))
}

fn registry_prefix(height: usize) -> Result<Vec<u64>, CompileError> {
    let air = shape(height)?;
    let a = analysis::analyze(&air).map_err(|_| CompileError::Shape("registered AIR geometry"))?;
    let layout = AirLayout::from_air::<Val>(&air);
    let gadget = LogUpGadget::new();
    let lookups = Lookups::<Val>::from_air::<profile::Challenge, _>(&air)
        .pack_same_bus(&gadget, a.quotient_chunks / 2);
    let constraints = symbolic::get_symbolic_constraints::<Val, profile::Challenge, _, _>(
        &air, layout, &lookups, &gadget,
    );
    let order = symbolic::get_constraint_layout::<Val, profile::Challenge, _, _>(
        &air, layout, &lookups, &gadget,
    );
    let air_id = commitment::hash_fields(
        AIR_DOMAIN,
        &fingerprint::encode(&constraints.0, &constraints.1, &order),
    )
    .unwrap();
    let mut fields = vec![
        1,
        height as u64,
        PUBLIC_VALUES as u64,
        super::WIDTH as u64,
        air.preprocessed_width() as u64,
        a.permutation_width_base as u64,
        a.quotient_chunks as u64,
        profile::LOG_BLOWUP as u64,
        profile::NUM_QUERIES as u64,
        profile::CAP_HEIGHT as u64,
        profile::NUM_RANDOM_CODEWORDS as u64,
        profile::QUERY_POW_BITS as u64,
        0, // commit PoW
        3,
        1,
        8,
        4,
        4,
        1, // cubic, binary FRI, Poseidon width/rate, salt, transcript revision
        1,
        0xffff_ffff, // Goldilocks modulus in u32 limbs
        3,
        commitment::MODULUS - 1,
        commitment::MODULUS - 1,
        0,
        1, // X^3-X-1
    ];
    fields.extend(air_id);
    // Separate the opt-in fixed-u64 node format from every legacy registry.
    // The default registry prefix, identity and historical bytes are unchanged.
    #[cfg(feature = "block-v2-wide-lanes")]
    fields.extend([0x5243_4f44_4543_3032, profile::NODE_CODEC_REVISION]); // RCODEC02
                                                                          // Pin the wallet component profile separately from this aggregate profile.
    fields.extend(
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [0; 32],
        }
        .to_fields()[..8]
            .iter(),
    );
    Ok(fields)
}

fn check_caps(caps: &Caps) -> Result<(), CompileError> {
    if caps.iter().any(|cap| cap.len() != 1 << profile::CAP_HEIGHT) {
        return Err(CompileError::Shape("registry cap length"));
    }
    Ok(())
}

pub fn profile_id(height: usize, caps: &Caps) -> Result<[u8; 32], CompileError> {
    check_caps(caps)?;
    let mut fields = registry_prefix(height)?;
    fields.extend(
        caps.iter()
            .flatten()
            .flatten()
            .map(|x| x.as_canonical_u64()),
    );
    let digest = commitment::hash_fields(REGISTRY_DOMAIN, &fields).unwrap();
    let mut out = [0; 32];
    for (chunk, value) in out.chunks_exact_mut(8).zip(digest) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

fn sum_bits(b: &mut ProgramBuilder, bits: &[Wire]) -> Wire {
    let mut sum = b.constant(Val::ZERO);
    for (i, &bit) in bits.iter().enumerate() {
        let weight = b.constant(Val::from_u64(1u64 << i));
        let term = b.mul(weight, bit);
        sum = b.add(sum, term);
    }
    sum
}

fn assert_u32(b: &mut ProgramBuilder, value: Wire) {
    let bits: [Wire; 32] = core::array::from_fn(|i| b.bit_hint(value, i));
    for &bit in &bits {
        b.assert_bool(bit);
    }
    let reconstructed = sum_bits(b, &bits);
    b.assert_equal(reconstructed, value);
}

fn registry(
    b: &mut ProgramBuilder,
    inputs: &mut ProofInputs,
    public: &[Wire],
    height: usize,
    caps: &Caps,
) -> Result<[Vec<[Wire; 4]>; 3], CompileError> {
    check_caps(caps)?;
    let mut fields: Vec<_> = registry_prefix(height)?
        .into_iter()
        .map(|v| b.constant(Val::from_u64(v)))
        .collect();
    let keys: [Vec<_>; 3] =
        core::array::from_fn(|i| caps[i].iter().map(|d| inputs.digest(b, d)).collect());
    fields.extend(keys.iter().flatten().flatten().copied());
    let digest = b.hash_fields(REGISTRY_DOMAIN, &fields);
    for i in 0..4 {
        // Canonical decomposition prevents x+p from aliasing the registry identity.
        let bits = b.bits(digest[i]);
        let low = sum_bits(b, &bits[..32]);
        let high = sum_bits(b, &bits[32..]);
        b.assert_equal(low, public[2 * i]);
        b.assert_equal(high, public[2 * i + 1]);
    }
    for &limb in &public[8..16] {
        assert_u32(b, limb);
    }
    Ok(keys)
}

fn finish(b: ProgramBuilder, inputs: ProofInputs) -> Result<Compiled, CompileError> {
    Ok(Compiled {
        program: b
            .finish(None)
            .map_err(|_| CompileError::Shape("program size"))?,
        witness: inputs.values,
    })
}

fn public(b: &ProgramBuilder) -> [Wire; PUBLIC_VALUES] {
    core::array::from_fn(|i| b.public(i).unwrap())
}

fn assert_constant(b: &mut ProgramBuilder, wire: Wire, value: u64) {
    let constant = b.constant(Val::from_u64(value));
    b.assert_equal(wire, constant);
}

/// Range constraint with public, fixed Lagrange selectors. No unconstrained mode hints.
fn selectors(b: &mut ProgramBuilder, value: Wire, first: u64, last: u64) -> Vec<Wire> {
    let one = b.constant(Val::ONE);
    let diffs: Vec<_> = (first..=last)
        .map(|v| {
            let c = b.constant(Val::from_u64(v));
            b.sub(value, c)
        })
        .collect();
    let mut polynomial = one;
    for &d in &diffs {
        polynomial = b.mul(polynomial, d);
    }
    b.assert_zero(polynomial);
    (first..=last)
        .map(|i| {
            let mut numerator = one;
            let mut denominator = Val::ONE;
            for j in first..=last {
                if i != j {
                    numerator = b.mul(numerator, diffs[(j - first) as usize]);
                    denominator *= Val::from_u64(i) - Val::from_u64(j);
                }
            }
            let inverse = b.constant(denominator.inverse());
            b.mul(numerator, inverse)
        })
        .collect()
}

fn parent_root(
    b: &mut ProgramBuilder,
    level: Wire,
    lc: Wire,
    rc: Wire,
    left: &[Wire],
    right: &[Wire],
) -> [Wire; 4] {
    let mut fields = vec![level, lc, rc];
    fields.extend_from_slice(left);
    fields.extend_from_slice(right);
    b.hash_fields(commitment::NODE, &fields)
}

pub fn wrapper(
    height: usize,
    caps: &Caps,
    wallet_public: &[Val],
    proof: &Proof<Config>,
) -> Result<Compiled, CompileError> {
    if wallet_public.len() != js::N_PUBLIC {
        return Err(CompileError::Shape("wallet statement"));
    }
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], WRAPPER);
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
    verifier::uni::verify(
        &mut b,
        &mut inputs,
        &ContextJoinSplitAir,
        js::HEIGHT,
        &inner,
        proof,
    )?;
    let digest = b.hash_fields(commitment::STATEMENT + 1, &wallet);
    let mut fields = public[..16].to_vec();
    fields.push(b.constant(Val::ONE));
    fields.extend(digest);
    let root = b.hash_fields(commitment::LEAF, &fields);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

/// Opt-in research candidate: two public wallet proofs in a level-one wrapper.
/// Both proof slots are always fully verified. Public COUNT selects one or two
/// actual entries; with COUNT=1, a caller can repeat its public proof in slot two
/// and the right committed leaf is canonical empty padding. This does not gate
/// away any verifier constraints or accept an unproved transaction.
///
/// The single-wallet entrypoints do not select this program. Explicit grouped
/// registration requires separately approved preprocessing keys and a new profile
/// pin. No wallet witness is accepted by this interface.
pub fn wrapper_pair(
    height: usize,
    caps: &Caps,
    wallet_public: [&[Val]; 2],
    proofs: [&Proof<Config>; 2],
) -> Result<Compiled, CompileError> {
    if wallet_public
        .iter()
        .any(|values| values.len() != js::N_PUBLIC)
    {
        return Err(CompileError::Shape("paired wallet statements"));
    }
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], WRAPPER);
    assert_constant(&mut b, public[LEVEL], 1);
    // Constrain COUNT before using COUNT-1 as a selector. Neither verifier is
    // conditional on this selector; it only selects the public committed root.
    let _count_masks = selectors(&mut b, public[COUNT], 1, 2);
    let one = b.constant(Val::ONE);
    let right_count = b.sub(public[COUNT], one);
    let inner_context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0; 32],
    }
    .to_fields();
    let mut roots = Vec::with_capacity(2);
    for slot in 0..2 {
        let wallet = inputs.bases(&mut b, wallet_public[slot]);
        let mut inner = wallet.clone();
        inner.extend(
            inner_context[..8]
                .iter()
                .map(|&value| b.constant(Val::from_u64(value))),
        );
        inner.extend_from_slice(&public[8..16]);
        verifier::uni::verify(
            &mut b,
            &mut inputs,
            &ContextJoinSplitAir,
            js::HEIGHT,
            &inner,
            proofs[slot],
        )?;
        let digest = b.hash_fields(commitment::STATEMENT + 1, &wallet);
        let mut fields = public[..16].to_vec();
        fields.push(one);
        fields.extend(digest);
        roots.push(b.hash_fields(commitment::LEAF, &fields));
    }
    let empty = b.hash_fields(commitment::EMPTY, &public[..16]);
    let mut right = empty;
    for i in 0..4 {
        let difference = b.sub(roots[1][i], empty[i]);
        let selected = b.mul(right_count, difference);
        right[i] = b.add(empty[i], selected);
    }
    let root = parent_root(&mut b, one, one, right_count, &roots[0], &right);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

pub fn empty(height: usize, caps: &Caps) -> Result<Compiled, CompileError> {
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], EMPTY);
    assert_constant(&mut b, public[COUNT], 0);
    let masks = selectors(&mut b, public[LEVEL], 0, 6);
    let mut root = b.hash_fields(commitment::EMPTY, &public[..16]);
    let zero = b.constant(Val::ZERO);
    let mut selected = [zero; 4];
    for (level, &mask) in masks.iter().enumerate() {
        for i in 0..4 {
            let term = b.mul(root[i], mask);
            selected[i] = b.add(selected[i], term);
        }
        if level < 6 {
            let level = b.constant(Val::from_usize(level + 1));
            root = parent_root(&mut b, level, zero, zero, &root, &root);
        }
    }
    for i in 0..4 {
        b.assert_equal(selected[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

pub fn merge(
    height: usize,
    caps: &Caps,
    children: [&[Val; PUBLIC_VALUES]; 2],
    proofs: [&BatchProof<Config>; 2],
) -> Result<Compiled, CompileError> {
    let child_air = shape(height)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let public = public(&b);
    let mut inputs = ProofInputs::default();
    let keys = registry(&mut b, &mut inputs, &public, height, caps)?;
    assert_constant(&mut b, public[MODE], MERGE);
    let mut child = Vec::new();
    for c in 0..2 {
        let fields = inputs.bases(&mut b, children[c]);
        for i in 0..16 {
            b.assert_equal(fields[i], public[i]);
        }
        let masks = selectors(&mut b, fields[MODE], WRAPPER, MERGE);
        let mut key = vec![[b.constant(Val::ZERO); 4]; 1 << profile::CAP_HEIGHT];
        for (i, selected) in key.iter_mut().enumerate() {
            for j in 0..4 {
                for k in 0..3 {
                    let term = b.mul(masks[k], keys[k][i][j]);
                    selected[j] = b.add(selected[j], term);
                }
            }
        }
        verifier::batch::verify(&mut b, &mut inputs, &child_air, &fields, &key, proofs[c])?;
        child.push(fields);
    }
    let left = &child[0];
    let right = &child[1];
    b.assert_equal(left[LEVEL], right[LEVEL]);
    let levels = selectors(&mut b, left[LEVEL], 0, 5);
    let one = b.constant(Val::ONE);
    let level = b.add(left[LEVEL], one);
    b.assert_equal(level, public[LEVEL]);
    let count = b.add(left[COUNT], right[COUNT]);
    b.assert_equal(count, public[COUNT]);
    let mut capacity = b.constant(Val::ZERO);
    for (i, &mask) in levels.iter().enumerate() {
        let n = b.constant(Val::from_usize(1 << i));
        let term = b.mul(n, mask);
        capacity = b.add(capacity, term);
    }
    let unfilled = b.sub(left[COUNT], capacity);
    let forbidden = b.mul(unfilled, right[COUNT]);
    b.assert_zero(forbidden);
    let root = parent_root(
        &mut b,
        level,
        left[COUNT],
        right[COUNT],
        &left[ROOT..],
        &right[ROOT..],
    );
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    finish(b, inputs)
}

#[cfg(test)]
mod tests {
    use super::super::backend::RegisteredProgram;
    use super::*;

    fn blank_caps() -> Caps {
        core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
    }

    #[test]
    fn empty_program_binds_canonical_padding_context_mode_and_registry() {
        let height = 2048;
        let caps = blank_caps();
        let context = Context {
            profile_id: profile_id(height, &caps).unwrap(),
            chain_id: [37; 32],
        };
        let compiled = empty(height, &caps).unwrap();
        for level in 0..=6 {
            let public = statement(commitment::empty_subtree(context, level).unwrap(), EMPTY);
            compiled
                .program
                .evaluate(&public, &compiled.witness)
                .unwrap();
            for index in [0, 8, MODE, LEVEL, COUNT, ROOT] {
                let mut wrong = public;
                wrong[index] += Val::ONE;
                assert!(
                    compiled
                        .program
                        .evaluate(&wrong, &compiled.witness)
                        .is_err(),
                    "index={index}, level={level}"
                );
            }
        }
        let public = statement(commitment::empty_subtree(context, 0).unwrap(), EMPTY);
        let mut changed_keys = compiled.witness;
        changed_keys[0] += Val::ONE;
        assert!(compiled.program.evaluate(&public, &changed_keys).is_err());
    }

    #[test]
    fn wrapper_compiles_a_real_wallet_proof_and_binds_its_statement() {
        let height = 1 << 18;
        let caps = blank_caps();
        let wallet = js::demo_witness();
        let wallet_public = js::public_values(&wallet);
        let context = Context {
            profile_id: profile_id(height, &caps).unwrap(),
            chain_id: [41; 32],
        };
        let mut inner_public = wallet_public.clone();
        inner_public.extend(
            Context {
                profile_id: profile::CANDIDATE_PROFILE_ID,
                chain_id: context.chain_id,
            }
            .to_fields()
            .map(Val::from_u64),
        );
        let config = profile::make_config();
        let proof = p3_uni_stark::prove(
            &config,
            &ContextJoinSplitAir,
            js::build_trace(&wallet),
            &inner_public,
        );
        p3_uni_stark::verify(&config, &ContextJoinSplitAir, &proof, &inner_public).unwrap();
        let digest = commitment::statement_digest(
            1,
            &wallet_public
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let node = commitment::leaf(
            context,
            commitment::Entry {
                kind: commitment::Kind::JoinSplit,
                statement_digest: digest,
            },
        )
        .unwrap();
        let public = statement(node, WRAPPER);
        let compiled = wrapper(height, &caps, &wallet_public, &proof).unwrap();
        let a = analysis::analyze(&MachineAir::new(compiled.program.clone())).unwrap();
        eprintln!(
            "wrapper rows={} height={} wires={} retained_lde_bytes={}",
            compiled.program.active_rows(),
            compiled.program.height(),
            compiled.program.wire_count(),
            a.retained_lde_bytes
        );
        compiled
            .program
            .evaluate(&public, &compiled.witness)
            .unwrap();
        for index in [0, 8, MODE, LEVEL, COUNT, ROOT] {
            let mut wrong = public;
            wrong[index] += Val::ONE;
            assert!(compiled
                .program
                .evaluate(&wrong, &compiled.witness)
                .is_err());
        }
        let mut altered = wallet_public;
        altered[js::PI_FEE] += Val::ONE;
        let bad = wrapper(height, &caps, &altered, &proof).unwrap();
        assert_eq!(
            compiled.program.manifest_fields(),
            bad.program.manifest_fields()
        );
        assert!(bad.program.evaluate(&public, &bad.witness).is_err());
    }

    #[test]
    #[ignore = "two real cubic wallet proofs and grouped compiler; run in a bounded service after timed trials"]
    fn paired_wrapper_binds_order_count_padding_and_both_full_wallet_verifiers() {
        use crate::block_v2::recursive;
        let wallets = [
            recursive::demo_wallet(0).unwrap(),
            recursive::demo_wallet(1).unwrap(),
        ];
        let height = 1 << 19;
        let caps = blank_caps();
        let context = Context {
            profile_id: profile_id(height, &caps).unwrap(),
            chain_id: wallets[0].chain,
        };
        let leaves: Vec<_> = wallets
            .iter()
            .map(|wallet| {
                let fields: Vec<_> = wallet.public.iter().map(|v| v.as_canonical_u64()).collect();
                commitment::leaf(
                    context,
                    commitment::Entry {
                        kind: commitment::Kind::JoinSplit,
                        statement_digest: commitment::statement_digest(1, &fields).unwrap(),
                    },
                )
                .unwrap()
            })
            .collect();
        let pair = statement(
            commitment::merge_nodes(leaves[0], leaves[1]).unwrap(),
            WRAPPER,
        );
        let single = statement(
            commitment::merge_nodes(leaves[0], commitment::empty_subtree(context, 0).unwrap())
                .unwrap(),
            WRAPPER,
        );
        let compiled = wrapper_pair(
            height,
            &caps,
            [&wallets[0].public, &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof],
        )
        .unwrap();
        let geometry = analysis::analyze(&MachineAir::new(compiled.program.clone())).unwrap();
        eprintln!("paired_wrapper active_rows={} height={} retained_lde_bytes={} recursive_proof_produced=false",
            compiled.program.active_rows(), compiled.program.height(), geometry.retained_lde_bytes);
        // A larger required height invalidates the unchanged-geometry cost model.
        assert!(compiled.program.height() <= height);
        compiled.program.evaluate(&pair, &compiled.witness).unwrap();
        compiled
            .program
            .evaluate(&single, &compiled.witness)
            .unwrap();
        for index in [0, 8, MODE, LEVEL, ROOT] {
            let mut wrong = pair;
            wrong[index] += Val::ONE;
            assert!(compiled
                .program
                .evaluate(&wrong, &compiled.witness)
                .is_err());
        }
        for count in [0, 3] {
            let mut wrong = pair;
            wrong[COUNT] = Val::from_u64(count);
            // Match the root arithmetic even for an invalid count, so rejection
            // cannot be credited to a stale root instead of the range constraint.
            let right_count = Val::from_u64(count) - Val::ONE;
            let empty = commitment::empty_subtree(context, 0).unwrap();
            let mut fields = vec![1, 1, right_count.as_canonical_u64()];
            fields.extend(leaves[0].root);
            fields.extend((0..4).map(|i| {
                let padding = Val::from_u64(empty.root[i]);
                (padding + right_count * (Val::from_u64(leaves[1].root[i]) - padding))
                    .as_canonical_u64()
            }));
            wrong[ROOT..].copy_from_slice(
                &commitment::hash_fields(commitment::NODE, &fields)
                    .unwrap()
                    .map(Val::from_u64),
            );
            assert!(compiled
                .program
                .evaluate(&wrong, &compiled.witness)
                .is_err());
        }
        let reversed = wrapper_pair(
            height,
            &caps,
            [&wallets[1].public, &wallets[0].public],
            [&wallets[1].proof, &wallets[0].proof],
        )
        .unwrap();
        assert_eq!(
            compiled.program.manifest_fields(),
            reversed.program.manifest_fields()
        );
        assert!(reversed.program.evaluate(&pair, &reversed.witness).is_err());
        let reverse_public = statement(
            commitment::merge_nodes(leaves[1], leaves[0]).unwrap(),
            WRAPPER,
        );
        reversed
            .program
            .evaluate(&reverse_public, &reversed.witness)
            .unwrap();

        // Odd occupancy needs no fabricated empty-wallet proof or private data:
        // repeating the available public proof keeps both verifiers enabled.
        let repeated = wrapper_pair(
            height,
            &caps,
            [&wallets[0].public, &wallets[0].public],
            [&wallets[0].proof, &wallets[0].proof],
        )
        .unwrap();
        assert_eq!(
            compiled.program.manifest_fields(),
            repeated.program.manifest_fields()
        );
        repeated
            .program
            .evaluate(&single, &repeated.witness)
            .unwrap();
        for slot in 0..2 {
            let mut changed = wallets[slot].public.clone();
            changed[js::PI_FEE] += Val::ONE;
            let mut values = [wallets[0].public.as_slice(), wallets[1].public.as_slice()];
            values[slot] = &changed;
            let bad = wrapper_pair(
                height,
                &caps,
                values,
                [&wallets[0].proof, &wallets[1].proof],
            )
            .unwrap();
            assert_eq!(
                compiled.program.manifest_fields(),
                bad.program.manifest_fields()
            );
            let mut changed_leaves = [leaves[0], leaves[1]];
            let fields: Vec<_> = changed.iter().map(|v| v.as_canonical_u64()).collect();
            changed_leaves[slot] = commitment::leaf(
                context,
                commitment::Entry {
                    kind: commitment::Kind::JoinSplit,
                    statement_digest: commitment::statement_digest(1, &fields).unwrap(),
                },
            )
            .unwrap();
            // Bind the altered statement into the expected root. Only actual
            // wallet-proof verification should reject this claimed transaction.
            let changed_pair = statement(
                commitment::merge_nodes(changed_leaves[0], changed_leaves[1]).unwrap(),
                WRAPPER,
            );
            let changed_single = statement(
                commitment::merge_nodes(
                    changed_leaves[0],
                    commitment::empty_subtree(context, 0).unwrap(),
                )
                .unwrap(),
                WRAPPER,
            );
            assert!(bad.program.evaluate(&changed_pair, &bad.witness).is_err());
            // Even an unused second slot is fully verified at COUNT=1.
            assert!(bad.program.evaluate(&changed_single, &bad.witness).is_err());
        }
        for slot in 0..2 {
            let encoded = postcard::to_allocvec(&wallets[slot].proof).unwrap();
            for mutation in 0..2 {
                let mut altered: Proof<Config> = postcard::from_bytes(&encoded).unwrap();
                if mutation == 0 {
                    altered.opening_proof.1.final_poly[0] += profile::Challenge::ONE;
                } else {
                    let mut roots = altered.commitments.trace.roots().to_vec();
                    roots[0][0] += Val::ONE;
                    altered.commitments.trace = p3_symmetric::MerkleCap::new(roots);
                }
                let mut proofs = [&wallets[0].proof, &wallets[1].proof];
                proofs[slot] = &altered;
                let bad = wrapper_pair(
                    height,
                    &caps,
                    [&wallets[0].public, &wallets[1].public],
                    proofs,
                )
                .unwrap();
                assert_eq!(
                    compiled.program.manifest_fields(),
                    bad.program.manifest_fields()
                );
                // Statements and both roots are unchanged: these cases isolate
                // proof verification, including the unused slot under COUNT=1.
                assert!(bad.program.evaluate(&pair, &bad.witness).is_err());
                assert!(bad.program.evaluate(&single, &bad.witness).is_err());
            }
        }
        assert!(wrapper_pair(
            height,
            &caps,
            [&wallets[0].public[..js::N_PUBLIC - 1], &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof]
        )
        .is_err());
    }

    #[test]
    fn merge_executes_real_registered_empty_proof_verifiers() {
        let height = 2048;
        let mut caps = blank_caps();
        // Registration is independent of values in registry/proof witness inputs.
        let initial = empty(height, &caps).unwrap();
        let registered =
            RegisteredProgram::new(MachineAir::new(initial.program.pad_to(height).unwrap()))
                .unwrap();
        caps[1] = registered.preprocessing_cap().roots().to_vec();
        let compiled = empty(height, &caps).unwrap();
        assert_eq!(
            registered.air().program().manifest_fields(),
            compiled
                .program
                .clone()
                .pad_to(height)
                .unwrap()
                .manifest_fields()
        );
        let context = Context {
            profile_id: profile_id(height, &caps).unwrap(),
            chain_id: [43; 32],
        };
        let node = commitment::empty_subtree(context, 0).unwrap();
        let public = statement(node, EMPTY);
        let proof = registered.prove(&public, &compiled.witness).unwrap();
        registered.verify(&proof, &public).unwrap();
        let parent = statement(commitment::merge_nodes(node, node).unwrap(), MERGE);
        let compiled = merge(height, &caps, [&public, &public], [&proof, &proof]).unwrap();
        eprintln!(
            "empty-child merge rows={} height={} wires={}",
            compiled.program.active_rows(),
            compiled.program.height(),
            compiled.program.wire_count()
        );
        compiled
            .program
            .evaluate(&parent, &compiled.witness)
            .unwrap();
        for index in [0, 8, MODE, LEVEL, COUNT, ROOT] {
            let mut wrong = parent;
            wrong[index] += Val::ONE;
            assert!(compiled
                .program
                .evaluate(&wrong, &compiled.witness)
                .is_err());
        }
        let mut wrong_child = public;
        wrong_child[MODE] = Val::from_u64(WRAPPER);
        let bad = merge(height, &caps, [&wrong_child, &public], [&proof, &proof]).unwrap();
        assert_eq!(
            compiled.program.manifest_fields(),
            bad.program.manifest_fields()
        );
        assert!(bad.program.evaluate(&parent, &bad.witness).is_err());
    }

    #[test]
    fn full_size_merge_geometry_is_measured_without_preprocessing_allocation() {
        let height = 1 << 18;
        let air = shape(height).unwrap();
        let template = verifier::template::batch(&air).unwrap();
        let caps = blank_caps();
        let public = [Val::ZERO; PUBLIC_VALUES];
        let compiled = merge(height, &caps, [&public, &public], [&template, &template]).unwrap();
        let a = analysis::analyze(&MachineAir::new(compiled.program.clone())).unwrap();
        eprintln!(
            "merge child_height={height} rows={} outer_height={} wires={} retained_lde_bytes={}",
            compiled.program.active_rows(),
            compiled.program.height(),
            compiled.program.wire_count(),
            a.retained_lde_bytes
        );
        assert!(
            compiled
                .program
                .evaluate(&public, &compiled.witness)
                .is_err(),
            "shape templates are not valid proofs"
        );
    }
}
