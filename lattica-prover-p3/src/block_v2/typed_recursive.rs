//! Mixed-type research orchestration with its own pinned five-key registry.
//! No production ABI, activation, durable host application, or qualified timing.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use p3_symmetric::MerkleCap;
use serde::{Deserialize, Serialize};

use super::commitment::{self, Context, Entry, Kind, NodeSummary};
use super::machine::{
    backend::{RegisteredProgram, RegisteredVerifier},
    programs::{self, Compiled, PUBLIC_VALUES},
    typed_finalizer, typed_pairs,
    typed_programs::{self, Caps, HTLC, ISSUANCE},
    verifier::template,
    MachineAir,
};
use super::profile;
use super::recursive::{self, Error, NodeProof, WalletProof};
use super::typed_leaf::ContextAir;
use crate::{htlc_air as htlc, joinsplit_air as js};

/// Supplied independently from the host's expected transaction/height/policy.
#[derive(Clone, Copy)]
pub enum Policy {
    JoinSplit,
    Htlc { expected_height: u64 },
    Issuance { authorized_mint: u64 },
}

impl Policy {
    pub fn mode(self) -> u64 {
        match self {
            Self::JoinSplit => programs::WRAPPER,
            Self::Htlc { .. } => HTLC,
            Self::Issuance { .. } => ISSUANCE,
        }
    }

    fn kind(self) -> Kind {
        match self {
            Self::JoinSplit => Kind::JoinSplit,
            Self::Htlc { .. } => Kind::Htlc,
            Self::Issuance { .. } => Kind::Coinbase,
        }
    }
}

pub fn verify_wallet(wallet: &WalletProof, policy: Policy) -> Result<(), Error> {
    if matches!(policy, Policy::JoinSplit) {
        return recursive::verify_wallet(wallet);
    }
    let mut inner = wallet.public.clone();
    inner.extend(
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: wallet.chain,
        }
        .to_fields()
        .map(Val::from_u64),
    );
    match policy {
        Policy::Htlc { expected_height } => {
            if wallet.public.len() != htlc::N_PUBLIC
                || expected_height >= 1u64 << htlc::BITS
                || wallet.public[htlc::PI_HEIGHT] != Val::from_u64(expected_height)
                || wallet.public[htlc::PI_MINT] != Val::ZERO
            {
                return Err("HTLC statement/policy".into());
            }
            p3_uni_stark::verify(
                &profile::make_config(),
                &ContextAir(htlc::HtlcAir),
                &wallet.proof,
                &inner,
            )
            .map_err(|e| format!("HTLC verification: {e:?}").into())
        }
        Policy::Issuance { authorized_mint } => {
            if wallet.public.len() != js::N_PUBLIC
                || authorized_mint == 0
                || authorized_mint >= 1u64 << js::BITS
                || wallet.public[js::PI_MINT] != Val::from_u64(authorized_mint)
            {
                return Err("issuance statement/policy".into());
            }
            p3_uni_stark::verify(
                &profile::make_config(),
                &ContextAir(js::JoinSplitAir),
                &wallet.proof,
                &inner,
            )
            .map_err(|e| format!("issuance verification: {e:?}").into())
        }
        Policy::JoinSplit => unreachable!(),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "programs::Caps<N>: Serialize",
    deserialize = "programs::Caps<N>: Deserialize<'de>"
))]
pub struct Registry<const N: usize = 5> {
    pub height: usize,
    pub caps: programs::Caps<N>,
}

impl<const N: usize> Registry<N> {
    pub fn id(&self) -> Result<[u8; 32], Error> {
        if !matches!(N, 5 | 6 | 12) {
            return Err("unsupported typed registry size".into());
        }
        Ok(programs::profile_id(self.height, &self.caps)?)
    }

    /// CPU verification needs only the pinned registry, expected statement and
    /// this root proof. Inner proofs and their original witness artifacts are unnecessary.
    pub fn verify(
        &self,
        expected_profile: [u8; 32],
        node: &NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<(), Error> {
        let summary = recursive::summary_with_modes(expected, N as u64)?;
        if self.id()? != expected_profile
            || summary.context.profile_id != expected_profile
            || &node.public != expected
        {
            return Err("unapproved typed registry or unexpected statement".into());
        }
        let mode = expected[programs::MODE].as_canonical_u64();
        RegisteredVerifier::from_trusted_cap(
            PUBLIC_VALUES,
            self.height,
            MerkleCap::new(self.caps[(mode - 1) as usize].clone()),
        )
        .map_err(|e| format!("{e:?}"))?
        .verify(&node.proof, expected)
        .map_err(|e| e.into())
    }
}

pub fn compile_registration(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
) -> Result<Compiled, Error> {
    let caps: Caps = core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    Ok(match mode {
        programs::WRAPPER | HTLC | ISSUANCE => {
            let wallet = wallet.ok_or("typed wrapper registration needs a leaf proof template")?;
            typed_programs::wrapper(height, &caps, mode, &wallet.public, &wallet.proof)?
        }
        programs::EMPTY => programs::empty(height, &caps)?,
        programs::MERGE => {
            let proof = template::batch(&programs::shape(height)?)?;
            let public = [Val::ZERO; PUBLIC_VALUES];
            programs::merge(height, &caps, [&public, &public], [&proof, &proof])?
        }
        _ => return Err("unknown typed program mode".into()),
    })
}

pub fn register(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
    worker_memory_bytes: u64,
) -> Result<Vec<[Val; 4]>, Error> {
    let compiled = compile_registration(height, mode, wallet)?;
    register_compiled(height, compiled, worker_memory_bytes)
}

pub fn register_finalized(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
    worker_memory_bytes: u64,
) -> Result<Vec<[Val; 4]>, Error> {
    let compiled = typed_finalizer::compile_registration(height, mode, wallet)?;
    register_compiled(height, compiled, worker_memory_bytes)
}

fn paired_templates(mode: u64, wallets: [&WalletProof; 3]) -> Option<[&WalletProof; 2]> {
    typed_pairs::leaf_modes(mode).ok().map(|kinds| {
        kinds.map(|kind| match kind {
            programs::WRAPPER => wallets[0],
            HTLC => wallets[1],
            ISSUANCE => wallets[2],
            _ => unreachable!("validated typed pair mode"),
        })
    })
}

pub fn register_paired(
    height: usize,
    mode: u64,
    wallets: [&WalletProof; 3],
    worker_memory_bytes: u64,
) -> Result<Vec<[Val; 4]>, Error> {
    let compiled =
        typed_pairs::compile_registration(height, mode, paired_templates(mode, wallets))?;
    register_compiled(height, compiled, worker_memory_bytes)
}

fn register_compiled(
    height: usize,
    compiled: Compiled,
    worker_memory_bytes: u64,
) -> Result<Vec<[Val; 4]>, Error> {
    let program = compiled
        .program
        .pad_to(height)
        .map_err(|e| format!("{e:?}"))?;
    let registered =
        RegisteredProgram::new_with_memory_budget(MachineAir::new(program), worker_memory_bytes)
            .map_err(|e| format!("{e:?}"))?;
    Ok(registered.preprocessing_cap().roots().to_vec())
}

/// Compile all five modes to a stable shared height before allocating any
/// preprocessing LDE. The caller must qualify the resulting geometry separately.
pub fn common_height(wallets: [&WalletProof; 3]) -> Result<usize, Error> {
    common_height_inner(wallets, false)
}

pub fn common_height_finalized(wallets: [&WalletProof; 3]) -> Result<usize, Error> {
    common_height_inner(wallets, true)
}

pub fn common_height_paired(wallets: [&WalletProof; 3]) -> Result<usize, Error> {
    let mut height = 1 << 18;
    loop {
        let mut required = height;
        for mode in 1..=typed_pairs::KEY_COUNT as u64 {
            let compiled =
                typed_pairs::compile_registration(height, mode, paired_templates(mode, wallets))?;
            required = required.max(compiled.program.height());
        }
        if required == height {
            return Ok(height);
        }
        if required > 1 << 21 {
            return Err("paired typed geometry exceeds research range".into());
        }
        height = required;
    }
}

fn common_height_inner(wallets: [&WalletProof; 3], finalized: bool) -> Result<usize, Error> {
    let mut height = 1 << 18;
    loop {
        let mut required = height;
        for mode in 1..=if finalized { 6 } else { 5 } {
            let wallet = match mode {
                programs::WRAPPER => Some(wallets[0]),
                HTLC => Some(wallets[1]),
                ISSUANCE => Some(wallets[2]),
                _ => None,
            };
            let compiled = if finalized {
                typed_finalizer::compile_registration(height, mode, wallet)?
            } else {
                compile_registration(height, mode, wallet)?
            };
            required = required.max(compiled.program.height());
        }
        if required == height {
            return Ok(height);
        }
        if required > 1 << 21 {
            return Err("typed recursive geometry exceeds the research range".into());
        }
        height = required;
    }
}

/// Keep one immutable preprocessing program. Fresh proving randomness is made
/// by RegisteredProgram for every invocation, as in the legacy research path.
pub struct Session<const N: usize = 5> {
    registry: Registry<N>,
    expected_profile: [u8; 32],
    worker_memory_bytes: u64,
    cached: Option<(u64, RegisteredProgram)>,
    stats: recursive::CacheStats,
}

impl<const N: usize> Session<N> {
    pub fn new(
        registry: Registry<N>,
        expected_profile: [u8; 32],
        worker_memory_bytes: u64,
    ) -> Result<Self, Error> {
        if registry.id()? != expected_profile || worker_memory_bytes == 0 {
            return Err("unapproved typed registry or missing worker budget".into());
        }
        Ok(Self {
            registry,
            expected_profile,
            worker_memory_bytes,
            cached: None,
            stats: recursive::CacheStats::default(),
        })
    }

    pub fn stats(&self) -> recursive::CacheStats {
        self.stats
    }

    pub fn clear(&mut self) {
        self.cached = None;
    }

    fn prove(
        &mut self,
        mode: u64,
        compiled: Compiled,
        public: [Val; PUBLIC_VALUES],
    ) -> Result<NodeProof, Error> {
        if public[programs::MODE] != Val::from_u64(mode)
            || recursive::summary_with_modes(&public, N as u64)?
                .context
                .profile_id
                != self.expected_profile
        {
            return Err("typed session mode/profile".into());
        }
        let program = compiled
            .program
            .pad_to(self.registry.height)
            .map_err(|e| format!("{e:?}"))?;
        if self.cached.as_ref().is_some_and(|(m, _)| *m == mode) {
            if self.cached.as_ref().unwrap().1.air().program() != &program {
                return Err("typed cached program changed".into());
            }
            drop(program);
            self.stats.hits = self
                .stats
                .hits
                .checked_add(1)
                .ok_or("typed cache hit overflow")?;
        } else {
            self.cached = None;
            let registered = RegisteredProgram::new_with_memory_budget(
                MachineAir::new(program),
                self.worker_memory_bytes,
            )
            .map_err(|e| format!("{e:?}"))?;
            if registered.preprocessing_cap().roots() != self.registry.caps[(mode - 1) as usize] {
                return Err("typed program differs from registered key".into());
            }
            self.cached = Some((mode, registered));
            self.stats.setups = self
                .stats
                .setups
                .checked_add(1)
                .ok_or("typed cache setup overflow")?;
        }
        let proof = self
            .cached
            .as_ref()
            .unwrap()
            .1
            .prove(&public, &compiled.witness)
            .map_err(|e| format!("{e:?}"))?;
        let node = NodeProof { public, proof };
        self.registry
            .verify(self.expected_profile, &node, &node.public)?;
        Ok(node)
    }

    pub fn wrap(&mut self, wallet: &WalletProof, policy: Policy) -> Result<NodeProof, Error> {
        if N == typed_pairs::KEY_COUNT {
            return Err("paired registry requires wrap_pair".into());
        }
        verify_wallet(wallet, policy)?;
        let fields: Vec<_> = wallet.public.iter().map(|v| v.as_canonical_u64()).collect();
        let entry = Entry {
            kind: policy.kind(),
            statement_digest: commitment::statement_digest(policy.kind() as u8, &fields)?,
        };
        let node = commitment::leaf(
            Context {
                profile_id: self.expected_profile,
                chain_id: wallet.chain,
            },
            entry,
        )?;
        let compiled = typed_programs::wrapper(
            self.registry.height,
            &self.registry.caps,
            policy.mode(),
            &wallet.public,
            &wallet.proof,
        )?;
        self.prove(
            policy.mode(),
            compiled,
            programs::statement(node, policy.mode()),
        )
    }

    /// Verify both slots, including the unused right slot when count is one.
    pub fn wrap_pair(
        &mut self,
        wallets: [&WalletProof; 2],
        policies: [Policy; 2],
        count: u8,
    ) -> Result<NodeProof, Error> {
        if N != typed_pairs::KEY_COUNT || !matches!(count, 1 | 2) {
            return Err("paired wrapper requires twelve keys and one or two inputs".into());
        }
        if wallets[0].chain != wallets[1].chain {
            return Err("paired wallets use different chains".into());
        }
        for (wallet, policy) in wallets.iter().zip(policies) {
            verify_wallet(wallet, policy)?;
        }
        let context = Context {
            profile_id: self.expected_profile,
            chain_id: wallets[0].chain,
        };
        let leaf = |slot: usize| -> Result<NodeSummary, Error> {
            let fields: Vec<_> = wallets[slot]
                .public
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect();
            let kind = policies[slot].kind();
            Ok(commitment::leaf(
                context,
                Entry {
                    kind,
                    statement_digest: commitment::statement_digest(kind as u8, &fields)?,
                },
            )?)
        };
        let right = if count == 2 {
            leaf(1)?
        } else {
            commitment::empty_subtree(context, 0)?
        };
        let node = commitment::merge_nodes(leaf(0)?, right)?;
        let mode = typed_pairs::mode_for(policies.map(Policy::mode))?;
        let caps: &typed_pairs::Caps = self.registry.caps.as_slice().try_into()?;
        let compiled = typed_pairs::wrapper_pair(
            self.registry.height,
            caps,
            mode,
            [&wallets[0].public, &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof],
        )?;
        self.prove(mode, compiled, programs::statement(node, mode))
    }

    pub fn empty(&mut self, chain: [u8; 32], level: u8) -> Result<NodeProof, Error> {
        let node = commitment::empty_subtree(
            Context {
                profile_id: self.expected_profile,
                chain_id: chain,
            },
            level,
        )?;
        self.prove(
            programs::EMPTY,
            programs::empty(self.registry.height, &self.registry.caps)?,
            programs::statement(node, programs::EMPTY),
        )
    }

    pub fn merge(&mut self, left: &NodeProof, right: &NodeProof) -> Result<NodeProof, Error> {
        self.registry
            .verify(self.expected_profile, left, &left.public)?;
        self.registry
            .verify(self.expected_profile, right, &right.public)?;
        let node: NodeSummary = commitment::merge_nodes(
            recursive::summary_with_modes(&left.public, N as u64)?,
            recursive::summary_with_modes(&right.public, N as u64)?,
        )?;
        let compiled = programs::merge(
            self.registry.height,
            &self.registry.caps,
            [&left.public, &right.public],
            [&left.proof, &right.proof],
        )?;
        self.prove(
            programs::MERGE,
            compiled,
            programs::statement(node, programs::MERGE),
        )
    }

    /// Terminal proof for a separately registered finalizer construction.
    pub fn finalize(&mut self, child: &NodeProof) -> Result<NodeProof, Error> {
        let mode = match N {
            6 => typed_finalizer::FINALIZE,
            12 => typed_pairs::FINALIZE,
            _ => return Err("finalization requires six- or twelve-key research registry".into()),
        };
        self.registry
            .verify(self.expected_profile, child, &child.public)?;
        let mut node = recursive::summary_with_modes(&child.public, N as u64)?;
        if node.level >= commitment::DEPTH || child.public[programs::MODE] == Val::from_u64(mode) {
            return Err("finalizer child must be an unfinished subtree".into());
        }
        while node.level < commitment::DEPTH {
            let empty = commitment::empty_subtree(node.context, node.level)?;
            node = commitment::merge_nodes(node, empty)?;
        }
        let compiled = if N == typed_pairs::KEY_COUNT {
            let caps: &typed_pairs::Caps = self.registry.caps.as_slice().try_into()?;
            typed_pairs::finalize(self.registry.height, caps, &child.public, &child.proof)?
        } else {
            let caps: &typed_finalizer::Caps = self.registry.caps.as_slice().try_into()?;
            typed_finalizer::compile(self.registry.height, caps, &child.public, &child.proof)?
        };
        self.prove(mode, compiled, programs::statement(node, mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed_wallets() -> [WalletProof; 2] {
        let context = Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [41; 32],
        };
        let htlc = htlc::demo_htlc_witness();
        let htlc_bytes = super::super::typed_leaf::prove_htlc_research(&htlc, &context).unwrap();
        let mut issuance = js::demo_witness();
        issuance.mint = 7;
        issuance.outputs[0].value += 7;
        let issuance_bytes =
            super::super::typed_leaf::prove_issuance_research(&issuance, &context, 7).unwrap();
        [
            WalletProof {
                chain: context.chain_id,
                public: htlc::public_values(&htlc),
                proof: postcard::from_bytes(&htlc_bytes[72..]).unwrap(),
            },
            WalletProof {
                chain: context.chain_id,
                public: js::public_values(&issuance),
                proof: postcard::from_bytes(&issuance_bytes[72..]).unwrap(),
            },
        ]
    }

    #[test]
    fn six_key_session_requires_its_own_profile_and_rejects_finished_children() {
        let height = 2048;
        let budget = 512 * 1024 * 1024;
        let mut caps: programs::Caps<6> =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        caps[1] = register_finalized(height, programs::EMPTY, None, budget).unwrap();
        let registry = Registry::<6> { height, caps };
        let pin = registry.id().unwrap();
        let encoded = serde_json::to_vec(&registry).unwrap();
        let restored: Registry<6> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.id().unwrap(), pin);
        let legacy = Registry::<5> {
            height,
            caps: core::array::from_fn(|i| registry.caps[i].clone()),
        };
        assert_ne!(legacy.id().unwrap(), pin);
        let mut session = Session::new(registry.clone(), pin, budget).unwrap();
        let root = session.empty([47; 32], commitment::DEPTH).unwrap();
        registry.verify(pin, &root, &root.public).unwrap();
        assert!(legacy.verify(pin, &root, &root.public).is_err());
        assert!(session.finalize(&root).is_err());
        assert!(Session::new(registry, [0; 32], budget).is_err());
    }

    #[test]
    fn paired_session_binds_its_registry_and_rejects_invalid_slots_before_proving() {
        let (wallet, policy) = super::super::typed_fixture::wallet(0).unwrap();
        let height = 2048;
        let budget = 512 * 1024 * 1024;
        let mut caps: programs::Caps<12> =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        caps[1] = register_paired(height, programs::EMPTY, [&wallet; 3], budget).unwrap();
        let registry = Registry::<12> { height, caps };
        let pin = registry.id().unwrap();
        let restored: Registry<12> =
            serde_json::from_slice(&serde_json::to_vec(&registry).unwrap()).unwrap();
        assert_eq!(restored.id().unwrap(), pin);
        let previous = Registry::<6> {
            height,
            caps: core::array::from_fn(|i| registry.caps[i].clone()),
        };
        assert_ne!(previous.id().unwrap(), pin);
        let mut session = Session::new(registry.clone(), pin, budget).unwrap();
        assert!(session.wrap(&wallet, policy).is_err());
        for count in [0, 3, 64] {
            assert!(session.wrap_pair([&wallet; 2], [policy; 2], count).is_err());
        }
        let (mut bad, _) = super::super::typed_fixture::wallet(0).unwrap();
        bad.chain[0] ^= 1;
        assert!(session.wrap_pair([&wallet, &bad], [policy; 2], 2).is_err());
        bad.chain = wallet.chain;
        bad.public[js::PI_MINT] = Val::ONE;
        assert!(session.wrap_pair([&wallet, &bad], [policy; 2], 1).is_err());
        let mut old_session =
            Session::new(previous.clone(), previous.id().unwrap(), budget).unwrap();
        assert!(old_session.wrap_pair([&wallet; 2], [policy; 2], 2).is_err());
        let root = session.empty([47; 32], commitment::DEPTH).unwrap();
        registry.verify(pin, &root, &root.public).unwrap();
        assert!(previous.verify(pin, &root, &root.public).is_err());
        assert!(session.finalize(&root).is_err());
        assert!(Session::new(registry, [0; 32], budget).is_err());
    }

    #[test]
    fn typed_policy_and_legacy_separation() {
        let [htlc, issuance] = typed_wallets();
        let expected_height = htlc::demo_htlc_witness().current_height;
        verify_wallet(&htlc, Policy::Htlc { expected_height }).unwrap();
        verify_wallet(&issuance, Policy::Issuance { authorized_mint: 7 }).unwrap();
        assert!(verify_wallet(
            &htlc,
            Policy::Htlc {
                expected_height: expected_height + 1
            }
        )
        .is_err());
        assert!(verify_wallet(&issuance, Policy::Issuance { authorized_mint: 8 }).is_err());
        assert!(verify_wallet(&issuance, Policy::JoinSplit).is_err());
        assert!(verify_wallet(&htlc, Policy::JoinSplit).is_err());
        let normal = recursive::demo_wallet(0).unwrap();
        assert!(verify_wallet(&normal, Policy::Issuance { authorized_mint: 7 }).is_err());
        let mut relabeled = htlc;
        relabeled.chain[0] ^= 1;
        assert!(verify_wallet(&relabeled, Policy::Htlc { expected_height }).is_err());
    }

    #[test]
    fn typed_mixed_geometry_is_compiled_before_registration() {
        let [htlc, issuance] = typed_wallets();
        let normal = recursive::demo_wallet(0).unwrap();
        let height = common_height([&normal, &htlc, &issuance]).unwrap();
        let analysis =
            super::super::machine::analysis::analyze(&programs::shape(height).unwrap()).unwrap();
        eprintln!("typed mixed geometry height={height} retained_lde_lower_bound_bytes={} main_width={} preprocessed_width={}", analysis.retained_lde_bytes, analysis.main_width, analysis.preprocessed_width);
        assert!(analysis.fri_ali_bits >= profile::MIN_TREE_SECURITY_BITS);
    }

    #[test]
    fn pinned_typed_empty_root_and_merge_interpreter() {
        let height = 2048;
        let budget = 512 * 1024 * 1024;
        let mut caps: Caps =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        assert!(register(height, programs::EMPTY, None, 1).is_err());
        caps[1] = register(height, programs::EMPTY, None, budget).unwrap();
        let registry = Registry { height, caps };
        let pin = registry.id().unwrap();
        let mut session = Session::new(registry.clone(), pin, budget).unwrap();
        let left = session.empty([41; 32], 5).unwrap();
        assert!(session.finalize(&left).is_err());
        let right = session.empty([41; 32], 5).unwrap();
        drop(session);
        registry.verify(pin, &left, &left.public).unwrap();
        assert!(registry.verify([0; 32], &left, &left.public).is_err());
        let mut wrong = left.public;
        wrong[programs::ROOT] += Val::ONE;
        assert!(registry.verify(pin, &left, &wrong).is_err());
        let node = commitment::merge_nodes(
            recursive::summary_with_modes(&left.public, 5).unwrap(),
            recursive::summary_with_modes(&right.public, 5).unwrap(),
        )
        .unwrap();
        let compiled = programs::merge(
            height,
            &registry.caps,
            [&left.public, &right.public],
            [&left.proof, &right.proof],
        )
        .unwrap();
        compiled
            .program
            .evaluate(
                &programs::statement(node, programs::MERGE),
                &compiled.witness,
            )
            .unwrap();
        // This is a real pair of empty proofs and an interpreted merge; it is
        // deliberately not evidence of a proved mixed-transaction root.
    }
}
