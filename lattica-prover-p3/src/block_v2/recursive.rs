//! Research orchestration for actual recursive proofs. No production acceptance ABI.
//! A registry is trusted only against an independently pinned expected profile.
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use p3_symmetric::MerkleCap;
use p3_uni_stark::Proof;
use serde::{Deserialize, Serialize};

use super::machine::{
    analysis,
    backend::{RegisteredProgram, RegisteredVerifier},
    programs::{self, Caps, Compiled, PUBLIC_VALUES},
    verifier::template,
    MachineAir,
};
use super::{
    commitment::{self, Context, Entry, Kind, NodeSummary},
    leaf::ContextJoinSplitAir,
    profile::{self, Config},
};
use crate::joinsplit_air as js;

pub type Error = Box<dyn std::error::Error>;
pub const DEMO_CHAIN: [u8; 32] = [0x5a; 32];

#[derive(Serialize, Deserialize)]
pub struct WalletProof {
    pub chain: [u8; 32],
    pub public: Vec<Val>,
    pub proof: Proof<Config>,
}

/// Validate a public candidate wallet artifact without any witness data.
pub fn verify_wallet(wallet: &WalletProof) -> Result<(), Error> {
    if wallet.public.len() != js::N_PUBLIC {
        return Err("wallet public shape".into());
    }
    // The artifact stores the transaction statement and chain separately. The
    // proved statement also includes the candidate profile and chain limbs.
    let mut inner = wallet.public.clone();
    inner.extend(
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: wallet.chain,
        }
        .to_fields()
        .map(Val::from_u64),
    );
    p3_uni_stark::verify(
        &profile::make_config(),
        &ContextJoinSplitAir,
        &wallet.proof,
        &inner,
    )
    .map_err(|e| format!("wallet verification: {e:?}").into())
}

#[cfg(test)]
mod wallet_verification_tests {
    use super::*;

    #[test]
    fn public_wallet_verification_binds_context_and_statement() {
        let mut wallet = demo_wallet(0).unwrap();
        verify_wallet(&wallet).unwrap();
        wallet.chain[0] ^= 1;
        assert!(verify_wallet(&wallet).is_err());
        wallet.chain[0] ^= 1;
        wallet.public[0] += Val::ONE;
        assert!(verify_wallet(&wallet).is_err());
        wallet.public[0] -= Val::ONE;
        wallet.public.pop();
        assert!(verify_wallet(&wallet).is_err());
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Registry {
    pub height: usize,
    pub caps: Caps,
}

#[derive(Serialize, Deserialize)]
pub struct NodeProof {
    pub public: [Val; PUBLIC_VALUES],
    pub proof: BatchProof<Config>,
}

impl Registry {
    pub fn id(&self) -> Result<[u8; 32], Error> {
        Ok(programs::profile_id(self.height, &self.caps)?)
    }

    pub fn verifier(
        &self,
        expected_profile: [u8; 32],
        mode: u64,
    ) -> Result<RegisteredVerifier, Error> {
        if self.id()? != expected_profile || !(1..=3).contains(&mode) {
            return Err("unapproved registry/mode".into());
        }
        Ok(RegisteredVerifier::from_trusted_cap(
            PUBLIC_VALUES,
            self.height,
            MerkleCap::new(self.caps[(mode - 1) as usize].clone()),
        )
        .map_err(|e| format!("{e:?}"))?)
    }

    pub fn verify(
        &self,
        expected_profile: [u8; 32],
        node: &NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<(), Error> {
        if &node.public != expected {
            return Err("unexpected recursive statement".into());
        }
        let summary = summary(expected)?;
        if summary.context.profile_id != expected_profile {
            return Err("unexpected profile".into());
        }
        self.verifier(
            expected_profile,
            expected[programs::MODE].as_canonical_u64(),
        )?
        .verify(&node.proof, expected)
        .map_err(|e| e.into())
    }
}

pub fn summary(public: &[Val; PUBLIC_VALUES]) -> Result<NodeSummary, Error> {
    summary_with_modes(public, 3)
}

pub(crate) fn summary_with_modes(
    public: &[Val; PUBLIC_VALUES],
    modes: u64,
) -> Result<NodeSummary, Error> {
    let mut context_bytes = [0; 64];
    for (chunk, value) in context_bytes.chunks_exact_mut(4).zip(&public[..16]) {
        let value =
            u32::try_from(value.as_canonical_u64()).map_err(|_| "noncanonical context limb")?;
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    let mode = public[programs::MODE].as_canonical_u64();
    let level = public[programs::LEVEL].as_canonical_u64();
    let count = public[programs::COUNT].as_canonical_u64();
    if !(1..=modes).contains(&mode) || level > 6 || count > 1 << level {
        return Err("node metadata range".into());
    }
    let node = NodeSummary {
        context: Context {
            profile_id: context_bytes[..32].try_into().unwrap(),
            chain_id: context_bytes[32..].try_into().unwrap(),
        },
        level: level as u8,
        count: count as u8,
        root: core::array::from_fn(|i| public[programs::ROOT + i].as_canonical_u64()),
    };
    commitment::validate_summary(node)?;
    Ok(node)
}

fn blank_caps() -> Caps {
    core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
}

pub fn compile_registration(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
) -> Result<Compiled, Error> {
    let caps = blank_caps();
    Ok(match mode {
        programs::WRAPPER => {
            let wallet = wallet.ok_or("wrapper template requires a wallet proof")?;
            programs::wrapper(height, &caps, &wallet.public, &wallet.proof)?
        }
        programs::EMPTY => programs::empty(height, &caps)?,
        programs::MERGE => {
            let air = programs::shape(height)?;
            let proof = template::batch(&air)?;
            let public = [Val::ZERO; PUBLIC_VALUES];
            programs::merge(height, &caps, [&public, &public], [&proof, &proof])?
        }
        _ => return Err("unknown program mode".into()),
    })
}

/// Compile to closure without allocating a preprocessing LDE.
pub fn common_height(wallet: &WalletProof) -> Result<usize, Error> {
    let mut height = 1 << 18;
    loop {
        let mut required = height;
        for mode in [programs::WRAPPER, programs::EMPTY, programs::MERGE] {
            let compiled = compile_registration(height, mode, Some(wallet))?;
            required = required.max(compiled.program.height());
            println!(
                "geometry mode={mode} child_height={height} active_rows={} required_height={}",
                compiled.program.active_rows(),
                compiled.program.height()
            );
        }
        if required == height {
            let a = analysis::analyze(&programs::shape(height)?).map_err(|e| format!("{e:?}"))?;
            a.check_ram_lower_bound().map_err(|e| format!("{e:?}"))?;
            println!("geometry_closed height={height} main_width={} preprocessing_width={} retained_lde_bytes={}", a.main_width, a.preprocessed_width, a.retained_lde_bytes);
            return Ok(height);
        }
        if required > 1 << 21 {
            return Err("recursive geometry does not close in candidate range".into());
        }
        height = required;
    }
}

pub fn register(
    height: usize,
    mode: u64,
    wallet: Option<&WalletProof>,
) -> Result<Vec<[Val; 4]>, Error> {
    let compiled = compile_registration(height, mode, wallet)?;
    let air = MachineAir::new(
        compiled
            .program
            .pad_to(height)
            .map_err(|e| format!("{e:?}"))?,
    );
    println!(
        "registration_start mode={mode} height={height} active_rows={}",
        air.program().active_rows()
    );
    let registered = RegisteredProgram::new(air).map_err(|e| format!("{e:?}"))?;
    Ok(registered.preprocessing_cap().roots().to_vec())
}

struct CachedProgram {
    mode: u64,
    registered: RegisteredProgram,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub setups: u64,
    pub hits: u64,
}

/// Public-only aggregation with at most ONE immutable preprocessing workspace.
/// No wallet witnesses, proof randomness, or completed-proof results are cached.
/// This remains a research API; it is not a network service or an acceptance ABI.
pub struct ProverSession {
    registry: Registry,
    expected_profile: [u8; 32],
    cached: Option<CachedProgram>,
    stats: CacheStats,
}

impl ProverSession {
    pub fn new(registry: Registry, expected_profile: [u8; 32]) -> Result<Self, Error> {
        if registry.id()? != expected_profile {
            return Err("unapproved prover-session registry".into());
        }
        Ok(Self {
            registry,
            expected_profile,
            cached: None,
            stats: CacheStats::default(),
        })
    }

    pub fn stats(&self) -> CacheStats {
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
        if !(1..=3).contains(&mode)
            || public[programs::MODE] != Val::from_u64(mode)
            || summary(&public)?.context.profile_id != self.expected_profile
        {
            return Err("prover-session statement/profile/mode".into());
        }
        let Compiled { program, witness } = compiled;
        let program = program
            .pad_to(self.registry.height)
            .map_err(|e| format!("{e:?}"))?;
        let started = std::time::Instant::now();
        let hit = self
            .cached
            .as_ref()
            .is_some_and(|cached| cached.mode == mode);
        if hit {
            // Compare the complete immutable program, including witness indexing,
            // hint routing, reference counts, padding and authenticated rows.
            // Equal shape/height alone is NOT enough to reuse preprocessing.
            if self.cached.as_ref().unwrap().registered.air().program() != &program {
                return Err("cached program differs from compiled program".into());
            }
            self.stats.hits += 1;
            drop(program);
        } else {
            // Drop a previous mode BEFORE allocating a new preprocessing LDE.
            self.clear();
            println!(
                "prover_setup_start mode={mode} height={} active_rows={}",
                self.registry.height,
                program.active_rows()
            );
            let registered =
                RegisteredProgram::new(MachineAir::new(program)).map_err(|e| format!("{e:?}"))?;
            if registered.preprocessing_cap().roots() != self.registry.caps[(mode - 1) as usize] {
                return Err("compiled program differs from registered key".into());
            }
            self.cached = Some(CachedProgram { mode, registered });
            self.stats.setups += 1;
        }
        println!(
            "proof_start mode={mode} setup_ms={} preprocessing_cache_hit={hit}",
            started.elapsed().as_millis()
        );
        let started = std::time::Instant::now();
        let registered = &self.cached.as_ref().unwrap().registered;
        // RegisteredProgram::prove constructs fresh salt/hiding RNGs per call.
        let proof = registered
            .prove(&public, &witness)
            .map_err(|e| format!("{e:?}"))?;
        tracing::info_span!(target: "lattica_block_v2_perf", "native verification")
            .in_scope(|| registered.verifier().verify(&proof, &public))?;
        let node = NodeProof { public, proof };
        let bytes = tracing::info_span!(target: "lattica_block_v2_perf", "node serialization")
            .in_scope(|| super::codec::encode_node(&node))?
            .len()
            - super::codec::NODE_MAGIC.len();
        println!(
            "proof_verified mode={mode} prove_and_verify_ms={} node_payload_bytes={bytes}",
            started.elapsed().as_millis()
        );
        Ok(node)
    }

    pub fn wrap(&mut self, wallet: &WalletProof) -> Result<NodeProof, Error> {
        let node = wallet_summary(&self.registry, wallet)?;
        let compiled = tracing::info_span!(target: "lattica_block_v2_perf", "wrapper compilation")
            .in_scope(|| {
                programs::wrapper(
                    self.registry.height,
                    &self.registry.caps,
                    &wallet.public,
                    &wallet.proof,
                )
            })?;
        self.prove(
            programs::WRAPPER,
            compiled,
            programs::statement(node, programs::WRAPPER),
        )
    }

    pub fn empty(&mut self, chain: [u8; 32], level: u8) -> Result<NodeProof, Error> {
        let node = commitment::empty_subtree(
            Context {
                profile_id: self.expected_profile,
                chain_id: chain,
            },
            level,
        )?;
        let compiled = programs::empty(self.registry.height, &self.registry.caps)?;
        self.prove(
            programs::EMPTY,
            compiled,
            programs::statement(node, programs::EMPTY),
        )
    }

    pub fn merge(&mut self, left: &NodeProof, right: &NodeProof) -> Result<NodeProof, Error> {
        tracing::info_span!(target: "lattica_block_v2_perf", "child verification").in_scope(
            || {
                self.registry
                    .verify(self.expected_profile, left, &left.public)?;
                self.registry
                    .verify(self.expected_profile, right, &right.public)
            },
        )?;
        let node = commitment::merge_nodes(summary(&left.public)?, summary(&right.public)?)?;
        let compiled = tracing::info_span!(target: "lattica_block_v2_perf", "merge compilation")
            .in_scope(|| {
                programs::merge(
                    self.registry.height,
                    &self.registry.caps,
                    [&left.public, &right.public],
                    [&left.proof, &right.proof],
                )
            })?;
        self.prove(
            programs::MERGE,
            compiled,
            programs::statement(node, programs::MERGE),
        )
    }
}

pub fn wallet_summary(registry: &Registry, wallet: &WalletProof) -> Result<NodeSummary, Error> {
    if wallet.public.len() != js::N_PUBLIC {
        return Err("wallet public shape".into());
    }
    let fields: Vec<_> = wallet.public.iter().map(|v| v.as_canonical_u64()).collect();
    let entry = Entry {
        kind: Kind::JoinSplit,
        statement_digest: commitment::statement_digest(1, &fields)?,
    };
    Ok(commitment::leaf(
        Context {
            profile_id: registry.id()?,
            chain_id: wallet.chain,
        },
        entry,
    )?)
}

pub fn wrap(registry: &Registry, wallet: &WalletProof) -> Result<NodeProof, Error> {
    // One-shot research helper: its caller already supplies a trusted registry.
    ProverSession::new(registry.clone(), registry.id()?)?.wrap(wallet)
}

pub fn empty(registry: &Registry, chain: [u8; 32], level: u8) -> Result<NodeProof, Error> {
    ProverSession::new(registry.clone(), registry.id()?)?.empty(chain, level)
}

pub fn merge(registry: &Registry, left: &NodeProof, right: &NodeProof) -> Result<NodeProof, Error> {
    ProverSession::new(registry.clone(), registry.id()?)?.merge(left, right)
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn empty_registry() -> Registry {
        let height = 1024;
        let mut caps = blank_caps();
        let compiled = programs::empty(height, &caps).unwrap();
        // Registration and session setup must use the same padded height.
        // The wide layout's natural empty program fits below 1024 rows; the
        // default layout happened to round to 1024 and hid this fixture bug.
        let program = compiled.program.pad_to(height).unwrap();
        assert_eq!(program.height(), height);
        let registered = RegisteredProgram::new(MachineAir::new(program)).unwrap();
        caps[(programs::EMPTY - 1) as usize] = registered.preprocessing_cap().roots().to_vec();
        Registry { height, caps }
    }

    #[test]
    fn session_reuses_only_preprocessing_with_fresh_hiding_and_explicit_eviction() {
        let registry = empty_registry();
        let pin = registry.id().unwrap();
        let mut session = ProverSession::new(registry.clone(), pin).unwrap();
        let first = session.empty(DEMO_CHAIN, 0).unwrap();
        let second = session.empty(DEMO_CHAIN, 0).unwrap();
        assert_eq!(session.stats(), CacheStats { setups: 1, hits: 1 });
        registry.verify(pin, &first, &first.public).unwrap();
        registry.verify(pin, &second, &second.public).unwrap();
        assert_ne!(
            postcard::to_allocvec(&first).unwrap(),
            postcard::to_allocvec(&second).unwrap()
        );
        // Same geometry is not sufficient. A different instruction/witness map
        // must fail BEFORE doing expensive setup or using the cached key.
        let wrong = Compiled {
            program: super::super::machine::ProgramBuilder::new(PUBLIC_VALUES)
                .unwrap()
                .finish(Some(registry.height))
                .unwrap(),
            witness: Vec::new(),
        };
        assert!(session.prove(programs::EMPTY, wrong, first.public).is_err());
        assert_eq!(session.stats(), CacheStats { setups: 1, hits: 1 });
        session.clear();
        assert!(session.cached.is_none());
        let third = session.empty(DEMO_CHAIN, 1).unwrap();
        assert_eq!(session.stats(), CacheStats { setups: 2, hits: 1 });
        drop(session);
        registry.verify(pin, &third, &third.public).unwrap();
    }

    #[test]
    fn session_rejects_unapproved_registry_and_key_substitution() {
        let registry = empty_registry();
        let pin = registry.id().unwrap();
        let mut wrong_pin = pin;
        wrong_pin[0] ^= 1;
        assert!(ProverSession::new(registry.clone(), wrong_pin).is_err());
        let mut wrong = registry;
        wrong.caps[1][0][0] += Val::ONE;
        assert!(ProverSession::new(wrong.clone(), pin).is_err());
        // Even an explicitly supplied pin cannot make an unrelated compiled
        // preprocessing cap usable. The first setup must match the registry.
        let bad_pin = wrong.id().unwrap();
        let mut session = ProverSession::new(wrong, bad_pin).unwrap();
        assert!(session.empty(DEMO_CHAIN, 0).is_err());
        assert!(session.cached.is_none());
        assert_eq!(session.stats(), CacheStats::default());
    }

    #[test]
    fn switching_modes_evicts_the_previous_workspace_before_a_failed_setup() {
        let registry = empty_registry();
        let pin = registry.id().unwrap();
        let mut session = ProverSession::new(registry.clone(), pin).unwrap();
        let empty = session.empty(DEMO_CHAIN, 0).unwrap();
        assert!(session.cached.is_some());

        // The tiny fixture has no registered wrapper key. Requesting that mode
        // must drop the empty workspace, then reject the recomputed key.
        let compiled = programs::empty(registry.height, &registry.caps).unwrap();
        let mut public = empty.public;
        public[programs::MODE] = Val::from_u64(programs::WRAPPER);
        assert!(session.prove(programs::WRAPPER, compiled, public).is_err());
        assert!(session.cached.is_none());
        assert_eq!(session.stats(), CacheStats { setups: 1, hits: 0 });
        registry.verify(pin, &empty, &empty.public).unwrap();
    }
}

/// Local demo only: four distinct spends under one shared anchor. Private witness
/// construction lives here in the wallet fixture, never in wrap/merge APIs.
pub fn demo_wallet(index: usize) -> Result<WalletProof, Error> {
    if index >= 4 {
        return Err("demo wallet index".into());
    }
    let mut wallets: Vec<_> = (0..4)
        .map(|i| {
            let mut w = js::demo_witness();
            for input in &mut w.inputs {
                input.nk[0] += i as u64 * 1000;
                input.rho[0] += Val::from_usize(i * 1000);
                input.rcm[1] += Val::from_usize(i * 1000);
            }
            for output in &mut w.outputs {
                output.rho[0] += Val::from_usize(i * 1000);
            }
            w.tx_binding[0] += Val::from_usize(i);
            w
        })
        .collect();
    let commitments: Vec<_> = wallets
        .iter()
        .flat_map(|w| w.inputs.iter())
        .map(|input| {
            js::commit(
                js::recipient_of(
                    Val::from_u64(input.nk[0]),
                    Val::from_u64(input.nk[1]),
                    input.div,
                ),
                Val::from_u64(input.value),
                input.rho,
                input.rcm,
                input.asset,
            )
        })
        .collect();
    let (_, paths) = js::build_paths(&commitments);
    for (i, input) in wallets
        .iter_mut()
        .flat_map(|w| w.inputs.iter_mut())
        .enumerate()
    {
        input.sib = paths[i].0;
        input.bits = paths[i].1;
    }
    let wallet = &wallets[index];
    let public = js::public_values(wallet);
    let mut inner = public.clone();
    inner.extend(
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: DEMO_CHAIN,
        }
        .to_fields()
        .map(Val::from_u64),
    );
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(
        &config,
        &ContextJoinSplitAir,
        js::build_trace(wallet),
        &inner,
    );
    p3_uni_stark::verify(&config, &ContextJoinSplitAir, &proof, &inner)
        .map_err(|e| format!("{e:?}"))?;
    Ok(WalletProof {
        chain: DEMO_CHAIN,
        public,
        proof,
    })
}

// ---- OPT-IN GROUPED-PAIR RESEARCH INTERFACES ----
// Existing single-wallet entrypoints retain their behavior. These additive
// interfaces select programs::wrapper_pair explicitly; they do not authorize a
// registry or activate a profile. Qualification evidence lives in docs/evidence.

/// Explicit local program-construction choice, NOT a verifier/profile identity.
///
/// The existing free functions and ProverSession retain single-wallet behavior.
/// New callers retain this choice across geometry, compilation, registration and
/// session creation. Only the registered caps plus the independently supplied
/// expected profile bind the actual verifier program; this enum grants no trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapperConstruction {
    SingleWallet,
    GroupedPair,
}

impl WrapperConstruction {
    /// Compile a registration template for the selected construction.
    ///
    /// Repeating one completed public wallet proof supplies both pair-template
    /// slots. This does not mean that a count-two transaction is being proved,
    /// and does not admit a wallet witness or bypass either wallet verifier.
    /// Actual pair proving must produce exactly this immutable program.
    pub fn compile_registration(
        self,
        height: usize,
        mode: u64,
        wallet: Option<&WalletProof>,
    ) -> Result<Compiled, Error> {
        match (self, mode) {
            (Self::GroupedPair, programs::WRAPPER) => {
                let wallet = wallet.ok_or("paired wrapper template requires wallet proof")?;
                Ok(programs::wrapper_pair(
                    height,
                    &blank_caps(),
                    [&wallet.public, &wallet.public],
                    [&wallet.proof, &wallet.proof],
                )?)
            }
            // EMPTY, MERGE, unknown-mode rejection, and every SingleWallet
            // request retain the exact legacy compiler implementation.
            _ => compile_registration(height, mode, wallet),
        }
    }

    /// Structural common-height search for this explicit construction.
    ///
    /// This remains a compiler/RAM-lower-bound gate, not measured recursive
    /// closure, resource qualification, key approval or a full-tree security
    /// bound. The pair program must not inherit a measured legacy height by fiat.
    pub fn common_height(self, wallet: &WalletProof) -> Result<usize, Error> {
        if self == Self::SingleWallet {
            return common_height(wallet);
        }
        let mut height = 1 << 18;
        loop {
            let mut required = height;
            for mode in [programs::WRAPPER, programs::EMPTY, programs::MERGE] {
                let compiled = self.compile_registration(height, mode, Some(wallet))?;
                required = required.max(compiled.program.height());
                println!(
                    "grouped_geometry construction={self:?} mode={mode} child_height={height} active_rows={} required_height={}",
                    compiled.program.active_rows(),
                    compiled.program.height()
                );
            }
            if required == height {
                let a =
                    analysis::analyze(&programs::shape(height)?).map_err(|e| format!("{e:?}"))?;
                a.check_ram_lower_bound().map_err(|e| format!("{e:?}"))?;
                println!(
                    "grouped_structural_geometry_closed construction={self:?} height={height} main_width={} preprocessing_width={} retained_lde_bytes={} recursive_proof_produced=false",
                    a.main_width, a.preprocessed_width, a.retained_lde_bytes
                );
                return Ok(height);
            }
            if required > 1 << 21 {
                return Err("grouped recursive geometry does not close in candidate range".into());
            }
            height = required;
        }
    }

    /// Generate a preprocessing cap for the selected construction.
    ///
    /// This operation is key generation, NOT approval. The complete registry and
    /// its profile pin still require independent review/authorization outside
    /// these research APIs. This operation allocates preprocessing.
    pub fn register(
        self,
        height: usize,
        mode: u64,
        wallet: Option<&WalletProof>,
    ) -> Result<Vec<[Val; 4]>, Error> {
        if self == Self::SingleWallet {
            return register(height, mode, wallet);
        }
        let compiled = self.compile_registration(height, mode, wallet)?;
        let air = MachineAir::new(
            compiled
                .program
                .pad_to(height)
                .map_err(|e| format!("{e:?}"))?,
        );
        println!(
            "grouped_registration_start construction={self:?} mode={mode} height={height} active_rows={}",
            air.program().active_rows()
        );
        let registered = RegisteredProgram::new(air).map_err(|e| format!("{e:?}"))?;
        Ok(registered.preprocessing_cap().roots().to_vec())
    }

    /// Enter an explicitly selected session under a caller-supplied trust pin.
    ///
    /// There is deliberately no convenience overload using registry.id() as
    /// an automatically trusted expected profile.
    pub fn session(
        self,
        registry: Registry,
        expected_profile: [u8; 32],
    ) -> Result<ConstructionSession, Error> {
        ConstructionSession::new(self, registry, expected_profile)
    }
}

/// Native public-statement derivation only; NOT proof verification or approval.
///
/// Both summaries are ordinary level-zero, count-one leaves under this registry.
/// merge_nodes enforces matching chain/profile context and ordering and derives
/// level one/count two without caller-supplied root, level or count. This helper
/// does not impose new host anchor/nullifier policy or validate ledger state.
pub fn wallet_pair_summary(
    registry: &Registry,
    left: &WalletProof,
    right: &WalletProof,
) -> Result<NodeSummary, Error> {
    Ok(commitment::merge_nodes(
        wallet_summary(registry, left)?,
        wallet_summary(registry, right)?,
    )?)
}

/// Opt-in facade over the unchanged, one-workspace ProverSession.
///
/// Construction metadata selects the requested compiler only. It is not
/// serialized as an identity and cannot approve a key. ProverSession::prove
/// still checks the actual compiled program against the registered cap, the
/// immutable cached program, and the externally supplied profile pin.
pub struct ConstructionSession {
    construction: WrapperConstruction,
    session: ProverSession,
}

impl ConstructionSession {
    pub fn new(
        construction: WrapperConstruction,
        registry: Registry,
        expected_profile: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            construction,
            session: ProverSession::new(registry, expected_profile)?,
        })
    }

    pub fn construction(&self) -> WrapperConstruction {
        self.construction
    }

    pub fn stats(&self) -> CacheStats {
        self.session.stats()
    }

    pub fn clear(&mut self) {
        self.session.clear();
    }

    fn require_wrapper(&self, requested: WrapperConstruction) -> Result<(), Error> {
        if self.construction != requested {
            return Err("wrapper entrypoint differs from explicit construction selection".into());
        }
        Ok(())
    }

    /// The selected single-wallet route delegates to the unchanged legacy API.
    pub fn wrap(&mut self, wallet: &WalletProof) -> Result<NodeProof, Error> {
        self.require_wrapper(WrapperConstruction::SingleWallet)?;
        self.session.wrap(wallet)
    }

    /// Prove exactly two ordered completed public wallet proofs as one wrapper.
    ///
    /// No count-one option, witness-batch fallback or caller-chosen statement is
    /// exposed. The pair program always executes both full wallet verifiers. Only
    /// public statements/proofs enter this API; private wallet witnesses remain
    /// local to wallets. Actual compiled-cap matching occurs inside prove.
    pub fn wrap_pair(
        &mut self,
        left: &WalletProof,
        right: &WalletProof,
    ) -> Result<NodeProof, Error> {
        self.require_wrapper(WrapperConstruction::GroupedPair)?;
        let node = wallet_pair_summary(&self.session.registry, left, right)?;
        if node.level != 1 || node.count != 2 {
            return Err("paired wrapper statement derivation".into());
        }
        verify_wallet(left)?;
        verify_wallet(right)?;
        let compiled = tracing::info_span!(
            target: "lattica_block_v2_perf",
            "paired wrapper compilation"
        )
        .in_scope(|| {
            programs::wrapper_pair(
                self.session.registry.height,
                &self.session.registry.caps,
                [&left.public, &right.public],
                [&left.proof, &right.proof],
            )
        })?;
        self.session.prove(
            programs::WRAPPER,
            compiled,
            programs::statement(node, programs::WRAPPER),
        )
    }

    pub fn empty(&mut self, chain: [u8; 32], level: u8) -> Result<NodeProof, Error> {
        self.session.empty(chain, level)
    }

    pub fn merge(&mut self, left: &NodeProof, right: &NodeProof) -> Result<NodeProof, Error> {
        self.session.merge(left, right)
    }
}

/// Separate eight-wallet fixture size. Does not change demo_wallet's 0..4 range.
pub const EIGHT_WALLET_DEMO_SIZE: usize = 8;

/// Wallet-local fixture construction, never called by an aggregation API.
///
/// Build all sixteen input commitments into the same tree before assigning
/// paths. This deliberately changes the demo anchor relative to the legacy
/// four-wallet fixture; do not mix the fixture families in one expected block.
fn demo_witnesses_eight() -> Vec<js::Witness> {
    let mut wallets: Vec<_> = (0..EIGHT_WALLET_DEMO_SIZE)
        .map(|i| {
            let mut w = js::demo_witness();
            for input in &mut w.inputs {
                input.nk[0] += i as u64 * 1000;
                input.rho[0] += Val::from_usize(i * 1000);
                input.rcm[1] += Val::from_usize(i * 1000);
            }
            for output in &mut w.outputs {
                output.rho[0] += Val::from_usize(i * 1000);
            }
            w.tx_binding[0] += Val::from_usize(i);
            w
        })
        .collect();
    let commitments: Vec<_> = wallets
        .iter()
        .flat_map(|w| w.inputs.iter())
        .map(|input| {
            js::commit(
                js::recipient_of(
                    Val::from_u64(input.nk[0]),
                    Val::from_u64(input.nk[1]),
                    input.div,
                ),
                Val::from_u64(input.value),
                input.rho,
                input.rcm,
                input.asset,
            )
        })
        .collect();
    let (_, paths) = js::build_paths(&commitments);
    for (i, input) in wallets
        .iter_mut()
        .flat_map(|w| w.inputs.iter_mut())
        .enumerate()
    {
        input.sib = paths[i].0;
        input.bits = paths[i].1;
    }
    wallets
}

/// Local wallet fixture only: one of eight distinct spends under a common anchor.
///
/// Range is exactly 0..8, checked before witness construction or proving. This
/// returns only the public wallet artifact; its private fixture witness does not
/// cross into registration/session/aggregation.
pub fn demo_wallet_eight(index: usize) -> Result<WalletProof, Error> {
    if index >= EIGHT_WALLET_DEMO_SIZE {
        return Err("eight-wallet demo index".into());
    }
    let wallets = demo_witnesses_eight();
    let wallet = &wallets[index];
    let public = js::public_values(wallet);
    let mut inner = public.clone();
    inner.extend(
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: DEMO_CHAIN,
        }
        .to_fields()
        .map(Val::from_u64),
    );
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(
        &config,
        &ContextJoinSplitAir,
        js::build_trace(wallet),
        &inner,
    );
    p3_uni_stark::verify(&config, &ContextJoinSplitAir, &proof, &inner)
        .map_err(|e| format!("{e:?}"))?;
    Ok(WalletProof {
        chain: DEMO_CHAIN,
        public,
        proof,
    })
}

#[cfg(test)]
mod grouped_integration_draft_tests {
    use super::*;

    // These are test-only synthetic caps, not generated or approved verifier
    // keys. Self-derived pins in these tests exercise identity binding only.
    fn synthetic_registry() -> Registry {
        Registry {
            height: 1 << 19,
            caps: blank_caps(),
        }
    }

    #[test]
    fn explicit_construction_rejects_missing_templates_and_unknown_modes() {
        for choice in [
            WrapperConstruction::SingleWallet,
            WrapperConstruction::GroupedPair,
        ] {
            assert!(choice
                .compile_registration(1 << 19, programs::WRAPPER, None)
                .is_err());
            assert!(choice.compile_registration(1 << 19, 0, None).is_err());
            assert!(choice.compile_registration(1 << 19, 4, None).is_err());
        }
        assert!(compile_registration(1 << 19, programs::WRAPPER, None).is_err());
    }

    #[test]
    fn construction_session_rejects_wrong_pin_and_each_substituted_registry_key() {
        let registry = synthetic_registry();
        let test_pin = registry.id().unwrap();
        for choice in [
            WrapperConstruction::SingleWallet,
            WrapperConstruction::GroupedPair,
        ] {
            let session = choice.session(registry.clone(), test_pin).unwrap();
            assert_eq!(session.construction(), choice);
            assert_eq!(session.stats(), CacheStats::default());
            session.require_wrapper(choice).unwrap();
            let other = match choice {
                WrapperConstruction::SingleWallet => WrapperConstruction::GroupedPair,
                WrapperConstruction::GroupedPair => WrapperConstruction::SingleWallet,
            };
            assert!(session.require_wrapper(other).is_err());

            let mut wrong_pin = test_pin;
            wrong_pin[0] ^= 1;
            assert!(choice.session(registry.clone(), wrong_pin).is_err());
            for mode in 0..3 {
                let mut changed = registry.clone();
                changed.caps[mode][0][0] += Val::ONE;
                assert_ne!(changed.id().unwrap(), test_pin);
                assert!(choice.session(changed, test_pin).is_err());
            }
            let mut changed_height = registry.clone();
            changed_height.height *= 2;
            assert!(choice.session(changed_height, test_pin).is_err());
        }
        // This does NOT show that caps belong to the requested construction.
        // Actual preprocessing-cap comparison remains inside ProverSession::prove.
    }

    #[test]
    fn separate_fixture_index_limits_do_not_expand_legacy_acceptance() {
        assert!(demo_wallet(4).is_err());
        assert!(demo_wallet(usize::MAX).is_err());
        assert!(demo_wallet_eight(8).is_err());
        assert!(demo_wallet_eight(usize::MAX).is_err());
    }

    #[test]
    fn eight_wallet_fixture_has_common_anchor_zero_mint_and_distinct_nullifiers() {
        let wallets = demo_witnesses_eight();
        assert_eq!(wallets.len(), EIGHT_WALLET_DEMO_SIZE);
        let first = js::public_values(&wallets[0]);
        let mut nullifiers = std::collections::BTreeSet::new();
        let mut bindings = std::collections::BTreeSet::new();
        for wallet in &wallets {
            // Native derivation also asserts input membership and value balance.
            let public = js::public_values(wallet);
            assert_eq!(
                &public[js::PI_ANCHOR..js::PI_NF],
                &first[js::PI_ANCHOR..js::PI_NF]
            );
            assert_eq!(public[js::PI_MINT], Val::ZERO);
            for nf in public[js::PI_NF..js::PI_OUTCM].chunks_exact(4) {
                assert!(nullifiers.insert(
                    nf.iter()
                        .map(|value| value.as_canonical_u64())
                        .collect::<Vec<_>>()
                ));
            }
            assert!(bindings.insert(
                public[js::PI_TXBIND..]
                    .iter()
                    .map(|value| value.as_canonical_u64())
                    .collect::<Vec<_>>()
            ));
        }
        assert_eq!(
            nullifiers.len(),
            wallets
                .iter()
                .map(|wallet| wallet.inputs.len())
                .sum::<usize>()
        );
        assert_eq!(bindings.len(), EIGHT_WALLET_DEMO_SIZE);
    }

    #[test]
    #[ignore = "two wallet proofs and large program compilers; run explicitly in a bounded service"]
    fn construction_identity_and_pair_program_are_independent_of_source_values() {
        let wallets = [demo_wallet_eight(0).unwrap(), demo_wallet_eight(1).unwrap()];
        let registry = synthetic_registry();
        let height = registry.height; // Comparison geometry only, NOT closure.
        let single = compile_registration(height, programs::WRAPPER, Some(&wallets[0])).unwrap();
        {
            let explicit_single = WrapperConstruction::SingleWallet
                .compile_registration(height, programs::WRAPPER, Some(&wallets[0]))
                .unwrap();
            assert!(single.program == explicit_single.program);
        }
        let pair = WrapperConstruction::GroupedPair
            .compile_registration(height, programs::WRAPPER, Some(&wallets[0]))
            .unwrap();
        assert!(single.program != pair.program);
        drop(single);
        {
            let another_template = WrapperConstruction::GroupedPair
                .compile_registration(height, programs::WRAPPER, Some(&wallets[1]))
                .unwrap();
            assert!(pair.program == another_template.program);
        }
        for order in [[0, 1], [1, 0], [1, 1]] {
            let actual = programs::wrapper_pair(
                height,
                &registry.caps,
                [&wallets[order[0]].public, &wallets[order[1]].public],
                [&wallets[order[0]].proof, &wallets[order[1]].proof],
            )
            .unwrap();
            assert!(pair.program == actual.program);
        }
        let mut changed_caps = registry.caps;
        changed_caps[0][0][0] += Val::ONE;
        let changed_key_inputs = programs::wrapper_pair(
            height,
            &changed_caps,
            [&wallets[0].public, &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof],
        )
        .unwrap();
        assert!(pair.program == changed_key_inputs.program);
        // Caps/proofs/statements are inputs, not a way to select another program.
        // Distinct actual registration caps still need generation and review.
    }

    #[test]
    #[ignore = "full merge template compilation; run explicitly in a bounded service"]
    fn construction_selection_preserves_empty_and_merge_programs() {
        let height = 1 << 19;
        for mode in [programs::EMPTY, programs::MERGE] {
            let legacy = compile_registration(height, mode, None).unwrap();
            for choice in [
                WrapperConstruction::SingleWallet,
                WrapperConstruction::GroupedPair,
            ] {
                let selected = choice.compile_registration(height, mode, None).unwrap();
                assert!(legacy.program == selected.program);
            }
        }
    }

    #[test]
    #[ignore = "wallet proof plus fixed-point compilation; run explicitly in a bounded service"]
    fn grouped_common_height_uses_the_selected_program_for_every_mode() {
        let wallet = demo_wallet_eight(0).unwrap();
        let choice = WrapperConstruction::GroupedPair;
        let height = choice.common_height(&wallet).unwrap();
        assert!(height.is_power_of_two());
        assert!(((1usize << 18)..=(1usize << 21)).contains(&height));
        for mode in [programs::WRAPPER, programs::EMPTY, programs::MERGE] {
            let compiled = choice
                .compile_registration(height, mode, Some(&wallet))
                .unwrap();
            assert!(compiled.program.height() <= height);
            compiled.program.pad_to(height).unwrap();
        }
        // No preprocessing/key generation or actual recursive proof here.
    }

    #[test]
    #[ignore = "wallet proofs and full pair interpreters; run explicitly in a bounded service"]
    fn derived_pair_statement_binds_order_and_context_without_proving_a_node() {
        let mut wallets = [demo_wallet_eight(0).unwrap(), demo_wallet_eight(1).unwrap()];
        let registry = synthetic_registry();
        let test_pin = registry.id().unwrap();
        let node = wallet_pair_summary(&registry, &wallets[0], &wallets[1]).unwrap();
        assert_eq!((node.level, node.count), (1, 2));
        let public = programs::statement(node, programs::WRAPPER);
        let compiled = programs::wrapper_pair(
            registry.height,
            &registry.caps,
            [&wallets[0].public, &wallets[1].public],
            [&wallets[0].proof, &wallets[1].proof],
        )
        .unwrap();
        compiled
            .program
            .evaluate(&public, &compiled.witness)
            .unwrap();

        let reversed_node = wallet_pair_summary(&registry, &wallets[1], &wallets[0]).unwrap();
        assert_ne!(node.root, reversed_node.root);
        let reversed_public = programs::statement(reversed_node, programs::WRAPPER);
        assert!(compiled
            .program
            .evaluate(&reversed_public, &compiled.witness)
            .is_err());
        {
            let reversed = programs::wrapper_pair(
                registry.height,
                &registry.caps,
                [&wallets[1].public, &wallets[0].public],
                [&wallets[1].proof, &wallets[0].proof],
            )
            .unwrap();
            assert!(compiled.program == reversed.program);
            reversed
                .program
                .evaluate(&reversed_public, &reversed.witness)
                .unwrap();
        }

        wallets[1].chain[0] ^= 1;
        assert!(wallet_pair_summary(&registry, &wallets[0], &wallets[1]).is_err());
        assert!(verify_wallet(&wallets[1]).is_err());
        wallets[0].chain[0] ^= 1;
        // Both public leaves and their parent now use the changed chain, so a
        // stale root cannot explain rejection of these unchanged wallet proofs.
        let changed_context = programs::statement(
            wallet_pair_summary(&registry, &wallets[0], &wallets[1]).unwrap(),
            programs::WRAPPER,
        );
        assert!(compiled
            .program
            .evaluate(&changed_context, &compiled.witness)
            .is_err());
        wallets[0].chain[0] ^= 1;
        wallets[1].chain[0] ^= 1;

        let mut grouped = WrapperConstruction::GroupedPair
            .session(registry.clone(), test_pin)
            .unwrap();
        assert!(grouped.wrap(&wallets[0]).is_err());
        assert_eq!(grouped.stats(), CacheStats::default());
        let mut single = WrapperConstruction::SingleWallet
            .session(registry, test_pin)
            .unwrap();
        assert!(single.wrap_pair(&wallets[0], &wallets[1]).is_err());
        assert_eq!(single.stats(), CacheStats::default());
        // The wrong-entrypoint calls fail before any recursive setup/proving.
        // No session.wrap_pair success, generated key, or recursive proof is
        // exercised by this interpreter-only draft.
    }
}
