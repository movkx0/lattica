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
pub struct Registry {
    pub height: usize,
    pub caps: Caps,
}

impl Registry {
    pub fn id(&self) -> Result<[u8; 32], Error> {
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
        let summary = recursive::summary_with_modes(expected, 5)?;
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
    let mut height = 1 << 18;
    loop {
        let mut required = height;
        for mode in 1..=5 {
            let wallet = match mode {
                programs::WRAPPER => Some(wallets[0]),
                HTLC => Some(wallets[1]),
                ISSUANCE => Some(wallets[2]),
                _ => None,
            };
            let compiled = compile_registration(height, mode, wallet)?;
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
pub struct Session {
    registry: Registry,
    expected_profile: [u8; 32],
    worker_memory_bytes: u64,
    cached: Option<(u64, RegisteredProgram)>,
}

impl Session {
    pub fn new(
        registry: Registry,
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
        })
    }

    fn prove(
        &mut self,
        mode: u64,
        compiled: Compiled,
        public: [Val; PUBLIC_VALUES],
    ) -> Result<NodeProof, Error> {
        if public[programs::MODE] != Val::from_u64(mode)
            || recursive::summary_with_modes(&public, 5)?
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
            recursive::summary_with_modes(&left.public, 5)?,
            recursive::summary_with_modes(&right.public, 5)?,
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
