//! Fixed wallet AIRs with fresh randomness and complete request receipts.
//! Public preparation is reusable; private inputs and random streams are not.
use super::{NativeWalletTrace, Wallets};
use crate::{
    config::{Challenge, Val},
    cuda_compute::{
        NativeStarkProof, PreparedStark, Randoms, Result, Runtime, Specialization, StarkField,
        StarkRandomness, Starks,
    },
    proving::{Backend, Capabilities, Profile, Report, Request, Run, Stage},
};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
mod batch;
pub(crate) use batch::BatchProver;

pub(crate) struct WalletProver {
    runtime: Runtime,
    wallets: Wallets,
    starks: Starks,
    randoms: Arc<Randoms>,
}

/// The private prepared AIR cannot be replaced with an arbitrary circuit.
pub(crate) struct JoinSplitProver {
    engine: Arc<WalletProver>,
    prepared: PreparedStark<Challenge>,
}

pub(crate) struct HtlcProver {
    engine: Arc<WalletProver>,
    prepared: PreparedStark<Challenge>,
}

pub(crate) struct WalletProof<F: StarkField = Challenge> {
    pub(crate) proof: NativeStarkProof<F>,
    pub(crate) public_values: Vec<Val>,
    pub(crate) report: Report,
}

impl WalletProver {
    pub(crate) fn joinsplit_tree_root(
        &self,
        statements: &[u64],
        count: usize,
        host_bytes: usize,
        run: &Run,
    ) -> Result<[u64; 4]> {
        self.runtime.reported(run, || {
            self.wallets.joinsplit_tree_root(statements, count, host_bytes, run)
        })
    }
    pub(crate) fn new(runtime: &Runtime) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            runtime: runtime.clone(),
            wallets: Wallets::new(runtime)?,
            starks: Starks::new(runtime)?,
            randoms: Randoms::new(runtime)?,
        }))
    }

    pub(crate) fn prepare_joinsplit(
        self: &Arc<Self>,
        host_bytes: usize,
    ) -> Result<JoinSplitProver> {
        Ok(JoinSplitProver {
            engine: self.clone(),
            prepared: self.starks.prepare(
                &crate::joinsplit_air::JoinSplitAir,
                crate::joinsplit_air::HEIGHT.ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        })
    }

    pub(crate) fn prepare_htlc(self: &Arc<Self>, host_bytes: usize) -> Result<HtlcProver> {
        Ok(HtlcProver {
            engine: self.clone(),
            prepared: self.starks.prepare(
                &crate::htlc_air::HtlcAir,
                crate::htlc_air::HEIGHT.ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        })
    }

    fn prove<F: StarkField>(
        &self,
        prepared: &PreparedStark<F>,
        entry_point: &'static str,
        request: Request,
        host_bytes: usize,
        profile: Profile,
        context: Option<&crate::block_v2::commitment::Context>,
        generate: impl FnOnce(&Run) -> Result<NativeWalletTrace>,
    ) -> Result<WalletProof<F>> {
        let run =
            Run::new(entry_point, request, capabilities(profile)).map_err(super::super::error)?;
        let result = self.runtime.reported(&run, || {
            let frame = generate(&run)?;
            // Context is an injective public byte encoding. Keep wallet-derived
            // public values resident; no CPU witness oracle is involved.
            let contextual_public = context
                .map(|context| {
                    let fields = context.to_fields();
                    let public = self.runtime.allocate(frame.public.len() + fields.len())?;
                    public.copy_from(0, &frame.public, 0, frame.public.len())?;
                    public.write(frame.public.len(), &fields)?;
                    Ok::<_, String>(public)
                })
                .transpose()?;
            let public = contextual_public.as_ref().unwrap_or(&frame.public);
            // Account both the wire words and typed public statement during
            // conversion. This is bounded proof egress, not CPU reconstruction.
            let statement_bytes = frame
                .public
                .len()
                .checked_mul(16)
                .ok_or("CUDA wallet statement size overflow")?;
            let proof_host_bytes = host_bytes
                .checked_sub(statement_bytes)
                .ok_or("CUDA wallet statement exceeds host allowance")?;
            let masks = self
                .randoms
                .import(ChaCha20Rng::from_rng(&mut rand::rng()))?;
            let commitments = self
                .randoms
                .import(ChaCha20Rng::from_rng(&mut rand::rng()))?;
            let fri = self
                .randoms
                .import(ChaCha20Rng::from_rng(&mut rand::rng()))?;
            let proof = self.starks.prove(
                prepared,
                &frame.trace,
                Some(public),
                StarkRandomness {
                    masks: &masks,
                    commitments: &commitments,
                    fri: &fri,
                },
                proof_host_bytes,
            )?;
            let mut words = Vec::new();
            words
                .try_reserve_exact(frame.public.len())
                .map_err(super::super::error)?;
            words.resize(frame.public.len(), 0);
            frame.public.read(0, &mut words)?;
            let mut public_values = Vec::new();
            public_values
                .try_reserve_exact(words.len())
                .map_err(super::super::error)?;
            public_values.extend(words.into_iter().map(Val::from_u64));
            Ok((proof, public_values))
        });
        match result {
            Ok((proof, public_values)) => {
                let report = run.finish(true).map_err(super::super::error)?;
                Ok(WalletProof {
                    proof,
                    public_values,
                    report,
                })
            }
            Err(error) => {
                let _ = run.finish(false);
                Err(error)
            }
        }
    }
}

impl JoinSplitProver {
    pub(crate) fn prove(
        &self,
        witness: &crate::joinsplit_air::Witness,
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof> {
        self.engine.prove(
            &self.prepared,
            "cuda_joinsplit",
            request,
            host_bytes,
            Profile::LegacyQuadratic,
            None,
            |run| self.engine.wallets.joinsplit(witness, host_bytes, run),
        )
    }
}

impl HtlcProver {
    pub(crate) fn prove(
        &self,
        witness: &crate::htlc_air::Witness,
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof> {
        self.engine.prove(
            &self.prepared,
            "cuda_htlc",
            request,
            host_bytes,
            Profile::LegacyQuadratic,
            None,
            |run| self.engine.wallets.htlc(witness, host_bytes, run),
        )
    }
}

/// Fixed periodic columns are prepared once. These single-AIR protocols have
/// neither a preprocessed trace nor a lookup argument in their proof inventory.
pub(crate) fn capabilities(profile: Profile) -> Capabilities {
    let mut capabilities = Capabilities::cpu(profile, false, false);
    for stage in Stage::ARITHMETIC {
        if !matches!(stage, Stage::Preprocessing | Stage::Lookup) {
            capabilities.set(stage, Backend::Cuda);
        }
    }
    capabilities
}

use crate::block_v2::{
    commitment::Context, leaf::ContextJoinSplitAir, profile, typed_leaf::ContextAir,
};

pub(crate) struct ContextJoinSplitProver {
    engine: Arc<WalletProver>,
    prepared: PreparedStark<profile::Challenge>,
}
pub(crate) struct ContextHtlcProver {
    engine: Arc<WalletProver>,
    prepared: PreparedStark<profile::Challenge>,
}
pub(crate) struct IssuanceProver {
    engine: Arc<WalletProver>,
    prepared: PreparedStark<profile::Challenge>,
}

impl WalletProver {
    pub(crate) fn prepare_context_joinsplit(
        self: &Arc<Self>,
        host_bytes: usize,
    ) -> Result<ContextJoinSplitProver> {
        Ok(ContextJoinSplitProver {
            engine: self.clone(),
            prepared: self.starks.prepare(
                &ContextJoinSplitAir,
                crate::joinsplit_air::HEIGHT.ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        })
    }
    pub(crate) fn prepare_context_htlc(
        self: &Arc<Self>,
        host_bytes: usize,
    ) -> Result<ContextHtlcProver> {
        Ok(ContextHtlcProver {
            engine: self.clone(),
            prepared: self.starks.prepare(
                &ContextAir(crate::htlc_air::HtlcAir),
                crate::htlc_air::HEIGHT.ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        })
    }
    pub(crate) fn prepare_issuance(self: &Arc<Self>, host_bytes: usize) -> Result<IssuanceProver> {
        Ok(IssuanceProver {
            engine: self.clone(),
            // Issuance must NOT use ContextJoinSplitAir's mint=0 constraint.
            prepared: self.starks.prepare(
                &ContextAir(crate::joinsplit_air::JoinSplitAir),
                crate::joinsplit_air::HEIGHT.ilog2(),
                host_bytes,
                Specialization::Prefer,
            )?,
        })
    }
}

fn check_context(context: &Context) -> Result<()> {
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err("CUDA wallet context profile mismatch".into());
    }
    Ok(())
}

impl ContextJoinSplitProver {
    pub(crate) fn prove(
        &self,
        witness: &crate::joinsplit_air::Witness,
        context: &Context,
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof<profile::Challenge>> {
        check_context(context)?;
        if witness.mint != 0 {
            return Err("CUDA JoinSplit cannot authorize issuance".into());
        }
        self.engine.prove(
            &self.prepared,
            "cuda_context_joinsplit",
            request,
            host_bytes,
            Profile::BlockV2Cubic,
            Some(context),
            |run| self.engine.wallets.joinsplit(witness, host_bytes, run),
        )
    }
}
impl ContextHtlcProver {
    pub(crate) fn prove(
        &self,
        witness: &crate::htlc_air::Witness,
        context: &Context,
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof<profile::Challenge>> {
        check_context(context)?;
        if witness.mint != 0 {
            return Err("CUDA HTLC cannot authorize issuance".into());
        }
        self.engine.prove(
            &self.prepared,
            "cuda_context_htlc",
            request,
            host_bytes,
            Profile::BlockV2Cubic,
            Some(context),
            |run| self.engine.wallets.htlc(witness, host_bytes, run),
        )
    }
}
impl IssuanceProver {
    pub(crate) fn prove(
        &self,
        witness: &crate::joinsplit_air::Witness,
        context: &Context,
        authorized_mint: u64,
        request: Request,
        host_bytes: usize,
    ) -> Result<WalletProof<profile::Challenge>> {
        check_context(context)?;
        if authorized_mint == 0
            || authorized_mint >= 1u64 << crate::joinsplit_air::BITS
            || witness.mint != authorized_mint
        {
            return Err("CUDA wallet unauthorized issuance".into());
        }
        self.engine.prove(
            &self.prepared,
            "cuda_context_issuance",
            request,
            host_bytes,
            Profile::BlockV2Cubic,
            Some(context),
            |run| self.engine.wallets.joinsplit(witness, host_bytes, run),
        )
    }
}
