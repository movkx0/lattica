//! Fixed wallet AIRs with fresh randomness and complete request receipts.
//! Public preparation is reusable; private inputs and random streams are not.
use super::{NativeWalletTrace, Wallets};
use crate::{
    config::{Challenge, Val},
    cuda_compute::{
        NativeStarkProof, PreparedStark, Randoms, Result, Runtime, Specialization, StarkRandomness,
        Starks,
    },
    proving::{Backend, Capabilities, Profile, Report, Request, Run, Stage},
};
use p3_field::PrimeCharacteristicRing;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

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

pub(crate) struct WalletProof {
    pub(crate) proof: NativeStarkProof<Challenge>,
    pub(crate) public_values: Vec<Val>,
    pub(crate) report: Report,
}

impl WalletProver {
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

    fn prove(
        &self,
        prepared: &PreparedStark<Challenge>,
        entry_point: &'static str,
        request: Request,
        host_bytes: usize,
        generate: impl FnOnce(&Run) -> Result<NativeWalletTrace>,
    ) -> Result<WalletProof> {
        let mut capabilities = Capabilities::cpu(Profile::LegacyQuadratic, false, false);
        for stage in Stage::ARITHMETIC {
            if !matches!(stage, Stage::Preprocessing | Stage::Lookup) {
                capabilities.set(stage, Backend::Cuda);
            }
        }
        let run = Run::new(entry_point, request, capabilities).map_err(super::super::error)?;
        let result = self.runtime.reported(&run, || {
            let frame = generate(&run)?;
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
                Some(&frame.public),
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
        self.engine
            .prove(&self.prepared, "cuda_htlc", request, host_bytes, |run| {
                self.engine.wallets.htlc(witness, host_bytes, run)
            })
    }
}
