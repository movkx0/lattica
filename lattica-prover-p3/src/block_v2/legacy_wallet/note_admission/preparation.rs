//! Borrowed witness and owned public preprocessing. No GPU initialization,
//! entropy, trace arithmetic, proof construction, or dispatch authority.
use super::{
    add, resources::MAX_HOST_BYTES, Error, Geometry, PreparationResources, RandomnessBounds,
};
use crate::block_v2::{gpu_hash::device::Extension, gpu_quotient_prover::uni};
use crate::{config::Val, joinsplit_air as js, note_research_quota::Reservation};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
mod attempt;
#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(super) use attempt::EncodedPayload;
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
pub(super) use attempt::{NoteAttempt, NoteCompletion, OperationResources};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Diagnostics {
    pub geometry: Geometry,
    pub preparation: PreparationResources,
    pub randomness: RandomnessBounds,
    pub worker_host_allowance: usize,
    pub complete_prover_host_lifetime: bool,
    pub complete_prover_device_lifetime: bool,
    pub dispatch_enabled: bool,
}

/// A pure preparation recipe. Preparing it consumes an opaque charge from the
/// enclosing session's ledger. The recipe alone grants no allocation authority.
#[derive(Clone, Copy, Debug)]
pub struct PreparationPlan {
    diagnostic: Diagnostics,
    inner_host_allowance: usize,
}

/// Private witnesses stay borrowed and expected publics stay inline. This owner
/// is not Clone and never exposes the recorded program. The independent opt-in
/// qualification feature adds a guarded producer with an owned encoded result.
pub struct PreparedNote<'w> {
    prepared: uni::Prepared,
    witness: &'w js::Witness,
    expected_public: [Val; 26],
    plan: PreparationPlan,
    // Last field: public preprocessing and all other owned fields are destroyed
    // before their shared charge is released, including during unwinding.
    reservation: Reservation,
}

impl PreparationPlan {
    pub fn new(worker_host_allowance: usize) -> Result<Self, Error> {
        let geometry = Geometry::pinned()?;
        let preparation = PreparationResources::new(geometry)?;
        let randomness = RandomnessBounds::new(geometry)?;
        if worker_host_allowance > MAX_HOST_BYTES
            || worker_host_allowance <= preparation.required_payload_bytes
        {
            return Err(Error::ResourceLimit);
        }
        // Preserve borrowed/inline storage outside uni::Prepared's compiler and
        // periodic partition instead of lending it again to future PCS work.
        let inner_host_allowance = worker_host_allowance
            .checked_sub(add(
                preparation.borrowed_witness_bytes,
                preparation.owner_inline_bytes,
            )?)
            .ok_or(Error::ResourceLimit)?;
        Ok(Self {
            diagnostic: Diagnostics {
                geometry,
                preparation,
                randomness,
                worker_host_allowance,
                complete_prover_host_lifetime: false,
                complete_prover_device_lifetime: false,
                dispatch_enabled: false,
            },
            inner_host_allowance,
        })
    }

    pub fn required_host_bytes(self) -> usize {
        self.diagnostic.preparation.required_payload_bytes
    }

    pub fn diagnostics(self) -> Diagnostics {
        self.diagnostic
    }

    /// Consume a reservation from the enclosing research session's quota.
    /// Numeric byte declarations cannot substitute for this ownership token.
    /// Profile/context authentication of expected_public belongs to that caller;
    /// this function rejects malformed private amounts and inconsistent binding
    /// before allocating metadata, without computing commitments or nullifiers.
    pub fn prepare<'w>(
        self,
        witness: &'w js::Witness,
        expected_public: [Val; 26],
        reservation: Reservation,
    ) -> Result<PreparedNote<'w>, Error> {
        if reservation.reserved_bytes() < self.required_host_bytes() {
            return Err(Error::ResourceLimit);
        }
        admit_inputs(witness, &expected_public)?;
        let prepared = uni::Prepared::new(
            &js::JoinSplitAir,
            self.diagnostic.geometry.rows,
            Extension::Quadratic,
            self.inner_host_allowance,
        )
        .map_err(|_| Error::Preparation)?;
        Ok(PreparedNote {
            prepared,
            witness,
            expected_public,
            plan: self,
            reservation,
        })
    }
}

impl PreparedNote<'_> {
    #[cfg(all(
        any(test, feature = "note-gpu-proving-experiment"),
        feature = "gpu-bounded-info"
    ))]
    pub(super) fn device_minimum(
        &self,
    ) -> Result<crate::block_v2::gpu_hash::device::WalletProofMinimum, Error> {
        self.prepared.minimum().map_err(|_| Error::Preparation)
    }

    pub(super) fn same_ledger(&self, other: &Reservation) -> bool {
        self.reservation.same_ledger(other)
    }

    pub(super) fn operation_host_allowance(&self) -> Result<usize, Error> {
        self.prepared
            .operation_host_allowance()
            .map_err(|_| Error::ResourceLimit)
    }

    pub fn diagnostics(&self) -> Diagnostics {
        self.plan.diagnostics()
    }

    pub fn require_dispatch(&self) -> Result<(), Error> {
        Err(Error::IncompleteLifetimeAdmission)
    }
}

fn admit_inputs(witness: &js::Witness, public: &[Val; 26]) -> Result<(), Error> {
    if witness.fee != 0
        || witness.mint != 0
        || public[js::PI_FEE] != Val::ZERO
        || public[js::PI_MINT] != Val::ZERO
        || public[js::PI_NF..js::PI_NF + 4] == public[js::PI_NF + 4..js::PI_NF + 8]
        || public[js::PI_TXBIND..js::PI_TXBIND + 4] != witness.tx_binding
        || witness
            .inputs
            .iter()
            .flat_map(|input| input.nk)
            .any(|x| x >= Val::ORDER_U64)
    {
        return Err(Error::Statement);
    }
    let asset = witness.inputs[0].asset;
    if witness
        .inputs
        .iter()
        .any(|input| input.asset != asset || input.value >= 1 << 52)
        || witness
            .outputs
            .iter()
            .any(|output| output.asset != asset || output.value >= 1 << 52)
        || witness
            .inputs
            .iter()
            .map(|input| u128::from(input.value))
            .sum::<u128>()
            != witness
                .outputs
                .iter()
                .map(|output| u128::from(output.value))
                .sum::<u128>()
    {
        return Err(Error::Statement);
    }
    Ok(())
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
