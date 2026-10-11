//! Sequential recovery verification uses one existing coordinator job allowance.
//! Graph, snapshot/store, selections, registry backing and callback owners retain
//! their shared/caller reservations. This is a payload component, not total RSS.

use super::*;

#[cfg(all(
    not(debug_assertions),
    target_arch = "x86_64",
    target_os = "linux",
    feature = "stream"
))]
pub(super) struct Plan {
    pub registry_bytes: usize,
    pub wallet_bytes: usize,
    pub node_bytes: usize,
    pub control_bytes: usize,
    pub peak_bytes: usize,
}

#[cfg(all(
    not(debug_assertions),
    target_arch = "x86_64",
    target_os = "linux",
    feature = "stream"
))]
impl Plan {
    pub(super) fn new() -> Result<Self, Error> {
        use crate::block_v2::{execution::worker_budget, machine::backend};
        let add = |a: usize, b: usize| {
            a.checked_add(b)
                .ok_or("recovery verification storage overflow")
        };
        let registry_bytes =
            crate::block_v2::machine::programs::registry_setup::Plan::new()?.peak_bytes;
        let decoded = codec::proofs::INPUT_STORAGE_LIMIT;
        let wallet = recursive::verification::intake::Plan::maximum()?;
        let wallet_bytes = add(
            add(
                decoded,
                wallet
                    .numerical_peak_bytes
                    .max(wallet.summary_requested_bytes),
            )?,
            1024 + core::mem::size_of::<String>(),
        )?;
        let node_bytes = add(
            decoded,
            usize::try_from(backend::NATIVE_VERIFIER_COMPONENT_BYTES)?,
        )?;
        let control_bytes = usize::try_from(worker_budget::COORDINATOR_PACKET_BYTES)?;
        // Two wallet slots can retain both source and converted byte owners.
        // Graph metadata/indexes and the store's reader have separate plans.
        let controls_needed = add(
            profile::MAX_PROOF_BYTES
                .checked_mul(4)
                .ok_or("recovery proof byte overflow")?,
            1 << 20,
        )?;
        if controls_needed > control_bytes {
            return Err("recovery control storage exceeds coordinator packet allowance".into());
        }
        let peak_bytes = add(
            control_bytes,
            registry_bytes.max(wallet_bytes).max(node_bytes),
        )?;
        if peak_bytes > usize::try_from(worker_budget::COORDINATOR_JOB_BYTES)? {
            return Err("recovery verification exceeds coordinator job allowance".into());
        }
        Ok(Self {
            registry_bytes,
            wallet_bytes,
            node_bytes,
            control_bytes,
            peak_bytes,
        })
    }
}

impl TypedRegistryContext<'_> {
    /// Sequential registry setup, wallet and node verification with control bytes.
    /// Keep the shared graph/store/caller allowance reserved separately.
    pub fn recovery_storage_bytes() -> Result<usize, Error> {
        #[cfg(all(
            not(debug_assertions),
            target_arch = "x86_64",
            target_os = "linux",
            feature = "stream"
        ))]
        {
            Ok(Plan::new()?.peak_bytes)
        }
        #[cfg(not(all(
            not(debug_assertions),
            target_arch = "x86_64",
            target_os = "linux",
            feature = "stream"
        )))]
        {
            Err(
                "recovery verification accounting requires qualified release Linux x86_64 stream"
                    .into(),
            )
        }
    }

    pub fn admit_recovery_storage(available_bytes: u64) -> Result<(), Error> {
        if available_bytes < u64::try_from(Self::recovery_storage_bytes()?)? {
            return Err("coordinator RAM below recovery verification allowance".into());
        }
        Ok(())
    }
}
