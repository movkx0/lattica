//! One approved registry borrowed immutably across wallet and node verification.
//!
//! This is local validation authority, not a serialized ticket or a global cache.
//! It cannot outlive or permit mutation of the registry it checked. Wallet proof,
//! chain and caller-supplied policy verification still run for every input.

use super::*;
use crate::block_v2::typed_recursive::{Policy, Registry as TypedRegistry};

pub struct TypedRegistryContext<'a> {
    pin: RegistryPin,
    approved: crate::block_v2::typed_recursive::CheckedRegistryRef<'a>,
}

impl<'a> TypedRegistryContext<'a> {
    pub fn new(registry: &'a TypedRegistry<12>, profile: [u8; 32]) -> Result<Self, Error> {
        let approved = crate::block_v2::typed_recursive::CheckedRegistryRef::new(registry)?;
        Self::from_approved(approved, profile)
    }

    pub(crate) fn from_approved(
        approved: crate::block_v2::typed_recursive::CheckedRegistryRef<'a>,
        profile: [u8; 32],
    ) -> Result<Self, Error> {
        let registry = approved.as_registry();
        let pin = RegistryPin::new_typed_with_id(registry, profile, || Ok(approved.profile()))?;
        Ok(Self { pin, approved })
    }

    pub(crate) fn for_pin(
        registry: &'a TypedRegistry<12>,
        pin: RegistryPin,
    ) -> Result<Self, Error> {
        if !pin.is_typed() || pin.construction() != WrapperConstruction::GroupedPair {
            return Err("typed execution registry substitution".into());
        }
        let context = Self::new(registry, pin.profile())?;
        if context.pin() != pin {
            return Err("typed execution registry substitution".into());
        }
        Ok(context)
    }

    pub fn pin(&self) -> RegistryPin {
        self.pin
    }

    pub(crate) fn to_owned_registry(&self) -> crate::block_v2::typed_recursive::CheckedRegistry {
        self.approved.to_owned()
    }

    /// Initial wallet approval, pool registry construction and wallet intake
    /// run sequentially. Both registry constructors use the same setup quotas;
    /// registry/input ownership is reserved by the enclosing coordinator.
    pub fn preparation_storage_bytes() -> Result<usize, Error> {
        #[cfg(all(not(debug_assertions), target_arch = "x86_64", feature = "stream"))]
        {
            let intake = Self::wallet_intake_storage_bytes()?;
            let setup = crate::block_v2::machine::programs::registry_setup::Plan::new()?;
            Ok(intake.max(setup.peak_bytes))
        }
        #[cfg(not(all(not(debug_assertions), target_arch = "x86_64", feature = "stream")))]
        {
            Err("registry/wallet accounting requires qualified release x86_64 stream".into())
        }
    }

    /// Known payload peak for one sequential wallet intake. Input bytes, initial
    /// registry approval, allocator overhead and runtime storage are separate.
    pub fn wallet_intake_storage_bytes() -> Result<usize, Error> {
        #[cfg(all(not(debug_assertions), target_arch = "x86_64", feature = "stream"))]
        {
            Ok(recursive::verification::intake::Plan::maximum()?.peak_bytes)
        }
        #[cfg(not(all(not(debug_assertions), target_arch = "x86_64", feature = "stream")))]
        {
            Err("wallet intake accounting requires qualified release x86_64 stream".into())
        }
    }

    /// Verify one public wallet artifact against this approved registry and the
    /// host's expected chain/policy. No registry hashing is repeated here.
    pub fn verify_wallet(
        &self,
        expected_chain: [u8; 32],
        policy: Policy,
        bytes: &[u8],
    ) -> Result<VerifiedWallet, Error> {
        VerifiedWallet::check_typed_encoding(bytes)?;
        let storage =
            codec::proofs::Storage::new(recursive::verification::decoded::storage_limit()?);
        VerifiedWallet::verify_typed_admitted(self.pin, expected_chain, policy, bytes, &storage)
            .map(|(ticket, _)| ticket)
    }

    /// Verify and retain one owned buffer without rehashing a detached ticket.
    /// Reject excessive backing before decoding or numerical verification.
    pub fn verify_wallet_owned(
        &self,
        expected_chain: [u8; 32],
        policy: Policy,
        bytes: Vec<u8>,
    ) -> Result<VerifiedWalletPayload, Error> {
        VerifiedWalletPayload::check_capacity(&bytes)?;
        let ticket = self.verify_wallet(expected_chain, policy, &bytes)?;
        Ok(VerifiedWalletPayload { ticket, bytes: bytes.into() })
    }

    // Durable recovery retains the reference decoder's general input allowance.
    // The recovery phase separately reserves decoding plus numerical verification.
    pub(crate) fn verify_stored_wallet_owned(
        &self,
        expected_chain: [u8; 32],
        policy: Policy,
        bytes: Vec<u8>,
    ) -> Result<VerifiedWalletPayload, Error> {
        VerifiedWalletPayload::check_capacity(&bytes)?;
        let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
        let (ticket, _) = VerifiedWallet::verify_typed_owned_approved(
            self.pin,
            &self.approved,
            expected_chain,
            policy,
            &bytes,
            &storage,
        )?;
        Ok(VerifiedWalletPayload { ticket, bytes: bytes.into() })
    }

    /// Check the full job pin, canonical encoding and original numerical proof.
    /// Only registry identity construction is reused across this immutable borrow.
    pub fn verify_node(&self, job: &Job, bytes: &[u8]) -> Result<VerifiedNode, Error> {
        VerifiedNode::verify_typed_approved(job, &self.approved, bytes)
    }

    /// Verification and digest derivation authenticate this owned buffer before
    /// it enters durable storage or the graph. No mutable alias survives this
    /// transfer; a detached ticket and caller-supplied bytes require rebinding.
    pub fn verify_node_owned(
        &self,
        job: &Job,
        bytes: Vec<u8>,
    ) -> Result<VerifiedNodePayload, Error> {
        let ticket = self.verify_node(job, &bytes)?;
        Ok(VerifiedNodePayload { ticket, bytes })
    }
}

#[path = "typed_registry/recovery.rs"]
mod recovery;

#[cfg(all(test, feature = "stream"))]
#[path = "typed_registry/tests.rs"]
pub(crate) mod tests;
