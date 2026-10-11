//! Bounded approval tied to an immutable borrow of one legacy registry.
//! This is local validation authority, not a serialized or reusable worker ticket.
use super::*;

pub(crate) struct CheckedRegistryRef<'a> {
    registry: &'a Registry,
    profile: [u8; 32],
}

impl<'a> CheckedRegistryRef<'a> {
    pub(crate) fn new(registry: &'a Registry) -> Result<Self, Error> {
        let profile = registry.bounded_id()?;
        Ok(Self { registry, profile })
    }

    pub(crate) fn profile(&self) -> [u8; 32] {
        self.profile
    }

    #[cfg(test)]
    pub(crate) fn as_registry(&self) -> &'a Registry {
        self.registry
    }

    pub(crate) fn verify(
        &self,
        node: &NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<(), Error> {
        verify_with_verifier(self.profile, node, expected, |mode| {
            self.registry.verifier_from_cap(mode)
        })
    }

    pub(crate) fn wallet_summary(&self, wallet: &WalletProof) -> Result<NodeSummary, Error> {
        wallet_summary_with_profile(wallet, || Ok(self.profile))
    }
}

impl ProverSession {
    /// Admit caller-owned registry backing and startup before copying its caps.
    /// The derived identity remains bound to this owned, immutable registry.
    pub(super) fn from_borrowed_registry(
        registry: &Registry,
        worker_memory_bytes: u64,
    ) -> Result<Self, Error> {
        storage::admit_session(registry)?;
        storage::admit_startup(worker_memory_bytes)?;
        let approved = CheckedRegistryRef::new(registry)?;
        Ok(Self {
            registry: registry.clone(),
            expected_profile: approved.profile(),
            worker_memory_bytes,
            cached: None,
            stats: CacheStats::default(),
        })
    }

    /// Both constructors validate the profile before owning the registry. No
    /// production method mutates that registry or exposes a mutable reference.
    /// Cache eviction changes preprocessing ownership, never this authority.
    pub(super) fn registry_approval(&self) -> CheckedRegistryRef<'_> {
        CheckedRegistryRef {
            registry: &self.registry,
            profile: self.expected_profile,
        }
    }
}

#[cfg(all(test, feature = "stream"))]
#[path = "recursive_checked_registry_tests.rs"]
mod tests;
