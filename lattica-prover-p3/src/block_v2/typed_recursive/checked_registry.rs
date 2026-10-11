//! An owned registry whose identity cannot outlive or diverge from its caps.
//! This is not a consensus allowlist: callers must compare the derived profile
//! with their expected profile/worker capabilities. Approval is never decoded
//! from a worker packet, and no mutable registry reference is exposed.

use super::*;

#[derive(Clone)]
pub(crate) struct CheckedRegistry {
    registry: Registry<12>,
    profile: [u8; 32],
}

impl CheckedRegistry {
    pub(crate) fn new(registry: Registry<12>) -> Result<Self, Error> {
        let profile = CheckedRegistryRef::new(&registry)?.profile();
        Ok(Self { registry, profile })
    }

    pub(crate) fn profile(&self) -> [u8; 32] {
        self.profile
    }

    pub(crate) fn storage_bytes(&self) -> Result<usize, Error> {
        self.registry.storage_bytes()
    }

    pub(crate) fn as_registry(&self) -> &Registry<12> {
        &self.registry
    }

    pub(crate) fn as_ref(&self) -> CheckedRegistryRef<'_> {
        CheckedRegistryRef {
            registry: &self.registry,
            profile: self.profile,
        }
    }

    /// Verify the complete original numerical statement on every call. Only
    /// symbolic registry identity construction is reused, never proof results.
    pub(crate) fn verify(
        &self,
        node: &NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<(), Error> {
        self.as_ref().verify(node, expected)
    }
}

/// The immutable borrow keeps the approved identity tied to exactly these caps.
/// Neither ownership transfer nor cloning serializes or trusts an approval bit.
pub(crate) struct CheckedRegistryRef<'a> {
    registry: &'a Registry<12>,
    profile: [u8; 32],
}

impl<'a> CheckedRegistryRef<'a> {
    pub(crate) fn new(registry: &'a Registry<12>) -> Result<Self, Error> {
        registry.storage_bytes()?;
        let profile = programs::registry_setup::profile_id(registry.height, &registry.caps)?;
        Ok(Self { registry, profile })
    }

    pub(crate) fn profile(&self) -> [u8; 32] {
        self.profile
    }

    pub(crate) fn as_registry(&self) -> &'a Registry<12> {
        self.registry
    }

    pub(crate) fn to_owned(&self) -> CheckedRegistry {
        CheckedRegistry {
            registry: self.registry.clone(),
            profile: self.profile,
        }
    }

    pub(crate) fn verify(
        &self,
        node: &NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<(), Error> {
        let summary = recursive::summary_with_modes(expected, 12)?;
        if summary.context.profile_id != self.profile || &node.public != expected {
            return Err("unapproved typed registry or unexpected statement".into());
        }
        self.registry.verify_statement(node, expected)
    }
}

impl Session<12> {
    pub(crate) fn from_checked(
        registry: CheckedRegistry,
        worker_memory_bytes: u64,
    ) -> Result<Self, Error> {
        storage::admit_session(&registry.registry)?;
        storage::active_memory_bytes(worker_memory_bytes, 0)?;
        Ok(Self::from_admitted(
            registry.registry,
            registry.profile,
            worker_memory_bytes,
        ))
    }

    pub(crate) fn registry_approval(&self) -> Result<CheckedRegistryRef<'_>, Error> {
        // Generic reference sessions can have other supported geometries. The
        // worker approval token retains the execution profile's height ceiling.
        if !self.registry.height.is_power_of_two()
            || !(8..=1 << 21).contains(&self.registry.height)
            || self
                .registry
                .caps
                .iter()
                .any(|cap| cap.len() != 1 << profile::CAP_HEIGHT)
        {
            return Err("typed execution registry shape/profile".into());
        }
        Ok(CheckedRegistryRef {
            registry: &self.registry,
            profile: self.expected_profile,
        })
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
