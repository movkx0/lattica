//! Binding supplied by the trusted native host bridge after verified replay.
//!
//! This binds dispatch to a host snapshot; it does not perform native application.
//! The bridge must recheck the preparation pins and atomically compare the head
//! when publishing the CPU-audited root.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    #[default]
    Candidate,
    Prefix,
}

impl Scope {
    fn is_candidate(&self) -> bool {
        *self == Self::Candidate
    }
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    #[serde(default, skip_serializing_if = "Scope::is_candidate")]
    scope: Scope,
    schema_version: u32,
    head_token: [u8; 32],
    generation: u64,
    configuration_sha256: [u8; 32],
    complete_body_sha256: [u8; 32],
    preparation_sha256: [u8; 32],
    expected: Expected,
}

impl Binding {
    /// A trusted host may seal only an extension under the same native head.
    /// Ordered wallet identity is checked separately by the verified DAG.
    pub(super) fn check_prefix_extension(&self, next: &Self) -> Result<(), Error> {
        next.check_scope(false)?;
        self.check_cache_session(next)?;
        if self.expected.count > next.expected.count {
            return Err("sealed native selection shrank its prefix".into());
        }
        Ok(())
    }

    pub(super) fn check_candidate(&self, next: &Self) -> Result<(), Error> {
        self.check_phase(next, false)
    }

    pub(super) fn check_phase(&self, next: &Self, prefix: bool) -> Result<(), Error> {
        self.check_scope(prefix)?;
        next.check_scope(prefix)?;
        if serde_json::to_value(self)? != serde_json::to_value(next)? {
            return Err("bounded pool phase changed its native candidate".into());
        }
        Ok(())
    }

    pub(super) fn check_pool_session(&self, next: &Self) -> Result<(), Error> {
        self.check_scope(false)?;
        next.check_scope(false)?;
        if self.configuration_sha256 != next.configuration_sha256
            || self.expected.profile != next.expected.profile
            || self.expected.chain != next.expected.chain
        {
            return Err("pool native configuration changed".into());
        }
        Ok(())
    }
    pub(super) fn check_scope(&self, prefix: bool) -> Result<(), Error> {
        self.validate()?;
        if (self.scope == Scope::Prefix) != prefix {
            return Err("native preparation scope differs from proving scope".into());
        }
        Ok(())
    }

    pub(super) fn check_cache_session(&self, current: &Self) -> Result<(), Error> {
        self.check_scope(true)?;
        current.validate()?;
        let overlap = self.expected.count.min(current.expected.count) as usize;
        if self.head_token != current.head_token
            || self.generation != current.generation
            || self.configuration_sha256 != current.configuration_sha256
            || self.expected.profile != current.expected.profile
            || self.expected.chain != current.expected.chain
            || self.expected.block_height != current.expected.block_height
            || (0..overlap).any(|index| {
                self.expected
                    .authorized_issuance
                    .get(&index)
                    .copied()
                    .unwrap_or(0)
                    != current
                        .expected
                        .authorized_issuance
                        .get(&index)
                        .copied()
                        .unwrap_or(0)
            })
        {
            return Err("pre-seal cache belongs to another native head or policy".into());
        }
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        self.expected.validate()?;
        if self.schema_version != 1
            || self.generation == u64::MAX
            || [
                self.head_token,
                self.configuration_sha256,
                self.complete_body_sha256,
                self.preparation_sha256,
            ]
            .iter()
            .any(|digest| *digest == [0; 32])
        {
            return Err("native host snapshot binding is invalid".into());
        }
        Ok(())
    }

    pub(super) fn head_for(&self, expected: &Expected) -> Result<[u8; 32], Error> {
        self.validate()?;
        // Include height and issuance grants, beyond the recursive public root.
        if serde_json::to_value(&self.expected)? != serde_json::to_value(expected)? {
            return Err("native host snapshot differs from the proving expectation".into());
        }
        Ok(self.head_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            scope: Scope::Candidate,
            schema_version: 1,
            head_token: [1; 32],
            generation: 0,
            configuration_sha256: [2; 32],
            complete_body_sha256: [3; 32],
            preparation_sha256: [4; 32],
            expected: Expected {
                schema_version: 1,
                profile: [5; 32],
                chain: [6; 32],
                root: [7; 4],
                count: 8,
                block_height: 10,
                authorized_issuance: [(3, 7), (7, 7)].into_iter().collect(),
            },
        }
    }

    #[test]
    fn live_extension_requires_sealing_the_same_head_and_all_prefix_grants() {
        let mut prefix = binding(); prefix.scope = Scope::Prefix;
        let mut final_binding = binding();
        final_binding.expected.count = 16;
        final_binding.expected.root = [8; 4];
        final_binding.complete_body_sha256 = [9; 32];
        final_binding.preparation_sha256 = [10; 32];
        final_binding.expected.authorized_issuance.insert(15, 7);
        prefix.check_prefix_extension(&final_binding).unwrap();
        assert!(prefix.check_prefix_extension(&prefix).is_err());
        assert!(final_binding.check_prefix_extension(&final_binding).is_err());
        for field in ["head", "generation", "configuration", "profile", "chain", "height", "count", "grant", "removed_grant"] {
            let mut changed = final_binding.clone();
            match field {
                "head" => changed.head_token[0] ^= 1,
                "generation" => changed.generation += 1,
                "configuration" => changed.configuration_sha256[0] ^= 1,
                "profile" => changed.expected.profile[0] ^= 1,
                "chain" => changed.expected.chain[0] ^= 1,
                "height" => changed.expected.block_height += 1,
                "count" => changed.expected.count = 4,
                "grant" => { changed.expected.authorized_issuance.insert(7, 8); },
                "removed_grant" => { changed.expected.authorized_issuance.remove(&7); },
                _ => unreachable!(),
            }
            assert!(prefix.check_prefix_extension(&changed).is_err(), "{field}");
        }
    }

    #[test]
    fn prefix_scope_cannot_be_used_for_sealed_dispatch() {
        let mut source = binding();
        assert!(source.check_scope(false).is_ok());
        assert!(source.check_scope(true).is_err());
        source.scope = Scope::Prefix;
        assert!(source.check_scope(true).is_ok());
        assert!(source.check_scope(false).is_err());
        assert_eq!(serde_json::to_value(&source).unwrap()["scope"], "prefix");
        assert!(serde_json::to_value(binding())
            .unwrap()
            .get("scope")
            .is_none());
    }

    #[test]
    fn bounded_phase_requires_the_entire_original_candidate_binding() {
        let original = binding();
        original.check_candidate(&original).unwrap();
        for field in 0..7 {
            let mut changed = original.clone();
            match field {
                0 => changed.head_token[0] ^= 1,
                1 => changed.generation += 1,
                2 => changed.configuration_sha256[0] ^= 1,
                3 => changed.complete_body_sha256[0] ^= 1,
                4 => changed.preparation_sha256[0] ^= 1,
                5 => changed.expected.block_height += 1,
                _ => changed.expected.count += 1,
            }
            assert!(original.check_candidate(&changed).is_err(), "field {field}");
        }
    }

    #[test]
    fn bounded_prefix_phase_preserves_scope_and_every_native_pin() {
        let mut prefix = binding();
        prefix.scope = Scope::Prefix;
        prefix.check_phase(&prefix, true).unwrap();
        assert!(prefix.check_candidate(&prefix).is_err());
        assert!(prefix.check_pool_session(&prefix).is_err());
        for field in 0..8 {
            let mut changed = prefix.clone();
            match field {
                0 => changed.scope = Scope::Candidate,
                1 => changed.head_token[0] ^= 1,
                2 => changed.generation += 1,
                3 => changed.configuration_sha256[0] ^= 1,
                4 => changed.complete_body_sha256[0] ^= 1,
                5 => changed.preparation_sha256[0] ^= 1,
                6 => changed.expected.count += 1,
                _ => {
                    changed.expected.authorized_issuance.insert(3, 8);
                }
            }
            assert!(prefix.check_phase(&changed, true).is_err(), "field {field}");
        }
        assert!(binding().check_phase(&binding(), true).is_err());
    }

    #[test]
    fn cache_allows_growth_but_rejects_another_head_height_or_policy() {
        let mut source = binding();
        source.scope = Scope::Prefix;
        let mut current = binding();
        current.expected.count = 16;
        current.expected.root = [8; 4];
        current.complete_body_sha256 = [9; 32];
        current.preparation_sha256 = [10; 32];
        current.expected.authorized_issuance.insert(15, 7);
        assert!(source.check_cache_session(&current).is_ok());
        for field in [
            "head_token",
            "generation",
            "configuration_sha256",
            "height",
            "profile",
            "chain",
            "grant",
        ] {
            let mut changed = current.clone();
            match field {
                "head_token" => changed.head_token[0] ^= 1,
                "generation" => changed.generation += 1,
                "configuration_sha256" => changed.configuration_sha256[0] ^= 1,
                "height" => changed.expected.block_height += 1,
                "profile" => changed.expected.profile[0] ^= 1,
                "chain" => changed.expected.chain[0] ^= 1,
                "grant" => {
                    changed.expected.authorized_issuance.insert(3, 8);
                }
                _ => unreachable!(),
            }
            assert!(source.check_cache_session(&changed).is_err(), "{field}");
        }
        assert!(current.check_cache_session(&current).is_err());
    }

    #[test]
    fn actual_native_head_is_distinct_from_profile_and_binds_all_policy_fields() {
        let binding = binding();
        assert_eq!(binding.head_for(&binding.expected).unwrap(), [1; 32]);
        assert_ne!(
            binding.head_for(&binding.expected).unwrap(),
            binding.expected.profile
        );
        for field in [
            "profile",
            "chain",
            "root",
            "count",
            "block_height",
            "authorized_issuance",
        ] {
            let mut expected = serde_json::to_value(&binding.expected).unwrap();
            match field {
                "profile" | "chain" | "root" => expected[field][0] = json!(9),
                "count" => expected[field] = json!(4),
                "block_height" => expected[field] = json!(11),
                "authorized_issuance" => expected[field] = json!({"3": 8, "7": 7}),
                _ => unreachable!(),
            }
            assert!(binding
                .head_for(&serde_json::from_value(expected).unwrap())
                .is_err());
        }
    }

    #[test]
    fn absent_pins_and_exhausted_generation_cannot_bind_a_native_candidate() {
        let binding = binding();
        for field in [
            "head_token",
            "configuration_sha256",
            "complete_body_sha256",
            "preparation_sha256",
        ] {
            let mut value = serde_json::to_value(&binding).unwrap();
            value[field] = json!(vec![0u8; 32]);
            assert!(serde_json::from_value::<Binding>(value)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut exhausted = binding;
        exhausted.generation = u64::MAX;
        assert!(exhausted.validate().is_err());
    }
}
