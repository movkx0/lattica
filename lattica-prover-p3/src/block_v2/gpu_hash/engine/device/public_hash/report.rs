//! Bounded evidence of completed public-hash work in one engine lifetime.
//! The accessor reads this observation, never the environment or a new device.

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
enum Kernel {
    #[serde(rename = "baseline")]
    Baseline,
    #[serde(rename = "sbox-pair-v1")]
    SboxPairV1,
}

/// The effective implementation observed after a completed public-hash batch.
/// This is execution telemetry, not proof authentication or fresh GPU credit.
/// A scalar baseline tail and a cooperative baseline batch share one policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PublicHashExecution {
    kernel: Kernel,
    gpu_tuning_compiled: bool,
    nvidia_supported: bool,
}

impl PublicHashExecution {
    /// Exact label for the implementation which actually dispatched.
    pub fn kernel(self) -> &'static str {
        match self.kernel {
            Kernel::Baseline => "baseline",
            Kernel::SboxPairV1 => "sbox-pair-v1",
        }
    }

    pub fn gpu_tuning_compiled(self) -> bool {
        self.gpu_tuning_compiled
    }

    pub fn nvidia_supported(self) -> bool {
        self.nvidia_supported
    }

    /// Bind the actual entry point and detected engine capability before
    /// dispatch. The enclosing observation is updated only after completion.
    pub(super) fn validated_kernel(name: &str, nvidia_supported: bool) -> Result<Self, String> {
        Self::checked(name, cfg!(feature = "gpu-tuning"), nvidia_supported)
    }

    fn checked(
        name: &str,
        gpu_tuning_compiled: bool,
        nvidia_supported: bool,
    ) -> Result<Self, String> {
        let kernel = match name {
            "device_public_hash" | "device_public_hash_cooperative" => Kernel::Baseline,
            "device_public_hash_batch" if gpu_tuning_compiled => Kernel::Baseline,
            "device_public_hash_sbox_pair" | "device_public_hash_batch_pair" if gpu_tuning_compiled && nvidia_supported => {
                Kernel::SboxPairV1
            }
            _ => return Err("unqualified public hash execution label".into()),
        };
        Ok(Self {
            kernel,
            gpu_tuning_compiled,
            nvidia_supported,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Observation {
    execution: Option<PublicHashExecution>,
    mixed: bool,
}

impl Observation {
    /// Call only after the event for this actual kernel has completed.
    /// Preserve completed work even if a later batch or callback fails.
    pub(crate) fn record(&mut self, execution: PublicHashExecution) {
        if let Some(previous) = self.execution {
            self.mixed |= previous != execution;
        } else {
            self.execution = Some(execution);
        }
    }

    pub(crate) fn get(self) -> Result<Option<PublicHashExecution>, String> {
        if self.mixed {
            Err("GPU context used inconsistent public hash implementations".into())
        } else {
            Ok(self.execution)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_flags_are_literal_and_serialization_has_exact_types() {
        for supported in [false, true] {
            let baseline =
                PublicHashExecution::validated_kernel("device_public_hash", supported).unwrap();
            assert_eq!(baseline.gpu_tuning_compiled(), cfg!(feature = "gpu-tuning"));
            assert_eq!(baseline.nvidia_supported(), supported);
            assert_eq!(baseline.kernel(), "baseline");
            assert_eq!(
                serde_json::to_value(baseline).unwrap(),
                serde_json::json!({
                    "kernel":"baseline", "gpu_tuning_compiled":cfg!(feature="gpu-tuning"),
                    "nvidia_supported":supported
                })
            );
        }
        let candidate =
            PublicHashExecution::checked("device_public_hash_sbox_pair", true, true).unwrap();
        assert_eq!(candidate.kernel(), "sbox-pair-v1");
        assert_eq!(
            serde_json::to_value(candidate).unwrap(),
            serde_json::json!({
                "kernel":"sbox-pair-v1", "gpu_tuning_compiled":true, "nvidia_supported":true
            })
        );
        for (feature, supported) in [(false, false), (false, true), (true, false)] {
            assert!(
                PublicHashExecution::checked("device_public_hash_sbox_pair", feature, supported)
                    .is_err()
            );
        }
        for invalid in ["baseline", "sbox-pair-v1", "device_public_hash_unknown", ""] {
            assert!(PublicHashExecution::checked(invalid, true, true).is_err());
        }
    }

    #[test]
    fn observation_requires_work_and_latches_mixed_execution() {
        let mut observed = Observation::default();
        assert_eq!(observed.get().unwrap(), None);
        let scalar = PublicHashExecution::checked("device_public_hash", true, true).unwrap();
        let cooperative =
            PublicHashExecution::checked("device_public_hash_cooperative", true, true).unwrap();
        observed.record(scalar);
        observed.record(cooperative);
        assert_eq!(observed.get().unwrap(), Some(scalar));
        let paired =
            PublicHashExecution::checked("device_public_hash_sbox_pair", true, true).unwrap();
        observed.record(paired);
        assert!(observed.get().is_err());
        observed.record(scalar);
        assert!(observed.get().is_err());
        let mut candidate = Observation::default();
        candidate.record(paired);
        candidate.record(paired);
        assert_eq!(candidate.get().unwrap(), Some(paired));
    }
}
