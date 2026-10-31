//! Explicit research selection; absent/empty/baseline keeps the qualified path.
//! No device enumeration, initialization or arithmetic occurs while parsing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Selection {
    #[default]
    Baseline,
    SboxPairV1,
}

impl Selection {
    pub(super) fn parse(value: Option<&str>, feature_enabled: bool) -> Result<Self, &'static str> {
        match value {
            None | Some("") | Some("baseline") => Ok(Self::Baseline),
            Some("sbox-pair-v1") if feature_enabled => Ok(Self::SboxPairV1),
            Some("sbox-pair-v1") => Err("public hash sbox-pair-v1 requires gpu-tuning"),
            _ => Err("unknown GPU public hash selection"),
        }
    }

    pub(crate) fn from_env() -> Result<Self, String> {
        let value = match std::env::var("LATTICA_V2_GPU_PUBLIC_HASH") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("GPU public hash selection must be UTF-8".into()),
        };
        Self::parse(value.as_deref(), cfg!(feature = "gpu-tuning")).map_err(str::to_owned)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::SboxPairV1 => "sbox-pair-v1",
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn require_device(self, device: ocl::Device) -> Result<(), String> {
        if self == Self::SboxPairV1 && super::nvidia::source_prefix(device).is_empty() {
            return Err("public hash sbox-pair-v1 requires NVIDIA SM7+ and 32-lane warps".into());
        }
        Ok(())
    }
}

// Fixed single-workgroup driver storage ceilings live inside the existing
// context reserve. Neither changes managed buffers, public input scratch or
// host staging. Query these before launching the experimental kernel.
pub(super) const PAIR_LANES: usize = 16;
pub(super) const PAIR_LOCAL_BYTES: u64 = 256;
pub(super) const PAIR_PRIVATE_BYTES_PER_LANE: u64 = 4096;

#[cfg(feature = "gpu")]
pub(super) fn inspect_kernel(
    kernel: &ocl::Kernel,
    device: ocl::Device,
) -> Result<(u64, u64), String> {
    use ocl::enums::{KernelWorkGroupInfo as Info, KernelWorkGroupInfoResult as Result};
    let local = match kernel
        .wg_info(device, Info::LocalMemSize)
        .map_err(|e| e.to_string())?
    {
        Result::LocalMemSize(bytes) => bytes,
        _ => return Err("public hash candidate local memory unavailable".into()),
    };
    let private = match kernel
        .wg_info(device, Info::PrivateMemSize)
        .map_err(|e| e.to_string())?
    {
        Result::PrivateMemSize(bytes) => bytes,
        _ => return Err("public hash candidate private memory unavailable".into()),
    };
    let maximum = match kernel
        .wg_info(device, Info::WorkGroupSize)
        .map_err(|e| e.to_string())?
    {
        Result::WorkGroupSize(lanes) => lanes,
        _ => return Err("public hash candidate workgroup bound unavailable".into()),
    };
    let compiled = match kernel
        .wg_info(device, Info::CompileWorkGroupSize)
        .map_err(|e| e.to_string())?
    {
        Result::CompileWorkGroupSize(lanes) => lanes,
        _ => return Err("public hash candidate compiled geometry unavailable".into()),
    };
    if local > PAIR_LOCAL_BYTES
        || private > PAIR_PRIVATE_BYTES_PER_LANE
        || maximum < PAIR_LANES
        || compiled != [PAIR_LANES, 1, 1]
    {
        return Err("public hash candidate exceeds fixed single-workgroup storage".into());
    }
    Ok((local, private))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_requires_exact_explicit_feature_selection() {
        for feature in [false, true] {
            for value in [None, Some(""), Some("baseline")] {
                assert_eq!(Selection::parse(value, feature), Ok(Selection::Baseline));
            }
        }
        assert!(Selection::parse(Some("sbox-pair-v1"), false).is_err());
        assert_eq!(
            Selection::parse(Some("sbox-pair-v1"), true),
            Ok(Selection::SboxPairV1)
        );
        for value in [
            "pair",
            "sbox-pair-v1,baseline",
            " sbox-pair-v1",
            "sbox-pair-v1 ",
            "SBOX-PAIR-V1",
        ] {
            assert!(Selection::parse(Some(value), true).is_err());
        }
    }
}
