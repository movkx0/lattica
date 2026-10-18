//! Process-local, opt-in candidates; never a change to the proof profile.
#[cfg(all(test, feature = "gpu-tuning"))]
mod gpu_tests;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Tuning {
    pub events: bool,
    pub commitment: bool,
    pub scale: bool,
    pub ntt: bool,
}

impl Tuning {
    pub(super) fn from_env() -> Result<Self, String> {
        let value = match std::env::var("LATTICA_V2_GPU_TUNING") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(Self::default()),
            Err(_) => return Err("GPU tuning selection must be UTF-8".into()),
        };
        Self::parse(&value, cfg!(feature = "gpu-tuning"))
    }

    fn parse(value: &str, enabled: bool) -> Result<Self, String> {
        let mut result = Self::default();
        if value.is_empty() {
            return Ok(result);
        }
        if !enabled {
            return Err("GPU tuning requires the gpu-tuning research feature".into());
        }
        if value.len() > 64 {
            return Err("GPU tuning selection is too long".into());
        }
        for item in value.split(',') {
            let selected = match item {
                "events" => &mut result.events,
                "commitment" => &mut result.commitment,
                "scale" => &mut result.scale,
                "ntt" => &mut result.ntt,
                _ => return Err(format!("unknown GPU tuning candidate: {item}")),
            };
            if *selected {
                return Err("duplicate GPU tuning candidate".into());
            }
            *selected = true;
        }
        Ok(result)
    }

    pub(super) fn shared_scale(self, input_rows: usize, output_rows: usize, width: usize) -> bool {
        self.scale && input_rows == 1 << 18 && output_rows == 1 << 19 && matches!(width, 98 | 200)
    }

    pub(super) fn ntt_powers(self, height: usize, width: usize) -> bool {
        self.ntt && height == 1 << 23 && matches!(width, 3 | 4 | 8 | 16)
    }
}

#[cfg(feature = "gpu-tuning")]
pub(super) fn kernel_source(nvidia: bool) -> String {
    let mut source = String::new();
    if nvidia {
        source.push_str(include_str!("commitment_shuffle.cl"));
    }
    source.push_str(include_str!("scale_shared.cl"));
    source
        .push_str("\n#define LATTICA_TUNED_NTT 1\n#define ntt_tile_cached ntt_tile_cached_tuned\n");
    source.push_str(include_str!("../../../gpu/ntt_cached.cl"));
    source.push_str("\n#undef ntt_tile_cached\n#undef LATTICA_TUNED_NTT\n");
    source
}

#[cfg(not(feature = "gpu-tuning"))]
pub(super) fn kernel_source(_: bool) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidates_require_explicit_feature_and_selection() {
        assert_eq!(Tuning::parse("", false).unwrap(), Tuning::default());
        for value in ["events", "commitment", "scale", "ntt"] {
            assert!(Tuning::parse(value, false).is_err());
            assert_ne!(Tuning::parse(value, true).unwrap(), Tuning::default());
        }
        for value in [
            "all",
            "events,events",
            "events,",
            " events",
            "scale,unknown",
        ] {
            assert!(Tuning::parse(value, true).is_err());
        }
        let all = Tuning::parse("events,commitment,scale,ntt", true).unwrap();
        assert!(all.events && all.commitment && all.scale && all.ntt);
    }
    #[test]
    fn transform_candidates_are_shape_limited() {
        let all = Tuning::parse("scale,ntt", true).unwrap();
        for log in [18, 19, 22, 23] {
            for width in [1, 2, 3, 4, 8, 15, 16, 17, 94, 98, 200] {
                assert_eq!(
                    all.ntt_powers(1 << log, width),
                    log == 23 && matches!(width, 3 | 4 | 8 | 16)
                );
                assert_eq!(
                    all.shared_scale(1 << 18, 1 << log, width),
                    log == 19 && matches!(width, 98 | 200)
                );
                assert!(!Tuning::default().ntt_powers(1 << log, width));
                assert!(!Tuning::default().shared_scale(1 << 18, 1 << log, width));
            }
        }
    }
}
