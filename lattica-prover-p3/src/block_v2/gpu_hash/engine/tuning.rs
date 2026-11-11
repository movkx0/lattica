mod schedules;
#[cfg(all(feature = "gpu", feature = "gpu-tuning"))]
pub(crate) mod screen;
pub(super) use schedules::{Ntt, Poseidon};
// The measured NTT schedule is standard. Other candidates require gpu-tuning.
#[cfg(all(test, feature = "gpu-tuning"))]
mod gpu_tests;
#[cfg(all(test, feature = "gpu-tuning"))]
mod witness_tests;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Tuning {
    pub events: bool,
    pub commitment: bool,
    pub scale: bool,
    pub ntt: bool,
    pub witness: bool,
    pub programs: bool,
    pub queries: bool,
    pub ntt_schedule: Ntt,
    pub poseidon_schedule: Poseidon,
}

impl Tuning {
    pub(super) fn from_env() -> Result<Self, String> {
        let value = match std::env::var("LATTICA_V2_GPU_TUNING") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => String::new(),
            Err(_) => return Err("GPU tuning selection must be UTF-8".into()),
        };
        let mut selected = Self::parse(&value, cfg!(feature = "gpu-tuning"))?;
        selected.ntt_schedule = Ntt::parse(
            &std::env::var("LATTICA_V2_GPU_NTT_PROFILE").unwrap_or_else(|_| "smalltile".into()),
        )?;
        selected.poseidon_schedule = Poseidon::parse(
            &std::env::var("LATTICA_V2_GPU_POSEIDON_PROFILE").unwrap_or_else(|_| "baseline".into()),
        )?;
        if !cfg!(feature = "gpu-tuning")
            && (selected.ntt_schedule != Ntt::default()
                || selected.poseidon_schedule != Poseidon::Baseline)
        {
            return Err("kernel schedules require gpu-tuning".into());
        }
        Ok(selected)
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
                "witness" => &mut result.witness,
                "programs" => &mut result.programs,
                "queries" => &mut result.queries,
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

fn kernel_sources(nvidia: bool, mut emit: impl FnMut(&str)) {
    #[cfg(not(feature = "gpu-tuning"))]
    let _ = nvidia;
    #[cfg(feature = "gpu-tuning")]
    {
        #[cfg(feature = "gpu")]
        emit(screen::SOURCE);
        if nvidia {
            emit(include_str!("commitment_shuffle.cl"));
        }
        emit(include_str!("scale_shared.cl"));
        emit(include_str!("device/witness_fused.cl"));
    }
    // Required by ordinary OpenCL proving, including builds without gpu-tuning.
    emit("\n#define LATTICA_TUNED_NTT 1\n#define ntt_tile_cached ntt_tile_cached_tuned\n");
    emit(include_str!("../../../gpu/ntt_cached.cl"));
    emit("\n#undef ntt_tile_cached\n");
    #[cfg(feature = "gpu-tuning")]
    {
        emit("\n#define LATTICA_NTT_PADDED 1\n#define ntt_tile_cached ntt_tile_cached_padded\n");
        emit(include_str!("../../../gpu/ntt_cached.cl"));
        emit("\n#undef ntt_tile_cached\n#undef LATTICA_NTT_PADDED\n");
    }
    emit("\n#undef LATTICA_TUNED_NTT\n");
}
pub(super) fn kernel_source(nvidia: bool) -> String {
    let mut source = String::new();
    kernel_sources(nvidia, |part| source.push_str(part));
    source
}

/// The source census visits the exact same fragments without allocating.
pub(super) fn kernel_source_len(nvidia: bool) -> Option<usize> {
    let mut length = Some(0usize);
    kernel_sources(nvidia, |part| {
        length = length.and_then(|n| n.checked_add(part.len()))
    });
    length
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_ntt_does_not_require_research_selection() {
        let tuning = Tuning::parse("", false).unwrap();
        assert_eq!(tuning.ntt_schedule, Ntt::SmallTile);
        assert_eq!(tuning.poseidon_schedule, Poseidon::Baseline);
        assert!(kernel_source(false).contains("#define ntt_tile_cached ntt_tile_cached_tuned"));
    }

    #[test]
    fn candidates_require_explicit_feature_and_selection() {
        assert_eq!(Tuning::parse("", false).unwrap(), Tuning::default());
        for value in [
            "events",
            "commitment",
            "scale",
            "ntt",
            "witness",
            "programs",
            "queries",
        ] {
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
