//! OpenCL execution choices. Measured V100 defaults and explicit research
//! selections change scheduling and public caches, never the proof profile.
#[cfg(all(test, feature = "gpu-tuning"))]
mod gpu_tests;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Tuning {
    explicit: bool,
    pub events: bool,
    pub events256: bool,
    pub paths: bool,
    pub public_cache: bool,
    pub tables: bool,
    pub quotient256: bool,
    pub hash32: bool,
    pub hash_unroll: bool,
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
        if value.len() > 128 {
            return Err("GPU tuning selection is too long".into());
        }
        result.explicit = true;
        if value == "reference" {
            return Ok(result);
        }
        for item in value.split(',') {
            let selected = match item {
                "events" => &mut result.events,
                "events256" => &mut result.events256,
                "paths" => &mut result.paths,
                "public_cache" => &mut result.public_cache,
                "tables" => &mut result.tables,
                "quotient256" => &mut result.quotient256,
                "hash32" => &mut result.hash32,
                "hash_unroll" => &mut result.hash_unroll,
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
        if result.events256 {
            result.events = true;
        }
        Ok(result)
    }

    pub(super) fn apply_defaults(
        &mut self,
        device: ocl::Device,
        limits: super::Limits,
        assigned_max_alloc: Option<usize>,
    ) -> Result<(), String> {
        use ocl::core::{DeviceInfo, DeviceInfoResult};
        let nvidia = matches!(
            device.info(DeviceInfo::VendorId),
            Ok(DeviceInfoResult::VendorId(0x10de))
        );
        self.select_defaults(
            nvidia,
            &device.name().map_err(|e| e.to_string())?,
            limits.managed_bytes,
            assigned_max_alloc.is_some(),
        );
        Ok(())
    }

    fn select_defaults(&mut self, nvidia: bool, name: &str, managed: usize, assigned: bool) {
        if self.explicit || !nvidia || !name.contains("V100-PCIE-32GB") {
            return;
        }
        self.events = true;
        self.paths = true;
        self.public_cache = true;
        // Assigned workers retain the workspace in their existing admission
        // profile. The larger standalone benchmark budgets fund 256 MiB here;
        // explicit research selections must reserve it in their own profile.
        self.quotient256 = !assigned && managed >= (11usize << 30);
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
    source.push_str("\n#define LATTICA_NTT_TABLES 1\n#define ntt_tile_cached ntt_tile_tables\n");
    source.push_str(include_str!("../../../gpu/ntt_cached.cl"));
    source.push_str("\n#undef ntt_tile_cached\n#undef LATTICA_NTT_TABLES\n");
    source.push_str(include_str!("ntt_tables.cl"));
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
        for value in [
            "events",
            "events256",
            "paths",
            "public_cache",
            "tables",
            "quotient256",
            "hash32",
            "hash_unroll",
            "commitment",
            "scale",
            "ntt",
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
    fn v100_defaults_preserve_assigned_and_small_workspace_allowances() {
        let select = |name, managed, assigned| {
            let mut t = Tuning::default();
            t.select_defaults(true, name, managed, assigned);
            t
        };
        let name = "Tesla V100-PCIE-32GB";
        let t = select(name, 16 << 30, false);
        assert!(t.events && t.paths && t.public_cache && t.quotient256);
        assert!(!t.events256 && !t.tables && !t.hash32 && !t.hash_unroll);
        assert!(!select(name, 8 << 30, false).quotient256);
        assert!(!select(name, 16 << 30, true).quotient256);
        assert_eq!(
            select("NVIDIA GeForce RTX 5080", 16 << 30, false),
            Tuning::default()
        );
        let mut reference = Tuning::parse("reference", true).unwrap();
        reference.select_defaults(true, name, 16 << 30, false);
        assert!(!reference.events && !reference.public_cache && !reference.quotient256);
        assert!(Tuning::parse("reference", false).is_err());
        let mut custom = Tuning::parse("events", true).unwrap();
        custom.select_defaults(true, name, 16 << 30, false);
        assert!(custom.events && !custom.paths && !custom.public_cache && !custom.quotient256);
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
