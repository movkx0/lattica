//! Workgroup-local twiddle reuse with explicit local-memory admission.

/// Expanded cache for the measured Volta device. Other devices retain the
/// original budget. OpenCL reports static local usage before dynamic arguments
/// are bound, so subtract that usage from the device's complete allowance.
pub(crate) fn local_word_limit(
    device: ocl::Device,
    program: &ocl::Program,
) -> Result<usize, String> {
    use ocl::core::{DeviceInfo, DeviceInfoResult, KernelWorkGroupInfo, KernelWorkGroupInfoResult};
    if !matches!(
        device.info(DeviceInfo::VendorId),
        Ok(DeviceInfoResult::VendorId(0x10de))
    ) || !matches!(device.info(DeviceInfo::Name), Ok(DeviceInfoResult::Name(name)) if name.contains("V100"))
    {
        return Ok(4096);
    }
    let local_bytes = match device
        .info(DeviceInfo::LocalMemSize)
        .map_err(|e| e.to_string())?
    {
        DeviceInfoResult::LocalMemSize(bytes) => {
            usize::try_from(bytes).map_err(|_| "GPU local memory size overflow")?
        }
        _ => return Err("GPU local memory response".into()),
    };
    let mut static_bytes = 0usize;
    for name in ["ntt_tile_cached", "ntt_tile_cached_tuned"] {
        if name.ends_with("_tuned") && !cfg!(feature = "gpu-tuning") {
            continue;
        }
        let kernel =
            ocl::core::create_kernel(program.as_core(), name).map_err(|e| e.to_string())?;
        let bytes = match ocl::core::get_kernel_work_group_info(
            &kernel,
            device,
            KernelWorkGroupInfo::LocalMemSize,
        )
        .map_err(|e| e.to_string())?
        {
            KernelWorkGroupInfoResult::LocalMemSize(bytes) => {
                usize::try_from(bytes).map_err(|_| "GPU static local memory overflow")?
            }
            _ => return Err("GPU static local memory response".into()),
        };
        static_bytes = static_bytes.max(bytes);
    }
    let words = local_words(local_bytes, static_bytes);
    eprintln!("bounded_gpu_ntt_local_memory device_bytes={local_bytes} static_bytes={static_bytes} dynamic_words={words}");
    Ok(words)
}

fn local_words(device_bytes: usize, static_bytes: usize) -> usize {
    (device_bytes.saturating_sub(static_bytes) / 8).min(6144)
}

fn preferred_column_bits(log_height: usize, width: usize, nvidia: bool) -> usize {
    if nvidia && matches!(log_height, 22 | 23) && width == 16 {
        3
    } else {
        4
    }
}

/// The measured large sixteen-column tiles fit their twiddle cache when split
/// into eight-column workgroups. Irregular widths and smaller transforms keep
/// their original geometry; both regressed under an unrestricted split.
pub(crate) fn max_column_bits(device: ocl::Device, log_height: usize, width: usize) -> usize {
    use ocl::core::{DeviceInfo, DeviceInfoResult};
    if !matches!(log_height, 22 | 23) || width != 16 {
        return 4;
    }
    preferred_column_bits(
        log_height,
        width,
        matches!(
            device.info(DeviceInfo::VendorId),
            Ok(DeviceInfoResult::VendorId(0x10de))
        ),
    )
}

/// Return the auxiliary word count only when both the original tile and
/// cached powers fit. Oversized groups keep the original kernel and geometry.
pub(crate) fn power_words(stages: usize, log_columns: usize, scaled: bool) -> Option<usize> {
    power_words_with_limit(stages, log_columns, scaled, 4096)
}

pub(crate) fn power_words_with_limit(
    stages: usize,
    log_columns: usize,
    scaled: bool,
    limit: usize,
) -> Option<usize> {
    if !(1..=12).contains(&stages) || log_columns > 4 {
        return None;
    }
    let rows = 1usize << stages;
    let tile = rows << log_columns;
    let powers = rows / 2 + stages + if scaled { rows } else { 0 };
    (tile + powers <= limit.min(6144)).then_some(powers)
}

#[cfg(test)]
mod tests {
    use super::{local_words, power_words, power_words_with_limit, preferred_column_bits};

    #[test]
    fn expanded_cache_subtracts_static_usage_and_checks_complete_local_storage() {
        assert_eq!(local_words(48 << 10, 8), 6143);
        assert_eq!(local_words(32 << 10, 0), 4096);
        assert_eq!(local_words(4, 8), 0);
        assert_eq!(local_words(usize::MAX, 0), 6144);
        for scaled in [false, true] {
            let powers = if scaled { 392 } else { 136 };
            let exact = 4096 + powers;
            assert_eq!(power_words_with_limit(8, 4, scaled, exact), Some(powers));
            assert_eq!(power_words_with_limit(8, 4, scaled, exact - 1), None);
            assert_eq!(power_words_with_limit(8, 4, scaled, 6143), Some(powers));
        }
        assert_eq!(power_words_with_limit(12, 0, false, usize::MAX), None);
    }

    #[test]
    fn column_split_is_limited_to_the_measured_device_and_shapes() {
        for log_height in 1..32 {
            for width in [1, 2, 8, 9, 15, 16, 17, 32, 94] {
                assert_eq!(preferred_column_bits(log_height, width, false), 4);
                let split = preferred_column_bits(log_height, width, true);
                assert_eq!(split == 3, matches!(log_height, 22 | 23) && width == 16);
                if split == 3 {
                    // Both complete schedules fit the cache, including scaling
                    // on the final group, within the original local allowance.
                    for (stages, last) in [(8, false), (8, false), (7, true)] {
                        assert!(power_words(stages, split, last).is_some());
                    }
                }
            }
        }
    }

    #[test]
    fn cached_groups_fit_and_full_tiles_keep_the_original_kernel() {
        // Production 2^18-row wide transforms use six-stage groups.
        assert_eq!(power_words(6, 4, false), Some(38));
        assert_eq!(power_words(6, 4, true), Some(102));
        // A 2^22-row transform starts with a full 32 KiB tile, then uses
        // seven-stage groups where both twiddles and row scaling fit.
        assert_eq!(power_words(8, 4, false), None);
        assert_eq!(power_words(8, 4, true), None);
        assert_eq!(power_words(7, 4, false), Some(71));
        assert_eq!(power_words(7, 4, true), Some(199));
        // Narrow shapes can admit twiddles while declining extra scale rows.
        assert_eq!(power_words(11, 0, false), Some(1035));
        assert_eq!(power_words(11, 0, true), None);
    }

    #[test]
    fn invalid_shifts_never_enter_cache_geometry() {
        assert_eq!(power_words(0, 0, false), None);
        assert_eq!(power_words(13, 0, false), None);
        assert_eq!(power_words(usize::MAX, 0, true), None);
        assert_eq!(power_words(1, usize::MAX, true), None);
    }
}
