//! Workgroup-local twiddle reuse within the original 32 KiB NTT budget.

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
    if !(1..=12).contains(&stages) || log_columns > 4 {
        return None;
    }
    let rows = 1usize << stages;
    let tile = rows << log_columns;
    let powers = rows / 2 + stages + if scaled { rows } else { 0 };
    (tile + powers <= 4096).then_some(powers)
}

#[cfg(test)]
mod tests {
    use super::{power_words, preferred_column_bits};

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
