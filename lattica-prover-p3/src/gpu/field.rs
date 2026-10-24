//! Explicit carry instructions for the measured V100 OpenCL compiler.

fn measured_device(vendor: u32, name: &str, capability: Option<(u32, u32)>) -> bool {
    vendor == 0x10de && name.contains("V100") && capability == Some((7, 0))
}

/// Unknown devices retain portable OpenCL arithmetic. The instruction sequence
/// needs no warp assumptions, barriers, extra buffers, or changed field bounds.
pub(crate) fn source_prefix(device: ocl::Device) -> &'static str {
    use ocl::core::{DeviceInfo, DeviceInfoResult};
    let vendor = match device.info(DeviceInfo::VendorId) {
        Ok(DeviceInfoResult::VendorId(vendor)) => vendor,
        _ => return "",
    };
    if vendor != 0x10de {
        return "";
    }
    let Ok(name) = device.name() else { return "" };
    let word = |parameter| {
        ocl::core::get_device_info_raw(device, parameter)
            .ok()
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
            .map(u32::from_ne_bytes)
    };
    // CL_DEVICE_COMPUTE_CAPABILITY_{MAJOR,MINOR}_NV.
    if measured_device(vendor, &name, word(0x4000).zip(word(0x4001))) {
        "#define LATTICA_NVIDIA_FIELD_CARRY 1\n"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::measured_device;

    #[test]
    fn carry_instructions_require_the_measured_vendor_device_and_capability() {
        assert!(measured_device(
            0x10de,
            "Tesla V100-PCIE-32GB",
            Some((7, 0))
        ));
        assert!(measured_device(
            0x10de,
            "Tesla V100-SXM2-16GB",
            Some((7, 0))
        ));
        for capability in [None, Some((6, 0)), Some((7, 2)), Some((8, 0))] {
            assert!(!measured_device(0x10de, "Tesla V100-PCIE-32GB", capability));
        }
        assert!(!measured_device(0x1002, "V100", Some((7, 0))));
        assert!(!measured_device(0x10de, "unrecognized", Some((7, 0))));
    }
}
